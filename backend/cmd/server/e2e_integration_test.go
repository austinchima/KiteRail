package main

// E2E invariant harness (STABILIZATION-PLAN.md, Phase 1).
//
// This file wires the REAL stack — real Postgres, real embedded OPA, the real
// buildHTTPHandler trust-domain assembly, and an httptest upstream — and
// asserts the invariants that unit tests with lying mocks cannot cover:
//
//	Inv 1  allow-parity:        agent credential stripped upstream, service token injected
//	Inv 2  quarantine→approve→replay: same replay-credential parity, entry reaches replayed
//	Inv 3  ledger chain:        hash chain verifies end-to-end through the HTTP surface
//	Inv 4  trust separation:    agent tokens rejected on human routes and vice versa
//	Inv 5  ledger-outage:       proxy fails CLOSED (503) when the audit ledger errors
//	Inv 6  exhaustion surfaces: replay failure drives status to replay_failed over HTTP
//	Inv 7  ledger honesty:      allow-path rows carry the real sha256 + real request id
//	Inv 8  MCP metadata parity: header/body contradiction → 400/-32020 before OPA;
//	                           matching mirrored headers ride through to the upstream
//
// The whole file skips unless KITERAIL_POSTGRES_DSN (or QUARANTINE_TEST_DSN)
// points at a migrated database — same gate as every other integration test.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/dashboard"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/dbtest"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/policystore"
	"github.com/austinchima/kiterail/internal/proxy"
	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	e2eAgentToken    = "e2e-agent-token"
	e2eReviewerToken = "e2e-reviewer-token"
	e2eTargetSecret  = "e2e-upstream-service-token"
)

// e2ePolicyMain mirrors policies/main.rego: a decisions-set aggregator where
// the most restrictive action wins deterministically.
const e2ePolicyMain = `package kiterail.authz

import rego.v1

severity := {"deny": 3, "quarantine": 2, "allow": 1}

default decision := {"action": "deny", "rule": "default_deny", "explanation": "No matching allow rule found"}

decision := result if {
    count(decisions) > 0
    max_sev := max({severity[d.action] | some d in decisions})
    winners := sort([json.marshal(d) | some d in decisions; severity[d.action] == max_sev])
    result := json.unmarshal(winners[0])
}
`

// e2ePolicyRules gives the harness three tools, one per decision action.
const e2ePolicyRules = `package kiterail.authz

import rego.v1

decisions contains {"action": "allow", "rule": "allow_safe_tool", "explanation": "safe tool allowed"} if {
    input.tool == "safe_tool"
}

decisions contains {"action": "quarantine", "rule": "quarantine_sensitive_tool", "explanation": "sensitive tool needs human approval"} if {
    input.tool == "sensitive_tool"
}

decisions contains {"action": "deny", "rule": "deny_dangerous_tool", "explanation": "dangerous tool denied"} if {
    input.tool == "dangerous_tool"
}
`

type e2eEnv struct {
	t            *testing.T
	server       *httptest.Server // KiteRail itself
	upstream     *httptest.Server // fake MCP upstream
	upstreamMu   sync.Mutex
	upstreamReqs []*http.Request // cloned requests (headers safe to read later)
	upstreamFail atomic.Bool     // when true, upstream answers 500
	upstreamN    atomic.Int32
	ready        *atomic.Bool // readiness flag wired into /readyz

	worker *quarantine.Worker
}

// upstreamHeader returns header `name` of upstream call i.
func (e *e2eEnv) upstreamHeader(i int, name string) string {
	e.upstreamMu.Lock()
	defer e.upstreamMu.Unlock()
	if i >= len(e.upstreamReqs) {
		return "<missing>"
	}
	return e.upstreamReqs[i].Header.Get(name)
}

// upstreamAuth returns the Authorization header of upstream call i.
func (e *e2eEnv) upstreamAuth(i int) string {
	e.upstreamMu.Lock()
	defer e.upstreamMu.Unlock()
	if i >= len(e.upstreamReqs) {
		return "<missing>"
	}
	return e.upstreamReqs[i].Header.Get("Authorization")
}

func (e *e2eEnv) upstreamCount() int { return int(e.upstreamN.Load()) }

func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	ctx := context.Background()
	logger := zap.NewNop()

	sqlDB := dbtest.Open(t)
	dbtest.Reset(t, sqlDB, "ledger", "quarantine")

	policyDir := e2eTempDir(t, "e2e-policies-")
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "main.rego"), []byte(e2ePolicyMain), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "rules.rego"), []byte(e2ePolicyRules), 0o600))

	engine, err := opaengine.New(ctx, policyDir, logger)
	require.NoError(t, err)

	qStore, err := quarantine.New(sqlDB)
	require.NoError(t, err)
	lStore, err := ledger.New(sqlDB)
	require.NoError(t, err)
	pStore, err := policystore.New(policyDir)
	require.NoError(t, err)

	env := &e2eEnv{t: t}

	// Fake MCP upstream: records every request (clone, so headers survive
	// after the handler returns) and optionally fails to drive replay paths.
	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.upstreamN.Add(1)
		env.upstreamMu.Lock()
		env.upstreamReqs = append(env.upstreamReqs, r.Clone(r.Context()))
		env.upstreamMu.Unlock()
		if env.upstreamFail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"upstream","result":{"ok":true}}`)
	}))
	t.Cleanup(env.upstream.Close)

	proxyHandler, err := proxy.NewHandler(logger, env.upstream.URL, engine,
		proxy.NoOpPublisher{}, qStore, lStore,
		proxy.WithTargetAuthToken(e2eTargetSecret),
	)
	require.NoError(t, err)

	env.worker = quarantine.NewWorker(qStore, lStore, logger, env.upstream.URL,
		quarantine.WithTargetAuthToken(e2eTargetSecret))

	identities := map[string]auth.Identity{
		e2eAgentToken:    {ID: "agent-alpha", Role: auth.RoleAgent},
		e2eReviewerToken: {ID: "reviewer-jane", Role: auth.RoleReviewer},
	}

	env.ready = &atomic.Bool{}
	env.ready.Store(true)

	handler := buildHTTPHandler(httpDeps{
		version:        "e2e",
		startTime:      time.Now(),
		dbConn:         sqlDB,
		proxy:          proxyHandler,
		quarantine:     quarantine.NewHandler(qStore, lStore, logger),
		ledger:         ledger.NewHandler(lStore, logger),
		policy:         policystore.NewHandler(pStore, engine, logger),
		dashboard:      dashboard.NewHandler(lStore, qStore, logger),
		identities:     identities,
		rateLimitRPS:   1000, // effectively unlimited; this harness tests invariants, not throttling
		rateLimitBurst: 1000,
		allowedOrigins: []string{"*"},
		ready:          env.ready,
	}, logger)

	env.server = httptest.NewServer(handler)
	t.Cleanup(env.server.Close)
	return env
}

// post sends an authenticated POST and returns (status, response body).
func (e *e2eEnv) post(t *testing.T, path, token, body string) (int, string) {
	t.Helper()
	return e.postHeaders(t, path, token, body, nil)
}

// postHeaders is post with extra request headers (MCP mirrored-metadata tests).
func (e *e2eEnv) postHeaders(t *testing.T, path, token, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

// get sends an authenticated GET and returns (status, response body).
func (e *e2eEnv) get(t *testing.T, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.server.URL+path, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

// ledgerEntries fetches the full ledger through the human HTTP surface.
func (e *e2eEnv) ledgerEntries(t *testing.T) []db.LedgerEntry {
	t.Helper()
	status, body := e.get(t, "/api/v1/ledger", e2eReviewerToken)
	require.Equal(t, http.StatusOK, status, "ledger query failed: %s", body)
	var entries []db.LedgerEntry
	require.NoError(t, json.Unmarshal([]byte(body), &entries))
	return entries
}

// ledgerValid hits /api/v1/ledger/verify and returns the chain verdict.
func (e *e2eEnv) ledgerValid(t *testing.T) bool {
	t.Helper()
	status, body := e.get(t, "/api/v1/ledger/verify", e2eReviewerToken)
	require.Equal(t, http.StatusOK, status, "ledger verify failed: %s", body)
	var resp struct {
		Valid bool `json:"valid"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	return resp.Valid
}

func toolsCallBody(id, tool string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":{"name":%q,"arguments":{"x":1}}}`, id, tool)
}

// quarantineStatus fetches one entry's status through the reviewer surface.
func (e *e2eEnv) quarantineStatus(t *testing.T, id string) string {
	t.Helper()
	status, body := e.get(t, "/api/v1/quarantine/"+id, e2eReviewerToken)
	require.Equal(t, http.StatusOK, status, "quarantine get failed: %s", body)
	var entry struct {
		Status string `json:"Status"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &entry))
	return entry.Status
}

// Invariant 1 + 7: the allow path must reach the upstream with the SERVICE
// credential (never the agent's), and the ledger row written before execution
// must be honest: real sha256 of the exact request body, real JSON-RPC id.
func TestE2E_AllowPath_ParityAndLedgerHonesty(t *testing.T) {
	env := newE2EEnv(t)

	body := toolsCallBody("1", "safe_tool")
	status, respBody := env.post(t, "/", e2eAgentToken, body)
	require.Equal(t, http.StatusOK, status, "allow path rejected: %s", respBody)
	require.Contains(t, respBody, `"ok":true`, "upstream response should be proxied verbatim")

	// Parity: exactly one upstream call, carrying the service token and NOT
	// the agent's token. This is the credential-isolation invariant.
	require.Equal(t, 1, env.upstreamCount(), "upstream must be hit exactly once")
	require.Equal(t, "Bearer "+e2eTargetSecret, env.upstreamAuth(0),
		"upstream must see the injected service credential")
	require.NotContains(t, env.upstreamAuth(0), e2eAgentToken,
		"agent credential must never reach the upstream")

	// Ledger honesty on the allow-path row.
	entries := env.ledgerEntries(t)
	require.Len(t, entries, 1, "exactly one ledger row for one proxied call")
	row := entries[0]
	require.Equal(t, "allow", row.Decision)
	require.Equal(t, "allow_safe_tool", row.PolicyRule)
	require.Equal(t, "agent-alpha", row.Agent)
	require.Equal(t, "safe_tool", row.Tool)
	require.Equal(t, "1", row.RequestID, "ledger must persist the real JSON-RPC request id")
	sum := sha256.Sum256([]byte(body))
	require.Equal(t, fmt.Sprintf("%x", sum), row.PayloadHash,
		"ledger must carry the real sha256 of the exact request body")

	// Chain integrity across the whole surface.
	require.True(t, env.ledgerValid(t), "ledger chain must verify")
}

// Invariant 2: a quarantined call must NOT touch the upstream until a human
// approves it, and the worker's replay must carry the same service credential
// parity as the synchronous allow path.
func TestE2E_QuarantineApproveReplay_Parity(t *testing.T) {
	env := newE2EEnv(t)

	// Quarantine: 202, upstream untouched, ledger row exists.
	status, respBody := env.post(t, "/", e2eAgentToken, toolsCallBody("2", "sensitive_tool"))
	require.Equal(t, http.StatusAccepted, status, "quarantine path failed: %s", respBody)
	require.Equal(t, 0, env.upstreamCount(), "quarantined call must never reach the upstream")

	var created struct {
		QuarantineID string `json:"quarantine_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(respBody), &created))
	require.NotEmpty(t, created.QuarantineID)
	require.Equal(t, "pending", env.quarantineStatus(t, created.QuarantineID))

	// Human approval via the reviewer surface (identity from the token, never the body).
	status, respBody = env.post(t, "/api/v1/quarantine/"+created.QuarantineID+"/approve", e2eReviewerToken, "{}")
	require.Equal(t, http.StatusOK, status, "approve failed: %s", respBody)
	require.Equal(t, "approved", env.quarantineStatus(t, created.QuarantineID))
	require.Equal(t, 0, env.upstreamCount(), "approval alone must not replay")

	// Worker replays synchronously.
	env.worker.ProcessOnce(context.Background())
	require.Equal(t, "replayed", env.quarantineStatus(t, created.QuarantineID))
	require.Equal(t, 1, env.upstreamCount(), "exactly one replay attempt")
	require.Equal(t, "Bearer "+e2eTargetSecret, env.upstreamAuth(0),
		"replay must carry the service credential, not the agent's or reviewer's")

	// The replay outcome is ledgered and the chain still verifies.
	entries := env.ledgerEntries(t)
	var replayRow *db.LedgerEntry
	for i := range entries {
		if entries[i].Decision == "approved_replayed" {
			replayRow = &entries[i]
		}
	}
	require.NotNil(t, replayRow, "replay must produce an approved_replayed ledger row")
	require.Equal(t, "reviewer-jane", replayRow.Agent, "replay row is attributed to the approving human")

	// KNOWN ABUSE, pinned until Phase 6: the worker currently writes the
	// quarantine UUID into BOTH payload_hash and request_id (ledger semantic
	// abuse documented in STABILIZATION-PLAN.md). Assert the CURRENT values
	// so the divergence cannot silently change shape, and so Phase 6 has a
	// failing pin to flip when real hashing lands.
	require.Equal(t, created.QuarantineID, replayRow.PayloadHash, "PIN(phase-6): worker writes quarantine UUID as payload_hash")
	require.Equal(t, created.QuarantineID, replayRow.RequestID, "PIN(phase-6): worker writes quarantine UUID as request_id")

	require.True(t, env.ledgerValid(t), "ledger chain must verify after replay")
}

// Invariant 4: the three trust domains reject cross-domain tokens.
func TestE2E_TrustSeparation(t *testing.T) {
	env := newE2EEnv(t)

	// Agent token on a human route: authenticated, wrong role.
	status, _ := env.get(t, "/api/v1/quarantine", e2eAgentToken)
	require.Equal(t, http.StatusForbidden, status, "agent token must not read the quarantine surface")

	// Reviewer token on the agent proxy: authenticated, wrong role.
	status, _ = env.post(t, "/", e2eReviewerToken, toolsCallBody("9", "safe_tool"))
	require.Equal(t, http.StatusForbidden, status, "reviewer token must not drive the agent proxy")

	// No token at all on a guarded route.
	status, _ = env.get(t, "/api/v1/ledger", "")
	require.Equal(t, http.StatusUnauthorized, status, "unguarded-token request must be rejected")
}

// e2eTempDir returns an absolute temporary directory for policy fixtures.
// On Windows that is "C:\..." — precisely the shape that used to break
// rego.Load (drive letter parsed as a URL scheme) before the engine-level
// fix; keeping the fixtures absolute pins that regression shut.
func e2eTempDir(t *testing.T, pattern string) string {
	t.Helper()
	return t.TempDir()
}

// failingLedgerStore injects an audit-ledger outage. Unlike the mockStore
// divergence this file exists to prevent, injecting an ERROR is the point of
// the invariant: the proxy's contract on ledger failure is fail-closed.
type failingLedgerStore struct{ err error }

func (f failingLedgerStore) Append(context.Context, db.LedgerEntry) error { return f.err }

// Invariant 5: when the audit ledger cannot accept the entry, the proxy must
// refuse to execute the call — no silent execution without an audit trail.
func TestE2E_LedgerOutage_FailsClosed(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Empty policy dir: every evaluation falls to default_deny. The decision
	// is irrelevant, though — the ledger append precedes execution and must
	// fail first.
	policyDir := e2eTempDir(t, "e2e-empty-policies-")
	engine, err := opaengine.New(ctx, policyDir, logger)
	require.NoError(t, err)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must NOT be reached when the ledger is unavailable")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	handler, err := proxy.NewHandler(logger, upstream.URL, engine,
		proxy.NoOpPublisher{},
		// QuarantineStore is never reached: the ledger append precedes the
		// decision switch, so a nil-shaped store is safe here.
		noopQuarantineStore{},
		failingLedgerStore{err: errors.New("ledger unavailable: injected outage")},
	)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(toolsCallBody("5", "safe_tool")))
	require.NoError(t, err)
	req = req.WithContext(auth.WithIdentity(req.Context(), auth.Identity{ID: "agent-alpha", Role: auth.RoleAgent}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"proxy must fail closed (503) when the audit ledger errors, got %d: %s", rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "audit unavailable")
}

type noopQuarantineStore struct{}

func (noopQuarantineStore) Create(context.Context, string, string, []byte, http.Header) (string, error) {
	return "", errors.New("unreachable: quarantine store is not exercised before ledger append")
}

// Invariant 6: replay failure is surfaced. With the upstream failing, the
// worker must drive attempts → replay_failed, visible through the HTTP
// surface, exactly as the direct-store integration test proves.
func TestE2E_ReplayExhaustion_SurfacesReplayFailed(t *testing.T) {
	env := newE2EEnv(t)
	env.upstreamFail.Store(true)

	status, respBody := env.post(t, "/", e2eAgentToken, toolsCallBody("3", "sensitive_tool"))
	require.Equal(t, http.StatusAccepted, status, "quarantine path failed: %s", respBody)
	var created struct {
		QuarantineID string `json:"quarantine_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(respBody), &created))

	status, respBody = env.post(t, "/api/v1/quarantine/"+created.QuarantineID+"/approve", e2eReviewerToken, "{}")
	require.Equal(t, http.StatusOK, status, "approve failed: %s", respBody)

	// defaultMaxReplayAttempts(3) + 1: attempts increment on release/success,
	// not at claim time (Phase 0 fix), so exhausting takes 4 upstream calls.
	const rounds = 4
	for range rounds {
		env.worker.ProcessOnce(context.Background())
	}
	require.Equal(t, rounds, env.upstreamCount(), "exhaustion must consume exactly maxAttempts+1 upstream calls")
	require.Equal(t, "replay_failed", env.quarantineStatus(t, created.QuarantineID),
		"entry must be parked as replay_failed after exhaustion")
	require.True(t, env.ledgerValid(t), "ledger chain must verify after exhaustion")
}

// Invariant 8a: a request whose mirrored MCP metadata contradicts the body is
// rejected with HTTP 400 + JSON-RPC -32020 BEFORE policy evaluation — the
// upstream is never touched and no ledger row is written. This is the spec's
// named attack class: an intermediary that authorizes a header while the
// server executes a different body.
func TestE2E_HeaderBodyContradiction_FailsClosed(t *testing.T) {
	env := newE2EEnv(t)

	body := toolsCallBody("8", "safe_tool")
	status, respBody := env.postHeaders(t, "/", e2eAgentToken, body, map[string]string{
		"Mcp-Method": "tools/list", // body says tools/call
	})
	require.Equal(t, http.StatusBadRequest, status, "contradictory metadata must be rejected: %s", respBody)

	var rpcErr struct {
		Error struct {
			Code    float64 `json:"code"`
			Message string  `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(respBody), &rpcErr))
	require.Equal(t, float64(-32020), rpcErr.Error.Code, "contradiction must map to -32020, body: %s", respBody)
	require.Contains(t, rpcErr.Error.Message, "contradicts")

	require.Equal(t, 0, env.upstreamCount(), "contradictory request must never reach the upstream")
	require.Empty(t, env.ledgerEntries(t), "pre-OPA rejection must not write a ledger row")

	// The Mcp-Name mirror is validated too.
	status, respBody = env.postHeaders(t, "/", e2eAgentToken, body, map[string]string{
		"Mcp-Name": "dangerous_tool", // body names safe_tool
	})
	require.Equal(t, http.StatusBadRequest, status, "contradictory Mcp-Name must be rejected: %s", respBody)
	require.NoError(t, json.Unmarshal([]byte(respBody), &rpcErr))
	require.Equal(t, float64(-32020), rpcErr.Error.Code)
	require.Equal(t, 0, env.upstreamCount())
}

// Invariant 8b: matching mirrored headers are accepted, and the intermediary
// mirrors — never rewrites — Mcp-Method / Mcp-Name / MCP-Protocol-Version to
// the upstream verbatim.
func TestE2E_MirroredHeaders_RideThroughToUpstream(t *testing.T) {
	env := newE2EEnv(t)

	body := toolsCallBody("8", "safe_tool")
	status, respBody := env.postHeaders(t, "/", e2eAgentToken, body, map[string]string{
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "safe_tool",
		"MCP-Protocol-Version": "2026-07-28",
	})
	require.Equal(t, http.StatusOK, status, "matching mirrored headers must pass: %s", respBody)
	require.Equal(t, 1, env.upstreamCount())
	require.Equal(t, "tools/call", env.upstreamHeader(0, "Mcp-Method"))
	require.Equal(t, "safe_tool", env.upstreamHeader(0, "Mcp-Name"))
	require.Equal(t, "2026-07-28", env.upstreamHeader(0, "MCP-Protocol-Version"),
		"protocol version is accepted-and-forwarded, not enforced (see docs/ARCHITECTURE.md)")
}

// Invariant 3 (dedicated): a deny decision is ledgered and the chain verifies
// across mixed decisions (allow/quarantine/deny/replay) in one database.
func TestE2E_DenyPath_LedgeredAndChainVerifies(t *testing.T) {
	env := newE2EEnv(t)

	status, respBody := env.post(t, "/", e2eAgentToken, toolsCallBody("4", "dangerous_tool"))
	require.Equal(t, http.StatusForbidden, status, "deny path failed: %s", respBody)
	require.Equal(t, 0, env.upstreamCount(), "denied call must never reach the upstream")

	entries := env.ledgerEntries(t)
	require.Len(t, entries, 1)
	require.Equal(t, "deny", entries[0].Decision)
	require.Equal(t, "deny_dangerous_tool", entries[0].PolicyRule)
	require.True(t, env.ledgerValid(t))
}
