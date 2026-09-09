package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/proxy"
	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/austinchima/kiterail/internal/types"
)

const (
	testAgentATok = "sk_agent_alpha_tok"
	testAgentBTok = "sk_agent_beta_tok"
	testRvwTok    = "sk_reviewer_jane_tok"
	testAdminTok  = "sk_admin_root_tok"

	testAgentAID = "agent-alpha"
	testAgentBID = "agent-beta"
)

var testIdentities = map[string]auth.Identity{
	testAgentATok: {ID: testAgentAID, Role: auth.RoleAgent},
	testAgentBTok: {ID: testAgentBID, Role: auth.RoleAgent},
	testRvwTok:    {ID: "jane", Role: auth.RoleReviewer},
	testAdminTok:  {ID: "root", Role: auth.RoleAdmin},
}

// --- fakes ---

type allowEngine struct{}

func (allowEngine) Evaluate(ctx context.Context, in proxy.EvalInput) (proxy.ProxyDecision, error) {
	return proxy.ProxyDecision{Action: types.ActionAllow, Rule: "test_allow_all"}, nil
}

type noopPublisher struct{}

func (noopPublisher) PublishTelemetry(ctx context.Context, e interface{}) error  { return nil }
func (noopPublisher) PublishAudit(ctx context.Context, e interface{}) error      { return nil }
func (noopPublisher) PublishQuarantine(ctx context.Context, e interface{}) error { return nil }

type memLedger struct {
	mu      sync.Mutex
	appends int
}

func (m *memLedger) Append(ctx context.Context, entry db.LedgerEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appends++
	return nil
}

func (m *memLedger) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appends
}

type fakeQStore struct{}

func (fakeQStore) Create(ctx context.Context, agentID, toolName string, payload []byte, headers http.Header) (string, error) {
	return "q-1", nil
}
func (fakeQStore) Get(ctx context.Context, id string) (db.QuarantineEntry, error) {
	return db.QuarantineEntry{}, fmt.Errorf("not found")
}
func (fakeQStore) List(ctx context.Context, status string) ([]db.QuarantineEntry, error) {
	return []db.QuarantineEntry{}, nil
}
func (fakeQStore) Approve(ctx context.Context, id, approvedBy string) error    { return nil }
func (fakeQStore) Deny(ctx context.Context, id, deniedBy, reason string) error { return nil }
func (fakeQStore) ClaimApproved(ctx context.Context, limit int) ([]db.QuarantineEntry, error) {
	return nil, nil
}
func (fakeQStore) MarkReplayed(ctx context.Context, id string) error      { return nil }
func (fakeQStore) MarkReplayFailed(ctx context.Context, id string) error  { return nil }
func (fakeQStore) ReturnToApproved(ctx context.Context, id string) error  { return nil }
func (fakeQStore) RecoverStuckReplays(ctx context.Context) (int64, error) { return 0, nil }
func (fakeQStore) WithReplayLock(ctx context.Context, replay func(context.Context) error) (bool, error) {
	return true, replay(ctx)
}

type stubHandler struct{ hits atomic.Int64 }

func (s *stubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"stub": r.URL.Path})
}

// --- harness ---

type fixture struct {
	handler     http.Handler
	upstream    *httptest.Server
	hits        atomic.Int64
	ledger      *memLedger
	db          sqlmock.Sqlmock
	stubs       map[string]*stubHandler // keyed by mount prefix
	ready       *atomic.Bool            // readiness flag wired into /readyz
	policyReady *atomic.Bool            // active OPA decision entry point
}

func newFixture(t *testing.T, rps float64, burst int) *fixture {
	t.Helper()

	f := &fixture{
		ledger: &memLedger{},
		stubs: map[string]*stubHandler{
			"ledger":    {},
			"policies":  {},
			"dashboard": {},
		},
	}

	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"upstream":"hit"}`))
	}))
	t.Cleanup(f.upstream.Close)

	proxyHandler, err := proxy.NewHandler(zap.NewNop(), f.upstream.URL,
		allowEngine{}, noopPublisher{}, fakeQStore{}, f.ledger)
	require.NoError(t, err)

	dbConn, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbConn.Close() })
	f.db = mock

	f.ready = &atomic.Bool{}
	f.ready.Store(true)
	f.policyReady = &atomic.Bool{}
	f.policyReady.Store(true)

	handler := buildHTTPHandler(httpDeps{
		version:        "test",
		startTime:      time.Now(),
		dbConn:         dbConn,
		proxy:          proxyHandler,
		quarantine:     quarantine.NewHandler(fakeQStore{}, nil, zap.NewNop()),
		ledger:         f.stubs["ledger"],
		policy:         f.stubs["policies"],
		dashboard:      f.stubs["dashboard"],
		identities:     testIdentities,
		rateLimitRPS:   rps,
		rateLimitBurst: burst,
		allowedOrigins: []string{"*"},
		ready:          f.ready,
		policyReady:    f.policyReady.Load,
	}, zap.NewNop())
	f.handler = handler

	return f
}

func TestCORSRejectsUnknownOrigin(t *testing.T) {
	called := false
	handler := corsMiddleware([]string{"https://console.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://console.example.com.evil")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.False(t, called)

	request = httptest.NewRequest(http.MethodOptions, "/", nil)
	request.Header.Set("Origin", "https://console.example.com")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "https://console.example.com", recorder.Header().Get("Access-Control-Allow-Origin"))
}

func doReq(t *testing.T, h http.Handler, method, path, token string, body []byte, extraHeaders map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func rpcBody(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "test.tool",
			"arguments": map[string]interface{}{},
		},
	})
	require.NoError(t, err)
	return b
}

// --- public endpoints ---

func TestPublicEndpoints_NoAuthRequired(t *testing.T) {
	f := newFixture(t, 10, 20)

	rr := doReq(t, f.handler, http.MethodGet, "/api/v1/health", "", nil, nil)
	assert.Equal(t, http.StatusOK, rr.Code, "health must stay public per docs/API.md")
	assert.Contains(t, rr.Body.String(), `"status":"ok"`)

	// Postgres answers → ready.
	f.db.ExpectPing()
	rr = doReq(t, f.handler, http.MethodGet, "/readyz", "", nil, nil)
	assert.Equal(t, http.StatusOK, rr.Code, "readyz must stay public")
	assert.Contains(t, rr.Body.String(), `"ready":true`)

	// A compiled process with no authorization entry point fails closed at
	// ingress AND must not advertise itself as ready to receive traffic.
	f.policyReady.Store(false)
	rr = doReq(t, f.handler, http.MethodGet, "/readyz", "", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), `"policy":false`)
	f.policyReady.Store(true)

	// Postgres unreachable → readiness failure, still public (no 401).
	f.db.ExpectPing().WillReturnError(context.DeadlineExceeded)
	rr = doReq(t, f.handler, http.MethodGet, "/readyz", "", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")

	// Draining (SIGTERM received, readiness flipped BEFORE the listener
	// stops): 503 without even consulting Postgres — new traffic must be
	// refused while in-flight requests drain.
	f.ready.Store(false)
	rr = doReq(t, f.handler, http.MethodGet, "/readyz", "", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), `"draining":true`)

	// Liveness is unaffected by draining: /health must keep answering 200 so
	// the orchestrator does not kill the pod mid-drain.
	rr = doReq(t, f.handler, http.MethodGet, "/api/v1/health", "", nil, nil)
	assert.Equal(t, http.StatusOK, rr.Code, "liveness must not flip during drain")

	rr = doReq(t, f.handler, http.MethodGet, "/metrics", "", nil, nil)
	assert.Equal(t, http.StatusOK, rr.Code, "metrics must stay public")
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/plain")
}

func TestProtectedRoutesRejectNewTrafficWhileDraining(t *testing.T) {
	f := newFixture(t, 1000, 1000)
	f.ready.Store(false)

	before := f.hits.Load()
	agent := doReq(t, f.handler, http.MethodPost, "/", testAgentATok, rpcBody(t), nil)
	assert.Equal(t, http.StatusServiceUnavailable, agent.Code)
	assert.Equal(t, before, f.hits.Load(), "draining traffic must not reach upstream")

	human := doReq(t, f.handler, http.MethodGet, "/api/v1/ledger", testRvwTok, nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, human.Code)
}

// --- agent trust domain: POST / ---

func TestProxyRoute_RoleBoundary(t *testing.T) {
	f := newFixture(t, 1000, 1000)

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{"valid agent allowed", testAgentATok, http.StatusOK},
		{"reviewer forbidden", testRvwTok, http.StatusForbidden},
		{"admin forbidden", testAdminTok, http.StatusForbidden},
		{"no token unauthorized", "", http.StatusUnauthorized},
		{"invalid token forbidden", "sk_bogus_token", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := f.hits.Load()
			rr := doReq(t, f.handler, http.MethodPost, "/", tc.token, rpcBody(t), nil)
			assert.Equal(t, tc.want, rr.Code)

			if tc.want == http.StatusOK {
				assert.Greater(t, f.hits.Load(), before, "request must reach the upstream target")
				assert.Equal(t, 1, f.ledger.count(), "allowed call must be audited")
			} else {
				assert.Equal(t, before, f.hits.Load(), "rejected request must never reach the target")
			}
		})
	}

	// Non-POST is rejected by the proxy's own ingress contract.
	rr := doReq(t, f.handler, http.MethodGet, "/", testAgentATok, nil, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// --- human trust domain: /api/v1/* management APIs ---

func TestHumanRoutes_RoleBoundary(t *testing.T) {
	f := newFixture(t, 1000, 1000)

	humanPaths := []string{
		"/api/v1/quarantine?status=pending",
		"/api/v1/ledger",
		"/api/v1/policies",
		"/api/v1/dashboard/stats",
	}

	for _, p := range humanPaths {
		t.Run("agent blocked from "+p, func(t *testing.T) {
			rr := doReq(t, f.handler, http.MethodGet, p, testAgentATok, nil, nil)
			assert.Equal(t, http.StatusForbidden, rr.Code)
			assert.Contains(t, rr.Body.String(), "insufficient role")

			// Agents cannot approve/deny either.
			rr = doReq(t, f.handler, http.MethodPost, "/api/v1/quarantine/1042/approve", testAgentATok, nil, nil)
			assert.Equal(t, http.StatusForbidden, rr.Code)
		})

		t.Run("reviewer allowed on "+p, func(t *testing.T) {
			if p == "/api/v1/quarantine?status=pending" {
				rr := doReq(t, f.handler, http.MethodGet, p, testRvwTok, nil, nil)
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.JSONEq(t, "[]\n", rr.Body.String())
			} else {
				rr := doReq(t, f.handler, http.MethodGet, p, testRvwTok, nil, nil)
				assert.Equal(t, http.StatusOK, rr.Code)
			}
		})

		t.Run("admin allowed on "+p, func(t *testing.T) {
			rr := doReq(t, f.handler, http.MethodGet, p, testAdminTok, nil, nil)
			assert.Equal(t, http.StatusOK, rr.Code)
		})

		t.Run("no token unauthorized on "+p, func(t *testing.T) {
			rr := doReq(t, f.handler, http.MethodGet, p, "", nil, nil)
			assert.Equal(t, http.StatusUnauthorized, rr.Code)
		})
	}
}

// --- rate limiting operates on authenticated identities ---

func TestRateLimit_ExhaustionReturns429(t *testing.T) {
	const burst = 2
	f := newFixture(t, 0.001, burst) // effectively no refill during the test

	for i := 0; i < burst; i++ {
		rr := doReq(t, f.handler, http.MethodPost, "/", testAgentATok, rpcBody(t), nil)
		require.Equalf(t, http.StatusOK, rr.Code, "request %d within burst should pass", i+1)
	}

	rr := doReq(t, f.handler, http.MethodPost, "/", testAgentATok, rpcBody(t), nil)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code, "exceeding burst must return 429")
	assert.Contains(t, rr.Body.String(), "rate limit exceeded")
}

func TestRateLimit_IndependentBucketsPerAgent(t *testing.T) {
	const burst = 2
	f := newFixture(t, 0.001, burst)

	for i := 0; i <= burst; i++ { // exhaust agent A's bucket
		doReq(t, f.handler, http.MethodPost, "/", testAgentATok, rpcBody(t), nil)
	}

	rr := doReq(t, f.handler, http.MethodPost, "/", testAgentATok, rpcBody(t), nil)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code, "agent A is exhausted")

	rr = doReq(t, f.handler, http.MethodPost, "/", testAgentBTok, rpcBody(t), nil)
	assert.Equal(t, http.StatusOK, rr.Code, "agent B must have its own bucket, unaffected by A")
}

func TestRateLimit_IgnoresClientControlledIdentity(t *testing.T) {
	const burst = 2
	f := newFixture(t, 0.001, burst)

	for i := 0; i <= burst; i++ { // exhaust agent A
		doReq(t, f.handler, http.MethodPost, "/", testAgentATok, rpcBody(t), nil)
	}

	// Spoofing A's identity via header/query/body must not drain or share buckets:
	// the limiter keys off the authenticated Bearer identity only.
	headers := map[string]string{"X-Agent-ID": testAgentAID}
	rr := doReq(t, f.handler, http.MethodPost, "/?agent="+testAgentAID, testAgentBTok, rpcBody(t), headers)
	assert.Equal(t, http.StatusOK, rr.Code, "bucket key must come from the authenticated token, not client input")

	// And B's own bucket is what gets charged: exhausting B now yields 429.
	for i := 0; i < burst; i++ {
		doReq(t, f.handler, http.MethodPost, "/", testAgentBTok, rpcBody(t), headers)
	}
	rr = doReq(t, f.handler, http.MethodPost, "/", testAgentBTok, rpcBody(t), headers)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
}

func TestRateLimit_FailsClosedWithoutAuthenticatedIdentity(t *testing.T) {
	rl := newRateLimiter(1000, 1000)
	passthrough := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := rl.middleware(passthrough)

	// No identity in context → the limiter must refuse, never silently skip.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	// With an authenticated identity the bucket applies normally.
	req = httptest.NewRequest(http.MethodPost, "/", nil).WithContext(
		auth.WithIdentity(context.Background(), auth.Identity{ID: "agent-x", Role: auth.RoleAgent}))
	rr = httptest.NewRecorder()
	protected.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRateLimit_UnauthenticatedRequestsNeverConsumeBuckets(t *testing.T) {
	const burst = 2
	f := newFixture(t, 0.001, burst)

	for i := 0; i < burst+3; i++ {
		rr := doReq(t, f.handler, http.MethodPost, "/", "", rpcBody(t), nil)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	}

	// The bucket was untouched by unauthenticated traffic.
	rr := doReq(t, f.handler, http.MethodPost, "/", testAgentATok, rpcBody(t), nil)
	assert.Equal(t, http.StatusOK, rr.Code)
}
