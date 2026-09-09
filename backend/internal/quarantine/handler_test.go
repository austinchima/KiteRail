package quarantine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/austinchima/kiterail/internal/db"
)

// ---- Mock store ----

// mockStore is an in-memory mirror of the REAL sql/quarantine.sql state
// machine. It must faithfully reproduce the real SQL semantics — claim does
// NOT increment attempts (ReturnToApproved/MarkReplayed do), Approve resets
// attempts to 0, and state transitions error when the guard doesn't match —
// because a mock that diverges from the database silently conceals bugs
// (this exact divergence once hid a live replay-exhaustion bug). When the SQL
// changes, change this too.
type mockStore struct {
	entries map[string]*db.QuarantineEntry
}

func newMockStore(entries ...*db.QuarantineEntry) *mockStore {
	m := &mockStore{entries: make(map[string]*db.QuarantineEntry)}
	for _, e := range entries {
		m.entries[e.ID] = e
	}
	return m
}

func (m *mockStore) Get(_ context.Context, id string) (db.QuarantineEntry, error) {
	e, ok := m.entries[id]
	if !ok {
		return db.QuarantineEntry{}, ErrNotFound
	}
	return *e, nil
}

func (m *mockStore) List(_ context.Context, status string) ([]db.QuarantineEntry, error) {
	var out []db.QuarantineEntry
	for _, e := range m.entries {
		if e.Status == status {
			out = append(out, *e)
		}
	}
	return out, nil
}

func (m *mockStore) Approve(_ context.Context, id, approvedBy string) error {
	e, ok := m.entries[id]
	if !ok || (e.Status != StatusPending && e.Status != StatusReplayFailed) {
		return ErrAlreadyResolved
	}
	e.Status = StatusApproved
	e.ResolvedBy = approvedBy
	e.Attempts = 0 // mirrors `attempts = 0` in ApproveQuarantineEntry
	return nil
}

func (m *mockStore) Deny(_ context.Context, id, deniedBy, reason string) error {
	e, ok := m.entries[id]
	if !ok || (e.Status != StatusPending && e.Status != StatusReplayFailed) {
		return ErrAlreadyResolved
	}
	e.Status = StatusDenied
	e.ResolvedBy = deniedBy
	return nil
}

func (m *mockStore) ClaimApproved(_ context.Context, limit int) ([]db.QuarantineEntry, error) {
	var out []db.QuarantineEntry
	for i := range m.entries {
		e := m.entries[i]
		if e.Status == StatusApproved {
			e.Status = StatusReplaying
			// Real SQL does NOT increment attempts at claim time.
			out = append(out, *e)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *mockStore) MarkReplayed(_ context.Context, id string) error {
	e, ok := m.entries[id]
	if !ok || e.Status != StatusReplaying {
		return ErrStaleTransition
	}
	e.Status = StatusReplayed
	e.Attempts++ // mirrors `attempts = attempts + 1` in MarkReplayed
	return nil
}

func (m *mockStore) MarkReplayFailed(_ context.Context, id string) error {
	e, ok := m.entries[id]
	if !ok || e.Status != StatusReplaying {
		return ErrStaleTransition
	}
	e.Status = StatusReplayFailed
	return nil
}

func (m *mockStore) ReturnToApproved(_ context.Context, id string) error {
	e, ok := m.entries[id]
	if !ok || e.Status != StatusReplaying {
		return ErrStaleTransition
	}
	e.Status = StatusApproved
	e.Attempts++ // mirrors `attempts = attempts + 1` in ReturnToApproved
	return nil
}

func (m *mockStore) RecoverStuckReplays(_ context.Context) (int64, error) {
	var n int64
	for _, e := range m.entries {
		if e.Status == StatusReplaying {
			e.Status = StatusApproved
			n++
		}
	}
	return n, nil
}

// WithReplayLock executes inline because each unit test owns its mock store.
// Database-backed concurrency is verified by integration tests against the
// real Postgres advisory lock.
func (m *mockStore) WithReplayLock(ctx context.Context, replay func(context.Context) error) (bool, error) {
	return true, replay(ctx)
}

// ---- Mock ledger ----

type mockLedger struct {
	entries []db.LedgerEntry
	err     error
}

func (m *mockLedger) Append(_ context.Context, e db.LedgerEntry) error {
	if m.err != nil {
		return m.err
	}
	m.entries = append(m.entries, e)
	return nil
}

// ---- Helpers ----

func reviewerCtx(ctx context.Context) context.Context {
	return auth.WithIdentity(ctx, auth.Identity{ID: "reviewer-jane", Role: auth.RoleReviewer})
}

func agentOnlyCtx(ctx context.Context) context.Context {
	return auth.WithIdentity(ctx, auth.Identity{ID: "agent-x", Role: auth.RoleAgent})
}

// ---- Handler HTTP-level tests ----

func TestApprove_RequiresReviewerRole(t *testing.T) {
	store := newMockStore(&db.QuarantineEntry{
		ID: "a3f1c9e2-7b4d-4a8e-9c6f-1d2e3f4a5b60", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: StatusPending, CreatedAt: time.Now(),
	})
	h := NewHandler(store, nil, zap.NewNop())

	cases := []struct {
		name string
		ctx  func(context.Context) context.Context
		want int
	}{
		{"no identity", func(c context.Context) context.Context { return c }, http.StatusForbidden},
		{"agent identity", agentOnlyCtx, http.StatusForbidden},
		{"reviewer identity", reviewerCtx, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/x/approve", strings.NewReader(`{"approved_by":"forge-me"}`))
			req = req.WithContext(tc.ctx(req.Context()))
			w := httptest.NewRecorder()
			h.approveEntry(w, req, "a3f1c9e2-7b4d-4a8e-9c6f-1d2e3f4a5b60")
			assert.Equal(t, tc.want, w.Code)
		})
	}

	entry := store.entries["a3f1c9e2-7b4d-4a8e-9c6f-1d2e3f4a5b60"]
	require.Equal(t, StatusApproved, entry.Status)
	assert.Equal(t, "reviewer-jane", entry.ResolvedBy, "approved_by MUST come from the authenticated identity, not the body")
}

func TestApprove_AlreadyResolved_Returns409(t *testing.T) {
	store := newMockStore(&db.QuarantineEntry{
		ID: "b4e2d8f3-8c5a-4b9f-0d7e-2e3f4a5b6c71", Status: StatusApproved, CreatedAt: time.Now(),
	})
	h := NewHandler(store, nil, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/x/approve", strings.NewReader(`{}`))
	req = req.WithContext(reviewerCtx(req.Context()))
	w := httptest.NewRecorder()
	h.approveEntry(w, req, "b4e2d8f3-8c5a-4b9f-0d7e-2e3f4a5b6c71")

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestApprove_NotFound_Returns404(t *testing.T) {
	h := NewHandler(newMockStore(), nil, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/999/approve", strings.NewReader(`{}`))
	req = req.WithContext(reviewerCtx(req.Context()))
	w := httptest.NewRecorder()
	h.approveEntry(w, req, "999")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeny_RecordsReviewerAndLedger(t *testing.T) {
	store := newMockStore(&db.QuarantineEntry{
		ID: "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82", Status: StatusPending, CreatedAt: time.Now(),
	})
	lg := &mockLedger{}
	h := NewHandler(store, nil, zap.NewNop())
	h.lStore = lg

	req := httptest.NewRequest(http.MethodPost, "/x/deny", strings.NewReader(`{"reason":"suspicious"}`))
	req = req.WithContext(reviewerCtx(req.Context()))
	w := httptest.NewRecorder()
	h.denyEntry(w, req, "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, StatusDenied, store.entries["c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82"].Status)
	assert.Equal(t, "reviewer-jane", store.entries["c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82"].ResolvedBy)
	require.Len(t, lg.entries, 1)
	assert.Equal(t, "hitl_denial", lg.entries[0].PolicyRule)
	assert.Equal(t, "reviewer-jane", lg.entries[0].Agent)
}

// TestDeny_EmptyBodyAllowed: a denial without a reason (empty body) is
// legitimate and must not be rejected by the body validation.
func TestDeny_EmptyBodyAllowed(t *testing.T) {
	store := newMockStore(&db.QuarantineEntry{
		ID: "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82", Status: StatusPending, CreatedAt: time.Now(),
	})
	h := NewHandler(store, nil, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/x/deny", strings.NewReader(""))
	req = req.WithContext(reviewerCtx(req.Context()))
	w := httptest.NewRecorder()
	h.denyEntry(w, req, "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, StatusDenied, store.entries["c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82"].Status)
}

// TestDeny_MalformedJSON_Rejected: the previously-unchecked decode error is
// now a 400 — a garbage body must not reach the store.
func TestDeny_MalformedJSON_Rejected(t *testing.T) {
	store := newMockStore(&db.QuarantineEntry{
		ID: "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82", Status: StatusPending, CreatedAt: time.Now(),
	})
	h := NewHandler(store, nil, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/x/deny", strings.NewReader(`{"reason":`))
	req = req.WithContext(reviewerCtx(req.Context()))
	w := httptest.NewRecorder()
	h.denyEntry(w, req, "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, StatusPending, store.entries["c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82"].Status,
		"malformed body must not transition the entry")
}

// TestDeny_OversizedBody_Rejected: the 1 KiB cap must bite before a large
// body is buffered and decoded.
func TestDeny_OversizedBody_Rejected(t *testing.T) {
	store := newMockStore(&db.QuarantineEntry{
		ID: "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82", Status: StatusPending, CreatedAt: time.Now(),
	})
	h := NewHandler(store, nil, zap.NewNop())

	big := `{"reason":"` + strings.Repeat("a", maxDenyBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/x/deny", strings.NewReader(big))
	req = req.WithContext(reviewerCtx(req.Context()))
	w := httptest.NewRecorder()
	h.denyEntry(w, req, "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, StatusPending, store.entries["c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82"].Status)
}

// ---- Worker durable replay tests ----

func newTestWorker(store *mockStore, targetURL string, lg *mockLedger) *Worker {
	wk := NewWorker(store, nil, zap.NewNop(), targetURL)
	if lg != nil {
		wk.lStore = lg
	}
	wk.maxReplayAttempts = defaultMaxReplayAttempts
	return wk
}

func TestWorker_ReplaySuccess_TransitionsToReplayed(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "kiterail-quarantine-c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82",
			r.Header.Get("Idempotency-Key"), "replay must carry a stable Idempotency-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82", AgentID: "a", ToolName: "t",
		Payload: []byte(`{"x":1}`), Status: StatusApproved, ResolvedBy: "jane", CreatedAt: time.Now(),
	})
	lg := &mockLedger{}
	wk := newTestWorker(store, target.URL, lg)

	entries, err := store.ClaimApproved(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	wk.processClaimed(context.Background(), entries[0])

	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, StatusReplayed, store.entries["c5d3e9a4-9d6b-4c0a-1e8f-3f4a5b6c7d82"].Status)
	require.Len(t, lg.entries, 1)
	assert.Equal(t, "approved_replayed", lg.entries[0].Decision)
	assert.Equal(t, "jane", lg.entries[0].Agent, "ledger must record the human approver")
}

func TestWorker_ProcessOnceRecoversOnlyWithinReplayPass(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	id := "c0ffee00-0000-4000-8000-000000000001"
	store := newMockStore(&db.QuarantineEntry{
		ID: id, AgentID: "agent", ToolName: "tool", Payload: []byte(`{}`),
		Status: StatusReplaying, CreatedAt: time.Now(),
	})
	wk := newTestWorker(store, target.URL, nil)

	// ProcessOnce acquires the store's replay ownership before recovery. The
	// mocked lock is inline; the integration suite verifies the real advisory
	// lock. The important invariant is that recovery is not a free-standing
	// operation that can reset another worker's live claim.
	wk.ProcessOnce(context.Background())
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, StatusReplayed, store.entries[id].Status)
}

func TestWorker_ReplayPreservesMcpMetadataAndDoesNotFollowRedirects(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "tools/call", r.Header.Get("Mcp-Method"))
		assert.Equal(t, "safe_tool", r.Header.Get("Mcp-Name"))
		assert.Equal(t, "tenant-blue", r.Header.Get("Mcp-Param-Tenant"))
		assert.Equal(t, "Bearer service-token", r.Header.Get("Authorization"))
		w.Header().Set("Location", "/somewhere-else")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer target.Close()

	id := "c0ffee00-0000-4000-8000-000000000002"
	store := newMockStore(&db.QuarantineEntry{
		ID: id, AgentID: "agent", ToolName: "tool", Payload: []byte(`{}`),
		Status: StatusApproved, CreatedAt: time.Now(),
		RequestHeaders: json.RawMessage(`{
			"Mcp-Method":["tools/call"],
			"Mcp-Name":["safe_tool"],
			"Mcp-Param-Tenant":["tenant-blue"],
			"Authorization":["Bearer untrusted-client-token"]
		}`),
	})
	wk := NewWorker(store, nil, zap.NewNop(), target.URL, WithTargetAuthToken("service-token"))

	entries, err := store.ClaimApproved(context.Background(), 1)
	require.NoError(t, err)
	wk.processClaimed(context.Background(), entries[0])

	assert.Equal(t, int32(1), calls.Load(), "replay must not follow redirects")
	assert.Equal(t, StatusApproved, store.entries[id].Status,
		"a redirect is an unsuccessful replay and remains retryable")
}

func TestWorker_TransientFailure_RetriesViaApprovedState(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "d6e4f0b5-0e7c-4d1b-2f9a-4a5b6c7d8e93", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: StatusApproved, CreatedAt: time.Now(),
	})
	wk := newTestWorker(store, target.URL, nil)

	entries, _ := store.ClaimApproved(context.Background(), 10)
	require.Len(t, entries, 1)
	wk.processClaimed(context.Background(), entries[0])

	// First claim failed but attempts remain — back to approved for re-claim.
	require.Equal(t, StatusApproved, store.entries["d6e4f0b5-0e7c-4d1b-2f9a-4a5b6c7d8e93"].Status)

	entries, _ = store.ClaimApproved(context.Background(), 10)
	require.Len(t, entries, 1)
	wk.processClaimed(context.Background(), entries[0])

	assert.Equal(t, int32(2), calls.Load())
	assert.Equal(t, StatusReplayed, store.entries["d6e4f0b5-0e7c-4d1b-2f9a-4a5b6c7d8e93"].Status)
}

func TestWorker_ExhaustsAttempts_MarksReplayFailed(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "e7f5a1c6-1f8d-4e2c-3a0b-5b6c7d8e9fa4", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: StatusApproved, CreatedAt: time.Now(),
	})
	lg := &mockLedger{}
	wk := newTestWorker(store, target.URL, lg)

	// The real SQL increments attempts on ReturnToApproved (release), not at
	// claim time, so exhaustion takes maxReplayAttempts+1 upstream calls:
	// attempts 0,1,2 fail and release; the call that reads attempts==3 exhausts.
	const replayCalls = defaultMaxReplayAttempts + 1
	for attempt := 0; attempt < replayCalls; attempt++ {
		entries, _ := store.ClaimApproved(context.Background(), 10)
		require.Len(t, entries, 1, "entry should be re-claimable while retries remain")
		wk.processClaimed(context.Background(), entries[0])
	}

	assert.Equal(t, int32(replayCalls), calls.Load())
	assert.Equal(t, StatusReplayFailed, store.entries["e7f5a1c6-1f8d-4e2c-3a0b-5b6c7d8e9fa4"].Status,
		"exhausted entries must surface to reviewers as replay_failed")
}

func TestWorker_ManualRetryAfterExhaust_Succeeds(t *testing.T) {
	var calls atomic.Int32
	id := "f8a6b2d7-2a9e-4f3d-4b1c-6c7d8e9fa0b5"
	const exhaustCalls = defaultMaxReplayAttempts + 1 // attempts increment on release, not claim
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= exhaustCalls {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: id, AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: StatusApproved, CreatedAt: time.Now(),
	})
	wk := newTestWorker(store, target.URL, nil)

	for range exhaustCalls {
		entries, _ := store.ClaimApproved(context.Background(), 10)
		wk.processClaimed(context.Background(), entries[0])
	}
	require.Equal(t, StatusReplayFailed, store.entries[id].Status)

	// Reviewer manually re-approves (resets attempts to 0); worker succeeds.
	require.NoError(t, store.Approve(context.Background(), id, "jane"))
	entries, _ := store.ClaimApproved(context.Background(), 10)
	require.Len(t, entries, 1)
	wk.processClaimed(context.Background(), entries[0])

	assert.Equal(t, StatusReplayed, store.entries[id].Status)
	assert.Equal(t, int32(exhaustCalls+1), calls.Load())
}

// ---- Task 3: replay auth parity with the ALLOW path ----
// Invariant: a request the proxy would ALLOW for an authenticated agent, and
// the same request quarantined-then-approved by a human, MUST reach an
// authenticated upstream with identical credentials. Regression net for the
// bug where approved replays omitted Authorization and 401'd forever.

func TestWorker_ReplayWithAuthToken_SucceedsAgainstAuthUpstream(t *testing.T) {
	const secret = "upstream-secret-token-abc123"
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	id := "a9b7c3d8-3b0f-4e4a-5c2d-7d8e9fa0b1c6"
	store := newMockStore(&db.QuarantineEntry{
		ID: id, AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: StatusApproved, CreatedAt: time.Now(),
	})
	wk := NewWorker(store, nil, zap.NewNop(), target.URL, WithTargetAuthToken(secret))

	entries, err := store.ClaimApproved(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	wk.processClaimed(context.Background(), entries[0])

	assert.Equal(t, int32(1), calls.Load(), "replay must reach the upstream exactly once")
	assert.Equal(t, StatusReplayed, store.entries[id].Status,
		"replay against an auth-required upstream must succeed when the token is provided")
}

func TestWorker_ReplayWithoutAuthToken_FailsAgainstAuthUpstream(t *testing.T) {
	// Documents the live bug's shape: without WithTargetAuthToken the worker
	// replays bare, the upstream 401s, and the entry churns approved→replaying
	// until attempts exhaust. main.go must always wire the token.
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	id := "b0c8d4e9-4c1a-4f5b-6d3e-8e9fa0b1c2d7"
	store := newMockStore(&db.QuarantineEntry{
		ID: id, AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: StatusApproved, CreatedAt: time.Now(),
	})
	lg := &mockLedger{}
	wk := newTestWorker(store, target.URL, lg)

	// Same call-count math as TestWorker_ExhaustsAttempts_MarksReplayFailed:
	// attempts increment on release, so exhaustion takes maxReplayAttempts+1 calls.
	const replayCalls = defaultMaxReplayAttempts + 1
	for attempt := 0; attempt < replayCalls; attempt++ {
		entries, _ := store.ClaimApproved(context.Background(), 10)
		require.Len(t, entries, 1)
		wk.processClaimed(context.Background(), entries[0])
	}

	assert.Equal(t, StatusReplayFailed, store.entries[id].Status,
		"replays without the target credential must not be marked replayed")
	assert.Equal(t, int32(replayCalls), calls.Load())
}

func TestWorker_AuthToken_NeverLeaksIntoPayloadLedgerOrLogs(t *testing.T) {
	const secret = "super-secret-upstream-token-xyz789"
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	var sawAuth atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	id := "c1d9e5f0-5d2b-4a6c-7e4f-9fa0b1c2d3e8"
	store := newMockStore(&db.QuarantineEntry{
		ID: id, AgentID: "a", ToolName: "t",
		Payload: []byte(`{"arguments":{}}`), Status: StatusApproved, CreatedAt: time.Now(),
	})
	lg := &mockLedger{}
	wk := NewWorker(store, nil, logger, target.URL, WithTargetAuthToken(secret))
	wk.lStore = lg

	entries, err := store.ClaimApproved(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	wk.processClaimed(context.Background(), entries[0])

	// The token DID go out on the wire — otherwise this test proves nothing.
	require.Equal(t, "Bearer "+secret, sawAuth.Load())

	// Secret isolation invariants:
	assert.NotContains(t, string(store.entries[id].Payload), secret,
		"token must never be persisted into the quarantine payload")
	for _, e := range lg.entries {
		assert.NotContains(t, fmt.Sprintf("%+v", e), secret,
			"token must never land in the audit ledger")
	}
	for _, entry := range logs.All() {
		assert.NotContains(t, entry.Message, secret)
		for _, field := range entry.Context {
			assert.NotContains(t, field.String, secret,
				"token must never be logged")
		}
	}
	assert.Equal(t, StatusReplayed, store.entries[id].Status)
}
