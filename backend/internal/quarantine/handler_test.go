package quarantine

import (
	"context"
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

	"github.com/austinchima/kiterail/internal/db"
)

// ---- Mock store ----

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
			e.Attempts++
			out = append(out, *e)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *mockStore) MarkReplayed(_ context.Context, id string) error {
	if e, ok := m.entries[id]; ok && e.Status == StatusReplaying {
		e.Status = StatusReplayed
	}
	return nil
}

func (m *mockStore) MarkReplayFailed(_ context.Context, id string) error {
	if e, ok := m.entries[id]; ok && (e.Status == StatusApproved || e.Status == StatusReplaying) {
		e.Status = StatusReplayFailed
	}
	return nil
}

func (m *mockStore) ReturnToApproved(_ context.Context, id string) error {
	if e, ok := m.entries[id]; ok && e.Status == StatusReplaying {
		e.Status = StatusApproved
	}
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

	for attempt := 0; attempt < defaultMaxReplayAttempts; attempt++ {
		entries, _ := store.ClaimApproved(context.Background(), 10)
		require.Len(t, entries, 1, "entry should be re-claimable while retries remain")
		wk.processClaimed(context.Background(), entries[0])
	}

	assert.Equal(t, int32(defaultMaxReplayAttempts), calls.Load())
	assert.Equal(t, StatusReplayFailed, store.entries["e7f5a1c6-1f8d-4e2c-3a0b-5b6c7d8e9fa4"].Status,
		"exhausted entries must surface to reviewers as replay_failed")
}

func TestWorker_ManualRetryAfterExhaust_Succeeds(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= defaultMaxReplayAttempts {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	id := "f8a6b2d7-2a9e-4f3d-4b1c-6c7d8e9fa0b5"
	store := newMockStore(&db.QuarantineEntry{
		ID: id, AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: StatusApproved, CreatedAt: time.Now(),
	})
	wk := newTestWorker(store, target.URL, nil)

	for range defaultMaxReplayAttempts {
		entries, _ := store.ClaimApproved(context.Background(), 10)
		wk.processClaimed(context.Background(), entries[0])
	}
	require.Equal(t, StatusReplayFailed, store.entries[id].Status)

	// Reviewer manually re-approves; attempts reset; worker succeeds.
	require.NoError(t, store.Approve(context.Background(), id, "jane"))
	entries, _ := store.ClaimApproved(context.Background(), 10)
	require.Len(t, entries, 1)
	wk.processClaimed(context.Background(), entries[0])

	assert.Equal(t, StatusReplayed, store.entries[id].Status)
	assert.Equal(t, int32(defaultMaxReplayAttempts+1), calls.Load())
}
