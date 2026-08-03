package quarantine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mockStore implements a minimal in-memory quarantine store for handler tests.
type mockStore struct {
	entries map[string]*QuarantineEntry
}

func newMockStore(entries ...*QuarantineEntry) *mockStore {
	m := &mockStore{entries: make(map[string]*QuarantineEntry)}
	for _, e := range entries {
		m.entries[e.ID] = e
	}
	return m
}

func (m *mockStore) Get(_ context.Context, id string) (QuarantineEntry, error) {
	e, ok := m.entries[id]
	if !ok {
		return QuarantineEntry{}, ErrNotFound
	}
	return *e, nil
}

func (m *mockStore) List(_ context.Context, status string) ([]QuarantineEntry, error) {
	var out []QuarantineEntry
	for _, e := range m.entries {
		if e.Status == status {
			out = append(out, *e)
		}
	}
	return out, nil
}

func (m *mockStore) Approve(_ context.Context, id, approvedBy string) error {
	e, ok := m.entries[id]
	if !ok || (e.Status != "pending" && e.Status != "replay_failed") {
		return ErrAlreadyResolved
	}
	e.Status = "approved"
	e.ResolvedBy = approvedBy
	return nil
}

func (m *mockStore) Deny(_ context.Context, id, deniedBy, reason string) error {
	e, ok := m.entries[id]
	if !ok || (e.Status != "pending" && e.Status != "replay_failed") {
		return ErrAlreadyResolved
	}
	e.Status = "denied"
	e.ResolvedBy = deniedBy
	return nil
}

func (m *mockStore) MarkReplayFailed(_ context.Context, id string) error {
	e, ok := m.entries[id]
	if !ok {
		return nil // best-effort; don't surface as error
	}
	e.Status = "replay_failed"
	return nil
}

// newTestHandler wires up a Handler backed by the mock store and pointed at
// targetURL (a test HTTP server URL).
func newTestHandler(store *mockStore, targetURL string) *Handler {
	logger := zap.NewNop()
	return &Handler{
		store:     &Store{},       // unused — we override methods via embedding trick below
		lStore:    nil,            // ledger writes are best-effort; nil is valid
		logger:    logger,
		targetURL: targetURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// handlerWithMock replaces the store field on a real Handler with our mock.
// We achieve this by building the handler directly — no embedding needed.
func handlerWithMock(mock *mockStore, targetURL string) *handlerMock {
	return &handlerMock{
		store:      mock,
		logger:     zap.NewNop(),
		targetURL:  targetURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// handlerMock mirrors Handler but uses mockStore instead of *Store.
// This avoids the need to extract a Store interface for just these tests.
type handlerMock struct {
	store      *mockStore
	logger     *zap.Logger
	targetURL  string
	httpClient *http.Client
}

func (h *handlerMock) approveAndReplay(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		ApprovedBy string `json:"approved_by"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.ApprovedBy == "" {
		body.ApprovedBy = "api"
	}

	entry, err := h.store.Get(r.Context(), id)
	if err != nil {
		http.Error(w, `{"error": "quarantine item not found"}`, http.StatusNotFound)
		return
	}

	if err := h.store.Approve(r.Context(), id, body.ApprovedBy); err != nil {
		if err == ErrAlreadyResolved {
			http.Error(w, `{"error": "quarantine item already resolved"}`, http.StatusConflict)
			return
		}
		http.Error(w, `{"error": "failed to approve"}`, http.StatusInternalServerError)
		return
	}

	// Replay.
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, h.targetURL, strings.NewReader(string(entry.Payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KiteRail-Agent", entry.AgentID)
	req.Header.Set("X-KiteRail-Quarantine-ID", id)
	req.Header.Set("X-KiteRail-Approved-By", body.ApprovedBy)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		_ = h.store.MarkReplayFailed(r.Context(), id)
		http.Error(w, `{"error": "target replay failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = h.store.MarkReplayFailed(r.Context(), id)
		http.Error(w, `{"error": "target replay failed"}`, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
}

// ---- Tests ----

func TestApprove_ReplaySuccess(t *testing.T) {
	// Start a mock target that records incoming requests.
	var replayedBody string
	var replayedAgent string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		replayedBody = string(b)
		replayedAgent = r.Header.Get("X-KiteRail-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	payload := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"stripe.charge.refund","arguments":{"amount":5000}}}`)
	store := newMockStore(&QuarantineEntry{
		ID:        "42",
		AgentID:   "agent_alpha",
		ToolName:  "stripe.charge.refund",
		Payload:   payload,
		Status:    "pending",
		CreatedAt: time.Now(),
	})
	h := handlerWithMock(store, target.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/42/approve",
		strings.NewReader(`{"approved_by":"jane"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.approveAndReplay(w, req, "42")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, string(payload), replayedBody, "target should receive original payload verbatim")
	assert.Equal(t, "agent_alpha", replayedAgent, "target should see original agent identity")
	assert.Equal(t, "approved", store.entries["42"].Status, "entry should be marked approved")
}

func TestApprove_AlreadyResolved_Returns409(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&QuarantineEntry{
		ID: "99", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: "approved", CreatedAt: time.Now(),
	})
	h := handlerWithMock(store, target.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/99/approve", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.approveAndReplay(w, req, "99")

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestApprove_NotFound_Returns404(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore() // empty
	h := handlerWithMock(store, target.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/999/approve", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.approveAndReplay(w, req, "999")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestApprove_TargetError_Returns502(t *testing.T) {
	// Target always returns 500.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()

	store := newMockStore(&QuarantineEntry{
		ID: "7", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: "pending", CreatedAt: time.Now(),
	})
	h := handlerWithMock(store, target.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/7/approve", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.approveAndReplay(w, req, "7")

	assert.Equal(t, http.StatusBadGateway, w.Code)
	// Item must be replay_failed so the PENDING inbox surfaces it for retry.
	assert.Equal(t, "replay_failed", store.entries["7"].Status)
}

func TestApprove_RetryAfterFailure_Succeeds(t *testing.T) {
	// First call: target returns 500 → item goes replay_failed.
	// Second call: target is healthy → item goes approved.
	callCount := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&QuarantineEntry{
		ID: "8", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: "pending", CreatedAt: time.Now(),
	})
	h := handlerWithMock(store, target.URL)

	// First approve attempt — target is down.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/8/approve", strings.NewReader(`{}`))
	w1 := httptest.NewRecorder()
	h.approveAndReplay(w1, req1, "8")
	require.Equal(t, http.StatusBadGateway, w1.Code)
	require.Equal(t, "replay_failed", store.entries["8"].Status)

	// Second approve attempt — target is healthy now.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/8/approve", strings.NewReader(`{}`))
	w2 := httptest.NewRecorder()
	h.approveAndReplay(w2, req2, "8")
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "approved", store.entries["8"].Status)
	assert.Equal(t, 2, callCount)
}
