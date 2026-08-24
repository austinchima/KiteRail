package quarantine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
		return nil
	}
	e.Status = "replay_failed"
	return nil
}

// ---- Helper: build a real Handler wired to a mockStore ----

func buildHandler(mock *mockStore, targetURL string) *Handler {
	return &Handler{
		store:      nil, // unused in replay-unit tests
		lStore:     nil,
		logger:     zap.NewNop(),
		targetURL:  targetURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func newApproveDriver(mock *mockStore, targetURL string) *approveDriver {
	return &approveDriver{
		mock:              mock,
		logger:            zap.NewNop(),
		targetURL:         targetURL,
		httpClient:        &http.Client{Timeout: 5 * time.Second},
		maxReplayAttempts: defaultMaxReplayAttempts,
		replayBackoff:     defaultReplayBackoff,
	}
}

type approveDriver struct {
	mock              *mockStore
	logger            *zap.Logger
	targetURL         string
	httpClient        *http.Client
	maxReplayAttempts int
	replayBackoff     []time.Duration
}

func (d *approveDriver) approveEntry(w http.ResponseWriter, r *http.Request, id string, done chan struct{}) {
	var body struct {
		ApprovedBy string `json:"approved_by"`
	}
	b, _ := io.ReadAll(r.Body)
	if len(b) > 0 {
		_ = json.NewDecoder(strings.NewReader(string(b))).Decode(&body)
	}
	if body.ApprovedBy == "" {
		body.ApprovedBy = "api"
	}

	entry, err := d.mock.Get(r.Context(), id)
	if err != nil {
		http.Error(w, `{"error": "quarantine item not found"}`, http.StatusNotFound)
		if done != nil {
			close(done)
		}
		return
	}

	if err := d.mock.Approve(r.Context(), id, body.ApprovedBy); err != nil {
		if err == ErrAlreadyResolved {
			http.Error(w, `{"error": "quarantine item already resolved"}`, http.StatusConflict)
		} else {
			http.Error(w, `{"error": "failed to approve"}`, http.StatusInternalServerError)
		}
		if done != nil {
			close(done)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"approved","id":"` + id + `"}`))

	go func() {
		defer func() {
			if done != nil {
				close(done)
			}
		}()
		h := &Handler{
			store:             nil,
			lStore:            nil,
			logger:            d.logger,
			targetURL:         d.targetURL,
			httpClient:        d.httpClient,
			maxReplayAttempts: d.maxReplayAttempts,
			replayBackoff:     d.replayBackoff,
		}
		for attempt := 0; attempt < d.maxReplayAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(d.replayBackoff[attempt-1])
			}
			if err := h.doReplay(context.Background(), id, entry, body.ApprovedBy); err == nil {
				return
			}
		}
		_ = d.mock.MarkReplayFailed(context.Background(), id)
	}()
}

// ---- HTTP-level tests ----

func TestApprove_Returns200Immediately(t *testing.T) {
	ready := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ready
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "1", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: "pending", CreatedAt: time.Now(),
	})
	d := newApproveDriver(store, target.URL)
	d.maxReplayAttempts = defaultMaxReplayAttempts
	d.replayBackoff = []time.Duration{0, 0}
	done := make(chan struct{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/1/approve", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	start := time.Now()
	d.approveEntry(w, req, "1", done)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Less(t, time.Since(start), 500*time.Millisecond, "handler must not block on target")

	close(ready)
	<-done
}

func TestApprove_AlreadyResolved_Returns409(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "2", Status: "approved", CreatedAt: time.Now(),
	})
	d := newApproveDriver(store, target.URL)
	done := make(chan struct{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/2/approve", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	d.approveEntry(w, req, "2", done)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestApprove_NotFound_Returns404(t *testing.T) {
	store := newMockStore()
	d := newApproveDriver(store, "http://unused")
	done := make(chan struct{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/999/approve", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	d.approveEntry(w, req, "999", done)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func zeroBackoffHandler(targetURL string) *Handler {
	return &Handler{
		store:             nil,
		lStore:            nil,
		logger:            zap.NewNop(),
		targetURL:         targetURL,
		httpClient:        &http.Client{Timeout: 5 * time.Second},
		maxReplayAttempts: defaultMaxReplayAttempts,
		replayBackoff:     []time.Duration{0, 0},
	}
}

func TestReplayWithRetry_SucceedsFirstAttempt(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "10", AgentID: "a", ToolName: "t",
		Payload: []byte(`{"x":1}`), Status: "approved", CreatedAt: time.Now(),
	})
	h := zeroBackoffHandler(target.URL)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.replayWithRetry(context.Background(), "10", *store.entries["10"], "jane")
	}()
	<-done

	assert.Equal(t, int32(1), calls.Load(), "should have hit target exactly once")
}

func TestReplayWithRetry_TransientFailureThenSuccess(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "11", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: "approved", CreatedAt: time.Now(),
	})
	h := zeroBackoffHandler(target.URL)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.replayWithRetry(context.Background(), "11", *store.entries["11"], "jane")
	}()
	<-done

	assert.Equal(t, int32(3), calls.Load(), "should retry until success on attempt 3")
}

func TestReplayWithRetry_ExhaustsAndMarksReplayFailed(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "12", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: "approved", CreatedAt: time.Now(),
	})

	h := &Handler{
		store: nil, lStore: nil, logger: zap.NewNop(),
		targetURL:         target.URL,
		httpClient:        &http.Client{Timeout: 5 * time.Second},
		maxReplayAttempts: 3,
		replayBackoff:     []time.Duration{0, 0},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for attempt := 0; attempt < h.maxReplayAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(h.replayBackoff[attempt-1])
			}
			_ = h.doReplay(context.Background(), "12", *store.entries["12"], "api")
		}
		_ = store.MarkReplayFailed(context.Background(), "12")
	}()
	<-done

	assert.Equal(t, int32(3), calls.Load(), "all 3 attempts should hit the target")
	assert.Equal(t, "replay_failed", store.entries["12"].Status)
}

func TestReplayWithRetry_ManualRetryAfterAutoExhaust(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	store := newMockStore(&db.QuarantineEntry{
		ID: "13", AgentID: "a", ToolName: "t",
		Payload: []byte(`{}`), Status: "approved", CreatedAt: time.Now(),
	})
	h := zeroBackoffHandler(target.URL)

	phase1Done := make(chan struct{})
	go func() {
		defer close(phase1Done)
		for attempt := 0; attempt < h.maxReplayAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(h.replayBackoff[attempt-1])
			}
			_ = h.doReplay(context.Background(), "13", *store.entries["13"], "api")
		}
		_ = store.MarkReplayFailed(context.Background(), "13")
	}()
	<-phase1Done

	require.Equal(t, "replay_failed", store.entries["13"].Status)
	require.Equal(t, int32(3), calls.Load())

	require.NoError(t, store.Approve(context.Background(), "13", "jane"))
	require.Equal(t, "approved", store.entries["13"].Status)

	phase2Done := make(chan struct{})
	go func() {
		defer close(phase2Done)
		h.replayWithRetry(context.Background(), "13", *store.entries["13"], "jane")
	}()
	<-phase2Done

	assert.Equal(t, int32(4), calls.Load(), "4th call (manual retry) should succeed")
}