package ledger

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newMockHandler(t *testing.T) (*Handler, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	store, err := New(sqlDB)
	require.NoError(t, err)
	return NewHandler(store, zap.NewNop()), mock
}

var ledgerColumns = []string{"seq_num", "timestamp", "agent", "tool", "decision", "policy_rule", "payload_hash", "prev_hash", "hash", "request_id", "policy_version"}

func serve(h *Handler, method, target string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_QueryValidatesParameters(t *testing.T) {
	h, _ := newMockHandler(t)
	for _, target := range []string{"/?limit=0", "/?limit=1001", "/?limit=x", "/?before=0", "/?before=-3"} {
		assert.Equal(t, http.StatusBadRequest, serve(h, http.MethodGet, target, "").Code, target)
	}
	assert.Equal(t, http.StatusMethodNotAllowed, serve(h, http.MethodPost, "/", "").Code)
	assert.Equal(t, http.StatusNotFound, serve(h, http.MethodGet, "/nope", "").Code)
}

func TestHandler_QueryFullPageSetsNextCursor(t *testing.T) {
	h, mock := newMockHandler(t)
	now := time.Now()
	mock.ExpectQuery("FROM ledger").
		WillReturnRows(sqlmock.NewRows(ledgerColumns).
			AddRow(9, now, "a", "t", "allow", "r", "p", "x", "h9", "", "").
			AddRow(8, now, "a", "t", "allow", "r", "p", "x", "h8", "", ""))

	rec := serve(h, http.MethodGet, "/?limit=2&agent=a", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "8", rec.Header().Get("X-Next-Before"))
	assert.Contains(t, rec.Body.String(), `"seq_num":9`)
}

func TestHandler_HeadOnEmptyLedger(t *testing.T) {
	h, mock := newMockHandler(t)
	mock.ExpectQuery("SELECT seq_num, hash, timestamp FROM ledger").
		WillReturnRows(sqlmock.NewRows([]string{"seq_num", "hash", "timestamp"}))
	rec := serve(h, http.MethodGet, "/head", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"seq_num":0,"hash":""}`, rec.Body.String())
}

func TestHandler_VerifyRejectsMalformedAnchor(t *testing.T) {
	h, _ := newMockHandler(t)
	assert.Equal(t, http.StatusBadRequest, serve(h, http.MethodGet, "/verify?anchor_seq=1", "").Code)
	assert.Equal(t, http.StatusBadRequest, serve(h, http.MethodGet, "/verify?anchor_seq=x&anchor_hash=h", "").Code)
	assert.Equal(t, http.StatusBadRequest, serve(h, http.MethodPost, "/verify", `{"seq_num":3}`).Code)
	assert.Equal(t, http.StatusBadRequest, serve(h, http.MethodGet, "/export?after_seq=-1", "").Code)
}

func TestHandler_VerifyAndExportAreSingleFlight(t *testing.T) {
	h, _ := newMockHandler(t)
	h.fullScan.Store(true) // a verification or export is already running
	assert.Equal(t, http.StatusTooManyRequests, serve(h, http.MethodGet, "/verify", "").Code)
	assert.Equal(t, http.StatusTooManyRequests, serve(h, http.MethodGet, "/export", "").Code)
}

func TestHandler_ExportStreamsNDJSON(t *testing.T) {
	h, mock := newMockHandler(t)
	now := time.Now()
	mock.ExpectQuery("WHERE seq_num > \\$1 ORDER BY seq_num ASC").
		WithArgs(int64(5)).
		WillReturnRows(sqlmock.NewRows(ledgerColumns).
			AddRow(6, now, "a", "t", "allow", "r", "p", "x", "h6", "", "").
			AddRow(7, now, "a", "t", "deny", "r", "p", "h6", "h7", "", ""))

	rec := serve(h, http.MethodGet, "/export?after_seq=5", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/x-ndjson", rec.Header().Get("Content-Type"))
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[1], `"seq_num":7`)
	assert.False(t, h.fullScan.Load(), "the single-flight guard is released")
}
