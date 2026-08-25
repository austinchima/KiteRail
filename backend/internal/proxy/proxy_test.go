package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Mocks

type MockOPAEngine struct {
	Decision ProxyDecision
	Err      error
	Input    EvalInput
}

func (m *MockOPAEngine) Evaluate(ctx context.Context, input EvalInput) (ProxyDecision, error) {
	m.Input = input
	return m.Decision, m.Err
}

type MockEventPublisher struct {
	TelemetryEvents  []interface{}
	AuditEvents      []interface{}
	QuarantineEvents []interface{}
}

func (m *MockEventPublisher) PublishTelemetry(ctx context.Context, event interface{}) error {
	m.TelemetryEvents = append(m.TelemetryEvents, event)
	return nil
}

func (m *MockEventPublisher) PublishAudit(ctx context.Context, event interface{}) error {
	m.AuditEvents = append(m.AuditEvents, event)
	return nil
}

func (m *MockEventPublisher) PublishQuarantine(ctx context.Context, event interface{}) error {
	m.QuarantineEvents = append(m.QuarantineEvents, event)
	return nil
}

type MockQuarantineStore struct {
	CreatedItems []struct {
		AgentID string
		Tool    string
		Payload []byte
	}
	ReturnID string
	Err      error
}

func (m *MockQuarantineStore) Create(ctx context.Context, agentID, toolName string, payload []byte) (string, error) {
	m.CreatedItems = append(m.CreatedItems, struct {
		AgentID string
		Tool    string
		Payload []byte
	}{agentID, toolName, payload})
	return m.ReturnID, m.Err
}

type MockLedgerStore struct {
	Entries []db.LedgerEntry
	Err     error
}

func (m *MockLedgerStore) Append(ctx context.Context, entry db.LedgerEntry) error {
	if m.Err != nil {
		return m.Err
	}
	m.Entries = append(m.Entries, entry)
	return nil
}

func agentCtx(ctx context.Context, id string) context.Context {
	return auth.WithIdentity(ctx, auth.Identity{ID: id, Role: auth.RoleAgent})
}

// Tests

func TestServeHTTP_Allow(t *testing.T) {
	logger := zap.NewNop()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer backend.Close()

	engine := &MockOPAEngine{
		Decision: ProxyDecision{Action: "allow", Rule: "allow_all"},
	}
	publisher := &MockEventPublisher{}
	qStore := &MockQuarantineStore{}
	lStore := &MockLedgerStore{}

	handler, err := NewHandler(logger, backend.URL, engine, publisher, qStore, lStore)
	require.NoError(t, err)

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "example_tool",
			"arguments": map[string]interface{}{
				"arg1": "val1",
			},
		},
		"id": 1,
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(agentCtx(req.Context(), "agent_1"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "example_tool", engine.Input.Tool)
	assert.Equal(t, "agent_1", engine.Input.Agent)

	assert.Len(t, publisher.TelemetryEvents, 1)
	assert.Len(t, publisher.AuditEvents, 1)
	assert.Len(t, publisher.QuarantineEvents, 0)

	assert.Len(t, lStore.Entries, 1)
	assert.Equal(t, "allow", lStore.Entries[0].Decision)
}

func TestServeHTTP_Deny(t *testing.T) {
	logger := zap.NewNop()

	engine := &MockOPAEngine{
		Decision: ProxyDecision{Action: "deny", Rule: "deny_all", Explanation: "forbidden"},
	}
	publisher := &MockEventPublisher{}
	qStore := &MockQuarantineStore{}
	lStore := &MockLedgerStore{}

	handler, err := NewHandler(logger, "http://localhost:9999", engine, publisher, qStore, lStore)
	require.NoError(t, err)

	payload := map[string]interface{}{
		"method": "direct_tool",
		"params": map[string]interface{}{},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(agentCtx(req.Context(), "agent_2"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "forbidden", resp["explanation"])

	assert.Len(t, publisher.TelemetryEvents, 1)
	assert.Len(t, publisher.AuditEvents, 1)
	assert.Len(t, lStore.Entries, 1)
	assert.Equal(t, "deny", lStore.Entries[0].Decision)
}

func TestServeHTTP_Quarantine(t *testing.T) {
	logger := zap.NewNop()

	engine := &MockOPAEngine{
		Decision: ProxyDecision{Action: "quarantine", Rule: "quarantine_rule"},
	}
	publisher := &MockEventPublisher{}
	qStore := &MockQuarantineStore{ReturnID: "q-123"}
	lStore := &MockLedgerStore{}

	handler, err := NewHandler(logger, "http://localhost:9999", engine, publisher, qStore, lStore)
	require.NoError(t, err)

	payload := map[string]interface{}{
		"method": "suspicious_tool",
		"params": map[string]interface{}{},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(agentCtx(req.Context(), "agent_3"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "quarantined", resp["status"])

	assert.Len(t, publisher.TelemetryEvents, 1)
	assert.Len(t, publisher.QuarantineEvents, 1)

	assert.Len(t, lStore.Entries, 1)
	assert.Equal(t, "quarantine", lStore.Entries[0].Decision)

	assert.Len(t, qStore.CreatedItems, 1)
	assert.Equal(t, "agent_3", qStore.CreatedItems[0].AgentID)
	assert.Equal(t, "suspicious_tool", qStore.CreatedItems[0].Tool)
}

// --- Fail-closed ingress (#2) ---

func TestServeHTTP_FailClosed_Ingress(t *testing.T) {
	logger := zap.NewNop()
	forwarded := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	newProxy := func() *Handler {
		h, err := NewHandler(logger, backend.URL,
			&MockOPAEngine{Decision: ProxyDecision{Action: "allow"}},
			&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
		require.NoError(t, err)
		return h
	}

	cases := []struct {
		name   string
		method string
		body   string
	}{
		{"GET rejected", http.MethodGet, `{}`},
		{"PUT rejected", http.MethodPut, `{"method":"x","params":{}}`},
		{"non-JSON rejected", http.MethodPost, "this is not json"},
		{"missing params rejected", http.MethodPost, `{"method":"tools/call"}`},
		{"missing method rejected", http.MethodPost, `{"params":{"name":"t"}}`},
		{"non-string method rejected", http.MethodPost, `{"method":123,"params":{}}`},
		{"empty method rejected", http.MethodPost, `{"method":"","params":{}}`},
		{"tools/call without name rejected", http.MethodPost, `{"method":"tools/call","params":{"arguments":{}}}`},
		{"non-object params rejected", http.MethodPost, `{"method":"x","params":[1,2]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwarded = false
			req := httptest.NewRequest(tc.method, "/", bytes.NewBufferString(tc.body))
			req = req.WithContext(agentCtx(req.Context(), "agent_x"))
			rr := httptest.NewRecorder()

			newProxy().ServeHTTP(rr, req)

			assert.NotEqual(t, http.StatusOK, rr.Code, "malformed request must not succeed")
			assert.False(t, forwarded, "malformed request must never reach the target")
		})
	}
}

func TestServeHTTP_FailClosed_OnBodyTooLarge(t *testing.T) {
	logger := zap.NewNop()
	forwarded := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler, err := NewHandler(logger, backend.URL,
		&MockOPAEngine{Decision: ProxyDecision{Action: "allow"}},
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{},
		WithMaxBodyBytes(64),
	)
	require.NoError(t, err)

	big := make([]byte, 128)
	for i := range big {
		big[i] = 'a'
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(big))
	req = req.WithContext(agentCtx(req.Context(), "agent_big"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	assert.False(t, forwarded)
}

// --- Fail-closed ledger guarantee (#4) ---

func TestServeHTTP_FailClosed_OnLedgerError(t *testing.T) {
	logger := zap.NewNop()
	forwarded := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler, err := NewHandler(logger, backend.URL,
		&MockOPAEngine{Decision: ProxyDecision{Action: "allow", Rule: "allow_all"}},
		&MockEventPublisher{}, &MockQuarantineStore{},
		&MockLedgerStore{Err: assert.AnError},
	)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{"method": "some_tool", "params": map[string]interface{}{}})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(agentCtx(req.Context(), "agent_l"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.False(t, forwarded, "allowed requests MUST NOT execute when the audit ledger is unavailable")
}

// --- Auth middleware ---

func TestAuthMiddleware(t *testing.T) {
	logger := zap.NewNop()
	identities := map[string]auth.Identity{
		"agent-key":    {ID: "agent-alpha", Role: auth.RoleAgent},
		"reviewer-key": {ID: "reviewer-bob", Role: auth.RoleReviewer},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.FromContext(r.Context())
		if ok {
			w.Write([]byte(string(id.Role) + ":" + id.ID))
		}
	})

	middleware := auth.Middleware(identities, logger, nextHandler)

	tests := []struct {
		name       string
		setupReq   func() *http.Request
		expectCode int
		expectBody string
	}{
		{
			name:       "No Auth",
			setupReq:   func() *http.Request { return httptest.NewRequest(http.MethodGet, "/", nil) },
			expectCode: http.StatusUnauthorized,
		},
		{
			name: "Invalid Auth Header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer invalid-key")
				return req
			},
			expectCode: http.StatusForbidden,
		},
		{
			name: "Valid Agent Key",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer agent-key")
				return req
			},
			expectCode: http.StatusOK,
			expectBody: "agent:agent-alpha",
		},
		{
			name: "Query Param Token Rejected",
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?token=agent-key", nil)
			},
			expectCode: http.StatusUnauthorized,
		},
		{
			name: "Malformed Header Rejected",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "agent-key")
				return req
			},
			expectCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setupReq()
			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectCode, rr.Code)
			if tc.expectBody != "" {
				assert.Equal(t, tc.expectBody, rr.Body.String())
			}
		})
	}
}

func TestRequireRole(t *testing.T) {
	guard := auth.RequireRole(auth.RoleReviewer, auth.RoleAdmin)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := guard(ok)

	tests := []struct {
		name     string
		identity auth.Identity
		want     int
	}{
		{"agent forbidden", auth.Identity{ID: "a", Role: auth.RoleAgent}, http.StatusForbidden},
		{"reviewer allowed", auth.Identity{ID: "r", Role: auth.RoleReviewer}, http.StatusOK},
		{"admin allowed", auth.Identity{ID: "d", Role: auth.RoleAdmin}, http.StatusOK},
		{"no identity forbidden", auth.Identity{}, http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.identity.ID != "" || tc.identity.Role != "" {
				req = req.WithContext(auth.WithIdentity(req.Context(), tc.identity))
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tc.want, rr.Code)
		})
	}
}

// --- Authorization header stripping ---

func TestServeHTTP_Allow_StripsAuthorizationHeader(t *testing.T) {
	logger := zap.NewNop()
	var upstreamAuth atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	engine := &MockOPAEngine{Decision: ProxyDecision{Action: "allow", Rule: "allow_all"}}
	handler, err := NewHandler(logger, backend.URL, engine, &MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	payload := map[string]interface{}{"method": "some_tool", "params": map[string]interface{}{}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk_secret_do_not_leak")
	req = req.WithContext(agentCtx(req.Context(), "agent_1"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "", upstreamAuth.Load(), "Authorization header must not reach the target")
}

func TestServeHTTP_TargetAuthTokenApplied(t *testing.T) {
	logger := zap.NewNop()
	var upstreamAuth atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler, err := NewHandler(logger, backend.URL,
		&MockOPAEngine{Decision: ProxyDecision{Action: "allow"}},
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{},
		WithTargetAuthToken("svc-credential"),
	)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{"method": "some_tool", "params": map[string]interface{}{}})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(agentCtx(req.Context(), "agent_1"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "Bearer svc-credential", upstreamAuth.Load())
}
