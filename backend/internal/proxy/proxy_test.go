package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/types"
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
		Headers http.Header
	}
	ReturnID string
	Err      error
}

func (m *MockQuarantineStore) Create(ctx context.Context, agentID, toolName string, payload []byte, headers http.Header) (string, error) {
	m.CreatedItems = append(m.CreatedItems, struct {
		AgentID string
		Tool    string
		Payload []byte
		Headers http.Header
	}{agentID, toolName, payload, headers})
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
		Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"},
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
	// RawMethod is the JSON-RPC protocol method from the validated body,
	// never the HTTP method (Phase 3's one documented meaning).
	assert.Equal(t, "tools/call", engine.Input.RawMethod)

	assert.Len(t, publisher.TelemetryEvents, 1)
	assert.Len(t, publisher.AuditEvents, 1)
	assert.Len(t, publisher.QuarantineEvents, 0)

	assert.Len(t, lStore.Entries, 1)
	assert.Equal(t, "allow", lStore.Entries[0].Decision)
}

func TestServeHTTP_Deny(t *testing.T) {
	logger := zap.NewNop()

	engine := &MockOPAEngine{
		Decision: ProxyDecision{Action: types.ActionDeny, Rule: "deny_all", Explanation: "forbidden"},
	}
	publisher := &MockEventPublisher{}
	qStore := &MockQuarantineStore{}
	lStore := &MockLedgerStore{}

	handler, err := NewHandler(logger, "http://localhost:9999", engine, publisher, qStore, lStore)
	require.NoError(t, err)

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "direct_tool",
		"params":  map[string]interface{}{},
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
		Decision: ProxyDecision{Action: types.ActionQuarantine, Rule: "quarantine_rule"},
	}
	publisher := &MockEventPublisher{}
	qStore := &MockQuarantineStore{ReturnID: "q-123"}
	lStore := &MockLedgerStore{}

	handler, err := NewHandler(logger, "http://localhost:9999", engine, publisher, qStore, lStore)
	require.NoError(t, err)

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "suspicious_tool",
		"params":  map[string]interface{}{},
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
			&MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow}},
			&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
		require.NoError(t, err)
		return h
	}

	cases := []struct {
		name   string
		method string
		body   string
	}{
		{"GET rejected", http.MethodGet, `{"jsonrpc":"2.0","method":"x","params":{}}`},
		{"PUT rejected", http.MethodPut, `{"jsonrpc":"2.0","method":"x","params":{}}`},
		{"non-JSON rejected", http.MethodPost, "this is not json"},
		{"missing jsonrpc rejected", http.MethodPost, `{"method":"x","params":{}}`},
		{"wrong jsonrpc version rejected", http.MethodPost, `{"jsonrpc":"1.0","method":"x","params":{}}`},
		{"batch array rejected", http.MethodPost, `[{"jsonrpc":"2.0","method":"x","params":{}}]`},
		{"client response shape rejected", http.MethodPost, `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{"client error shape rejected", http.MethodPost, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`},
		{"missing params rejected", http.MethodPost, `{"jsonrpc":"2.0","method":"tools/call"}`},
		{"missing method rejected", http.MethodPost, `{"jsonrpc":"2.0","params":{"name":"t"}}`},
		{"non-string method rejected", http.MethodPost, `{"jsonrpc":"2.0","method":123,"params":{}}`},
		{"empty method rejected", http.MethodPost, `{"jsonrpc":"2.0","method":"","params":{}}`},
		{"tools/call without name rejected", http.MethodPost, `{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{}}}`},
		{"non-object params rejected", http.MethodPost, `{"jsonrpc":"2.0","method":"x","params":[1,2]}`},
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
		&MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow}},
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
		&MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}},
		&MockEventPublisher{}, &MockQuarantineStore{},
		&MockLedgerStore{Err: assert.AnError},
	)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "some_tool",
		"params":  map[string]interface{}{},
	})
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

	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}
	handler, err := NewHandler(logger, backend.URL, engine, &MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "some_tool",
		"params":  map[string]interface{}{},
	}
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
		&MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow}},
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{},
		WithTargetAuthToken("svc-credential"),
	)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "some_tool",
		"params":  map[string]interface{}{},
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(agentCtx(req.Context(), "agent_1"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "Bearer svc-credential", upstreamAuth.Load())
}

// --- Phase 3: MCP ingress per the 2026-07-28 profile ---

// jsonRPCError extracts the code/message from a spec-shaped ingress rejection.
func jsonRPCError(t *testing.T, body string) (code float64, message string) {
	t.Helper()
	var resp struct {
		Error struct {
			Code    float64 `json:"code"`
			Message string  `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	return resp.Error.Code, resp.Error.Message
}

// newAllowProxy builds a proxy whose engine always allows, backed by a real
// httptest upstream recording the headers it receives.
type recordedUpstream struct {
	server *httptest.Server
	header atomic.Value // last request's http.Header
	hits   atomic.Int32
}

func newRecordedUpstream(t *testing.T) *recordedUpstream {
	t.Helper()
	u := &recordedUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.header.Store(r.Header.Clone())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok"}`))
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *recordedUpstream) lastHeader(t *testing.T) http.Header {
	t.Helper()
	h, _ := u.header.Load().(http.Header)
	return h
}

func TestServeHTTP_OtherMethod_RawMethodIsProtocolMethod(t *testing.T) {
	logger := zap.NewNop()
	upstream := newRecordedUpstream(t)
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}

	handler, err := NewHandler(logger, upstream.server.URL, engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	// A non-tools/call JSON-RPC method: the method string is both the policy
	// subject AND RawMethod.
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      7,
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": "x://y"},
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(agentCtx(req.Context(), "agent_m"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "resources/read", engine.Input.Tool)
	assert.Equal(t, "resources/read", engine.Input.RawMethod,
		"RawMethod must be the body's protocol method, never the HTTP method")
}

func TestServeHTTP_ContradictoryMcpMethod_RejectedBeforeOPA(t *testing.T) {
	logger := zap.NewNop()
	upstream := newRecordedUpstream(t)
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}
	lStore := &MockLedgerStore{}

	handler, err := NewHandler(logger, upstream.server.URL, engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, lStore)
	require.NoError(t, err)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Mcp-Method", "tools/list") // contradicts the body
	req = req.WithContext(agentCtx(req.Context(), "agent_c"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, msg := jsonRPCError(t, rr.Body.String())
	assert.Equal(t, float64(codeHeaderBodyMismatch), code, "contradiction must map to JSON-RPC -32020")
	assert.Contains(t, msg, "contradicts")
	assert.Zero(t, upstream.hits.Load(), "contradictory request must never reach the upstream")
	assert.Empty(t, engine.Input.Tool, "OPA must never see a header/body-contradictory request")
	assert.Empty(t, engine.Input.RawMethod)
	assert.Empty(t, lStore.Entries, "no ledger row for a pre-OPA rejection")
}

func TestServeHTTP_ContradictoryMcpName_RejectedBeforeOPA(t *testing.T) {
	logger := zap.NewNop()
	upstream := newRecordedUpstream(t)
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}

	handler, err := NewHandler(logger, upstream.server.URL, engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Mcp-Name", "other_tool") // contradicts params.name
	req = req.WithContext(agentCtx(req.Context(), "agent_c"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, _ := jsonRPCError(t, rr.Body.String())
	assert.Equal(t, float64(codeHeaderBodyMismatch), code)
	assert.Zero(t, upstream.hits.Load())
	assert.Empty(t, engine.Input.Tool, "OPA must never see a header/body-contradictory request")
}

func TestServeHTTP_McpNameWithoutToolName_RejectedBeforeOPA(t *testing.T) {
	logger := zap.NewNop()
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}

	handler, err := NewHandler(logger, "http://localhost:9999", engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	// resources/read mirrors params.uri, so a different header is rejected.
	body := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"x://y"}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Mcp-Name", "whatever")
	req = req.WithContext(agentCtx(req.Context(), "agent_c"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, _ := jsonRPCError(t, rr.Body.String())
	assert.Equal(t, float64(codeHeaderBodyMismatch), code)
	assert.Empty(t, engine.Input.Tool)
}

func TestServeHTTP_MatchingMirroredHeaders_AllowedAndForwarded(t *testing.T) {
	logger := zap.NewNop()
	upstream := newRecordedUpstream(t)
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}

	handler, err := NewHandler(logger, upstream.server.URL, engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "safe_tool")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req = req.WithContext(agentCtx(req.Context(), "agent_ok"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "matching mirrored headers must pass: %s", rr.Body.String())
	assert.Equal(t, int32(1), upstream.hits.Load())

	// The intermediary mirrors, never rewrites: headers arrive upstream exactly
	// as sent (protocol version is accepted-and-forwarded, not enforced — see
	// docs/ARCHITECTURE.md).
	h := upstream.lastHeader(t)
	assert.Equal(t, "tools/call", h.Get("Mcp-Method"))
	assert.Equal(t, "safe_tool", h.Get("Mcp-Name"))
	assert.Equal(t, "2026-07-28", h.Get("MCP-Protocol-Version"))
}

func TestServeHTTP_ProtocolVersion_Passthrough(t *testing.T) {
	logger := zap.NewNop()
	upstream := newRecordedUpstream(t)
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}

	handler, err := NewHandler(logger, upstream.server.URL, engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	// Absent Mcp-* headers are tolerated (legacy clients); the protocol version
	// header alone must still ride through to the upstream.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req = req.WithContext(agentCtx(req.Context(), "agent_v"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "2025-06-18", upstream.lastHeader(t).Get("MCP-Protocol-Version"))
}

func TestServeHTTP_BatchRejected(t *testing.T) {
	logger := zap.NewNop()
	upstream := newRecordedUpstream(t)
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}

	handler, err := NewHandler(logger, upstream.server.URL, engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{}}}]`))
	req = req.WithContext(agentCtx(req.Context(), "agent_b"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, _ := jsonRPCError(t, rr.Body.String())
	assert.Equal(t, float64(codeInvalidRequest), code, "batches map to -32600 (invalid request)")
	assert.Zero(t, upstream.hits.Load())
	assert.Empty(t, engine.Input.Tool)
}

func TestValidateIngressRejectsAmbiguousAndLossyShapes(t *testing.T) {
	for name, body := range map[string][]byte{
		"duplicate top-level key": []byte(`{"jsonrpc":"2.0","jsonrpc":"2.0","method":"tools/call","params":{"name":"safe"}}`),
		"duplicate nested key":    []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe","name":"other"}}`),
		"null arguments":          []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe","arguments":null}}`),
		"array arguments":         []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe","arguments":[]}}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validateIngress(body)
			require.Error(t, err)
		})
	}
}

func TestServeHTTP_Base64McpNameAndLargeRequestID(t *testing.T) {
	upstream := newRecordedUpstream(t)
	ledger := &MockLedgerStore{}
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}
	handler, err := NewHandler(zap.NewNop(), upstream.server.URL, engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, ledger)
	require.NoError(t, err)

	// 2^53+1 cannot be represented exactly by float64. The parser must retain
	// it verbatim for the audit ledger and JSON-RPC error correlation.
	body := `{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}`
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "=?base64?c2FmZV90b29s?=")
	request = request.WithContext(agentCtx(request.Context(), "agent-safe"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Len(t, ledger.Entries, 1)
	assert.Equal(t, "9007199254740993", ledger.Entries[0].RequestID)
	assert.Equal(t, "safe_tool", engine.Input.Tool)
}

func TestServeHTTP_DuplicateMcpHeaderRejectedBeforePolicy(t *testing.T) {
	engine := &MockOPAEngine{Decision: ProxyDecision{Action: types.ActionAllow, Rule: "allow_all"}}
	handler, err := NewHandler(zap.NewNop(), "http://localhost:9999", engine,
		&MockEventPublisher{}, &MockQuarantineStore{}, &MockLedgerStore{})
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe","arguments":{}}}`))
	request.Header.Add("Mcp-Method", "tools/call")
	request.Header.Add("Mcp-Method", "tools/call")
	request = request.WithContext(agentCtx(request.Context(), "agent-safe"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Empty(t, engine.Input.Tool)
}
