package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/austinchima/kiterail/internal/ledger"
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
	TelemetryEvents []interface{}
	AuditEvents     []interface{}
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
	Entries []ledger.LedgerEntry
	Err     error
}

func (m *MockLedgerStore) Append(ctx context.Context, entry ledger.LedgerEntry) error {
	m.Entries = append(m.Entries, entry)
	return m.Err
}

// Tests

func TestServeHTTP_Allow(t *testing.T) {
	logger := zap.NewNop()
	
	// Set up backend target
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
	req = req.WithContext(context.WithValue(req.Context(), agentContextKey, "agent_1"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Asserts
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
	req = req.WithContext(context.WithValue(req.Context(), agentContextKey, "agent_2"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Asserts
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
	req = req.WithContext(context.WithValue(req.Context(), agentContextKey, "agent_3"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Asserts
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

func TestAuthMiddleware(t *testing.T) {
	logger := zap.NewNop()
	apiKeys := map[string]string{
		"valid-key": "agent-alpha",
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := AgentFromContext(r.Context())
		w.Write([]byte(agent))
	})

	middleware := AuthMiddleware(apiKeys, logger, nextHandler)

	tests := []struct {
		name       string
		setupReq   func() *http.Request
		expectCode int
		expectBody string
	}{
		{
			name: "No Auth",
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
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
			name: "Valid Auth Header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer valid-key")
				return req
			},
			expectCode: http.StatusOK,
			expectBody: "agent-alpha",
		},
		{
			name: "Valid Token Query Param",
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?token=valid-key", nil)
			},
			expectCode: http.StatusOK,
			expectBody: "agent-alpha",
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
