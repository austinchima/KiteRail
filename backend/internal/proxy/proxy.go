package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// EvalInput represents the payload evaluated by the OPA engine.
type EvalInput struct {
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
	Agent     string          `json:"agent"`
	Timestamp time.Time       `json:"timestamp"`
}

// ProxyDecision represents the result of the policy evaluation.
type ProxyDecision struct {
	Action      string  `json:"action"` // allow, deny, quarantine
	Rule        string  `json:"rule"`
	LatencyMs   float64 `json:"latency_ms"`
	Explanation string  `json:"explanation"`
}

// OPAEngine defines the interface for policy evaluation.
type OPAEngine interface {
	Evaluate(ctx context.Context, input EvalInput) (ProxyDecision, error)
}

// EventPublisher defines the interface for publishing events.
type EventPublisher interface {
	PublishTelemetry(ctx context.Context, event interface{}) error
}

// QuarantineStore defines the interface for the quarantine store.
type QuarantineStore interface {
	Create(ctx context.Context, payload []byte) (string, error)
}

// Handler is the reverse proxy HTTP handler.
type Handler struct {
	logger          *zap.Logger
	target          *url.URL
	engine          OPAEngine
	publisher       EventPublisher
	quarantineStore QuarantineStore
	reverseProxy    *httputil.ReverseProxy
}

// New creates a new proxy handler.
func New(logger *zap.Logger, targetURL string, engine OPAEngine, publisher EventPublisher, store QuarantineStore) (*Handler, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	
	rp := httputil.NewSingleHostReverseProxy(u)

	return &Handler{
		logger:          logger,
		target:          u,
		engine:          engine,
		publisher:       publisher,
		quarantineStore: store,
		reverseProxy:    rp,
	}, nil
}

// ServeHTTP handles incoming requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	var reqBody map[string]interface{}
	if err := json.Unmarshal(body, &reqBody); err != nil {
		// Not JSON, just forward
		h.reverseProxy.ServeHTTP(w, r)
		return
	}

	methodRaw, hasMethod := reqBody["method"]
	paramsRaw, hasParams := reqBody["params"]
	
	if !hasMethod || !hasParams {
		// Not JSON-RPC MCP call
		h.reverseProxy.ServeHTTP(w, r)
		return
	}

	method, ok := methodRaw.(string)
	if !ok {
		h.reverseProxy.ServeHTTP(w, r)
		return
	}
	
	paramsBytes, _ := json.Marshal(paramsRaw)

	input := EvalInput{
		Method:    method,
		Params:    paramsBytes,
		Agent:     "unknown", // Could extract from headers
		Timestamp: time.Now(),
	}

	start := time.Now()
	decision, err := h.engine.Evaluate(r.Context(), input)
	latency := time.Since(start).Seconds() * 1000
	
	if err != nil {
		h.logger.Error("Policy evaluation failed", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	decision.LatencyMs = latency
	h.logger.Info("Proxy decision", zap.Any("decision", decision))

	switch decision.Action {
	case "allow":
		h.reverseProxy.ServeHTTP(w, r)
	case "deny":
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Denied by policy", "explanation": decision.Explanation})
	case "quarantine":
		id, err := h.quarantineStore.Create(r.Context(), body)
		if err != nil {
			h.logger.Error("Failed to store quarantine", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"quarantine_id": id, "status": "quarantined"})
	default:
		h.logger.Error("Unknown action", zap.String("action", decision.Action))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
