package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/metrics"
	"github.com/austinchima/kiterail/internal/types"
)

// EvalInput is an alias for types.EvalInput, kept here for backwards compatibility.
type EvalInput = types.EvalInput

// ProxyDecision is an alias for types.ProxyDecision, kept here for backwards compatibility.
type ProxyDecision = types.ProxyDecision

// OPAEngine defines the interface for policy evaluation.
type OPAEngine interface {
	Evaluate(ctx context.Context, input EvalInput) (ProxyDecision, error)
}

// EventPublisher defines the interface for publishing events.
type EventPublisher interface {
	PublishTelemetry(ctx context.Context, event interface{}) error
	PublishAudit(ctx context.Context, event interface{}) error
	PublishQuarantine(ctx context.Context, event interface{}) error
}

// QuarantineStore defines the interface for the quarantine store.
type QuarantineStore interface {
	Create(ctx context.Context, agentID, toolName string, payload []byte) (string, error)
}

// LedgerStore defines the interface for appending ledger audit entries.
type LedgerStore interface {
	Append(ctx context.Context, entry db.LedgerEntry) error
}

// NoOpPublisher is a null object pattern for EventPublisher.
type NoOpPublisher struct{}

func (NoOpPublisher) PublishTelemetry(ctx context.Context, event interface{}) error  { return nil }
func (NoOpPublisher) PublishAudit(ctx context.Context, event interface{}) error      { return nil }
func (NoOpPublisher) PublishQuarantine(ctx context.Context, event interface{}) error { return nil }

// Handler is the reverse proxy HTTP handler.
type Handler struct {
	logger          *zap.Logger
	target          *url.URL
	engine          OPAEngine
	publisher       EventPublisher
	quarantineStore QuarantineStore
	ledgerStore     LedgerStore
	maxBodyBytes    int64

	reverseProxy *httputil.ReverseProxy
}

// NewHandler creates a new proxy handler. targetAuthToken is presented to the
// upstream as a service credential and may be empty for local development.
func NewHandler(logger *zap.Logger, targetURL string, engine OPAEngine, publisher EventPublisher, store QuarantineStore, lStore LedgerStore, opts ...func(*Handler)) (*Handler, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		// The Authorization header carries the agent's KiteRail API key.
		// It authenticates the agent TO THE PROXY and must never reach the
		// downstream target (see docs/API.md, "The Proxy Endpoint").
		req.Header.Del("Authorization")
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream request failed", zap.Error(err), zap.String("agent", auth.AgentFromContext(r.Context())))
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}

	h := &Handler{
		logger:          logger,
		target:          u,
		engine:          engine,
		publisher:       publisher,
		quarantineStore: store,
		ledgerStore:     lStore,
		maxBodyBytes:    1 << 20,

		reverseProxy: rp,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// WithTargetAuthToken configures the service credential sent to the upstream.
func WithTargetAuthToken(token string) func(*Handler) {
	return func(h *Handler) {
		if token == "" {
			return
		}
		origDirector := h.reverseProxy.Director
		h.reverseProxy.Director = func(req *http.Request) {
			origDirector(req)
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
}

// WithMaxBodyBytes overrides the default request body cap.
func WithMaxBodyBytes(n int64) func(*Handler) {
	return func(h *Handler) { h.maxBodyBytes = n }
}

// ingressError writes a JSON-RPC-style rejection for requests that failed
// strict envelope validation. Fail closed: nothing malformed is ever
// forwarded to the target or bypasses policy evaluation.
func ingressError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       "invalid_request",
		"explanation": msg,
	})
}

// validateIngress strictly parses and validates an MCP/JSON-RPC invocation.
// It returns the tool name, arguments, JSON-RPC id, and raw body, or an error
// describing why the request must be rejected.
func validateIngress(body []byte) (tool string, arguments map[string]interface{}, requestID string, err error) {
	var reqBody map[string]interface{}
	if jsonErr := json.Unmarshal(body, &reqBody); jsonErr != nil {
		return "", nil, "", errors.New("body is not valid JSON")
	}

	methodRaw, hasMethod := reqBody["method"]
	paramsRaw, hasParams := reqBody["params"]
	if !hasMethod || !hasParams {
		return "", nil, "", errors.New("missing method or params — only bounded JSON-RPC/MCP invocations are accepted")
	}

	method, ok := methodRaw.(string)
	if !ok || method == "" {
		return "", nil, "", errors.New("method must be a non-empty string")
	}

	if idRaw, ok := reqBody["id"]; ok {
		switch v := idRaw.(type) {
		case string:
			requestID = v
		case float64:
			requestID = jsonNumber(v)
		}
	}

	if paramsMap, ok := paramsRaw.(map[string]interface{}); ok && method == "tools/call" {
		name, _ := paramsMap["name"].(string)
		if name == "" {
			return "", nil, "", errors.New("tools/call requires a non-empty params.name")
		}
		tool = name
		if args, ok := paramsMap["arguments"].(map[string]interface{}); ok {
			arguments = args
		}
	} else if pm, ok := paramsRaw.(map[string]interface{}); ok {
		// Non-MCP JSON-RPC — use the method itself as the policy subject.
		tool = method
		arguments = pm
	} else {
		return "", nil, "", errors.New("params must be a JSON object")
	}
	return tool, arguments, requestID, nil
}

func jsonNumber(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// ServeHTTP handles incoming requests.
//
// Ingress contract (fail closed): only POST requests whose bodies are valid,
// size-capped JSON-RPC/MCP invocations are processed. Anything else — wrong
// method, non-JSON, missing fields, unknown shapes — is rejected here and
// NEVER forwarded to the target, so no traffic can bypass OPA evaluation.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ingressError(w, http.StatusMethodNotAllowed, "only POST is accepted at the proxy endpoint")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			ingressError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
			return
		}
		ingressError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	tool, arguments, requestID, verr := validateIngress(body)
	if verr != nil {
		h.logger.Warn("rejected malformed ingress",
			zap.Error(verr),
			zap.String("agent", auth.AgentFromContext(r.Context())),
			zap.String("remote", r.RemoteAddr),
		)
		metrics.DecisionsTotal.WithLabelValues("reject").Inc()
		ingressError(w, http.StatusBadRequest, verr.Error())
		return
	}

	input := EvalInput{
		Tool:      tool,
		Arguments: arguments,
		Agent:     auth.AgentFromContext(r.Context()),
		Timestamp: time.Now(),
		RawMethod: r.Method,
	}

	start := time.Now()
	decision, evalErr := h.engine.Evaluate(r.Context(), input)
	latency := time.Since(start).Seconds() * 1000

	if evalErr != nil {
		h.logger.Error("Policy evaluation failed", zap.Error(evalErr))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	decision.LatencyMs = latency
	h.logger.Info("Proxy decision", zap.Any("decision", decision))
	metrics.DecisionsTotal.WithLabelValues(decision.Action).Inc()

	hashSum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hashSum[:])
	if err := h.publisher.PublishTelemetry(r.Context(), map[string]interface{}{
		"source":    input.Agent,
		"target":    input.Tool,
		"status":    decision.Action,
		"timestamp": time.Now(),
	}); err != nil {
		h.logger.Error("Failed to publish telemetry event", zap.Error(err))
	}

	// Audit guarantee: every evaluated decision is appended to the tamper-
	// evident ledger BEFORE execution, and a ledger failure fails closed.
	entry := db.LedgerEntry{
		Timestamp:   time.Now(),
		Agent:       input.Agent,
		Tool:        input.Tool,
		Decision:    decision.Action,
		PolicyRule:  decision.Rule,
		PayloadHash: payloadHash,
		RequestID:   requestID,
	}
	if h.ledgerStore != nil {
		if err := h.ledgerStore.Append(r.Context(), entry); err != nil {
			h.logger.Error("Ledger append failed — failing closed", zap.Error(err))
			http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
			return
		}
	}

	switch decision.Action {
	case "allow":
		if err := h.publisher.PublishAudit(r.Context(), map[string]interface{}{
			"action":    "allow",
			"agent":     input.Agent,
			"tool":      input.Tool,
			"rule":      decision.Rule,
			"timestamp": time.Now(),
		}); err != nil {
			h.logger.Error("Failed to publish audit event", zap.Error(err))
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		h.reverseProxy.ServeHTTP(w, r)
	case "deny":
		if err := h.publisher.PublishAudit(r.Context(), map[string]interface{}{
			"action":      "deny",
			"agent":       input.Agent,
			"tool":        input.Tool,
			"rule":        decision.Rule,
			"explanation": decision.Explanation,
			"timestamp":   time.Now(),
		}); err != nil {
			h.logger.Error("Failed to publish audit event", zap.Error(err))
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Denied by policy", "explanation": decision.Explanation})
	case "quarantine":
		id, err := h.quarantineStore.Create(r.Context(), input.Agent, input.Tool, body)
		if err != nil {
			h.logger.Error("Failed to store quarantine", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err := h.publisher.PublishQuarantine(r.Context(), map[string]any{
			"quarantine_id": id,
			"agent":         input.Agent,
			"tool":          input.Tool,
			"rule":          decision.Rule,
			"request_id":    requestID,
			"timestamp":     time.Now(),
		}); err != nil {
			h.logger.Error("Failed to publish quarantine event", zap.Error(err))
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"quarantine_id": id, "status": "quarantined"})
	default:
		h.logger.Error("Unknown action", zap.String("action", decision.Action))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// AgentFromContext extracts the agent ID from the request context.
// Retained for backwards compatibility with existing call sites.
func AgentFromContext(ctx context.Context) string {
	return auth.AgentFromContext(ctx)
}
