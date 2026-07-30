package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/ledger"
)

// EvalInput represents the payload evaluated by the OPA engine.
type EvalInput struct {
	Tool       string                 `json:"tool"`
	Arguments  map[string]interface{} `json:"arguments"`
	Agent      string                 `json:"agent"`
	Timestamp  time.Time              `json:"timestamp"`
	RawMethod  string                 `json:"raw_method"`
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
	PublishAudit(ctx context.Context, event interface{}) error
	PublishQuarantine(ctx context.Context, event interface{}) error
}

// QuarantineStore defines the interface for the quarantine store.
type QuarantineStore interface {
	Create(ctx context.Context, agentID, toolName string, payload []byte) (string, error)
}

// LedgerStore defines the interface for appending ledger audit entries.
type LedgerStore interface {
	Append(ctx context.Context, entry ledger.LedgerEntry) error
}

// Handler is the reverse proxy HTTP handler.
type Handler struct {
	logger          *zap.Logger
	target          *url.URL
	engine          OPAEngine
	publisher       EventPublisher
	quarantineStore QuarantineStore
	ledgerStore     LedgerStore
	reverseProxy    *httputil.ReverseProxy
}

// NewHandler creates a new proxy handler.
func NewHandler(logger *zap.Logger, targetURL string, engine OPAEngine, publisher EventPublisher, store QuarantineStore, lStore LedgerStore) (*Handler, error) {
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
		ledgerStore:     lStore,
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
	
	var tool string
	var arguments map[string]interface{}

	if method == "tools/call" {
		// MCP tool invocation — extract params.name and params.arguments
		paramsMap, ok := paramsRaw.(map[string]interface{})
		if !ok {
			h.reverseProxy.ServeHTTP(w, r)
			return
		}
		tool, _ = paramsMap["name"].(string)
		if args, ok := paramsMap["arguments"].(map[string]interface{}); ok {
			arguments = args
		}
	} else {
		// Non-MCP JSON-RPC — use method directly as tool name
		tool = method
		if pm, ok := paramsRaw.(map[string]interface{}); ok {
			arguments = pm
		}
	}

	if tool == "" {
		h.reverseProxy.ServeHTTP(w, r)
		return
	}

	input := EvalInput{
		Tool:      tool,
		Arguments: arguments,
		Agent:     AgentFromContext(r.Context()),
		Timestamp: time.Now(),
		RawMethod: method,
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

	hashSum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hashSum[:])

	if h.ledgerStore != nil {
		entry := ledger.LedgerEntry{
			Timestamp:   time.Now(),
			Agent:       input.Agent,
			Tool:        input.Tool,
			Decision:    decision.Action,
			PolicyRule:  decision.Rule,
			PayloadHash: payloadHash,
		}
		if err := h.ledgerStore.Append(r.Context(), entry); err != nil {
			h.logger.Error("Failed to write to ledger", zap.Error(err))
		}
	}

	switch decision.Action {
	case "allow":
		if h.publisher != nil {
			if err := h.publisher.PublishAudit(r.Context(), map[string]interface{}{
				"action":    "allow",
				"agent":     input.Agent,
				"tool":      input.Tool,
				"rule":      decision.Rule,
				"timestamp": time.Now(),
			}); err != nil {
				h.logger.Error("Failed to publish audit event", zap.Error(err))
			}
		}
		h.reverseProxy.ServeHTTP(w, r)
	case "deny":
		if h.publisher != nil {
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
		if h.publisher != nil {
			if err := h.publisher.PublishQuarantine(r.Context(), map[string]interface{}{
				"quarantine_id": id,
				"agent":         input.Agent,
				"tool":          input.Tool,
				"rule":          decision.Rule,
				"timestamp":     time.Now(),
			}); err != nil {
				h.logger.Error("Failed to publish quarantine event", zap.Error(err))
			}
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"quarantine_id": id, "status": "quarantined"})
	default:
		h.logger.Error("Unknown action", zap.String("action", decision.Action))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// AuthMiddleware validates bearer tokens on incoming requests.
func AuthMiddleware(apiKeys map[string]string, logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoint is public
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error": "missing Authorization header"}`, http.StatusUnauthorized)
			return
		}

		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			http.Error(w, `{"error": "invalid Authorization format, expected Bearer token"}`, http.StatusUnauthorized)
			return
		}

		token := auth[len(prefix):]
		agentID, ok := apiKeys[token]
		if !ok {
			logger.Warn("rejected unauthorized request", zap.String("token_prefix", token[:min(8, len(token))]))
			http.Error(w, `{"error": "invalid API key"}`, http.StatusForbidden)
			return
		}

		// Inject agent identity into request context
		ctx := context.WithValue(r.Context(), agentContextKey, agentID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string
const agentContextKey contextKey = "agent_id"

// AgentFromContext extracts the agent ID from the request context.
func AgentFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(agentContextKey).(string); ok {
		return v
	}
	return "unknown"
}
