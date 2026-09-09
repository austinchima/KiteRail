package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/mcp"
	"github.com/austinchima/kiterail/internal/metrics"
	"github.com/austinchima/kiterail/internal/types"
)

// JSON-RPC error codes emitted by the proxy's own ingress validation.
// Standard codes come from the JSON-RPC 2.0 spec; -32020 is reserved by the
// 2026-07-28 MCP spec for header/body disagreement (see docs/API.md).
const (
	codeInvalidRequest     = -32600 // envelope is not a single valid JSON-RPC request
	codeHeaderBodyMismatch = -32020 // mirrored MCP headers contradict the body
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
	Create(ctx context.Context, agentID, toolName string, payload []byte, headers http.Header) (string, error)
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
	targetAuthToken string
	engine          OPAEngine
	publisher       EventPublisher
	quarantineStore QuarantineStore
	ledgerStore     LedgerStore
	maxBodyBytes    int64

	reverseProxy *httputil.ReverseProxy
}

// NewHandler creates a new proxy handler. An optional upstream service token
// can be supplied with WithTargetAuthToken after construction.
func NewHandler(logger *zap.Logger, targetURL string, engine OPAEngine, publisher EventPublisher, store QuarantineStore, lStore LedgerStore, opts ...func(*Handler)) (*Handler, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		logger:          logger,
		target:          u,
		engine:          engine,
		publisher:       publisher,
		quarantineStore: store,
		ledgerStore:     lStore,
		maxBodyBytes:    1 << 20,
	}

	// Rewrite is the Go 1.26-supported reverse-proxy hook. It performs the
	// same path/query target rewrite as NewSingleHostReverseProxy while making
	// the credential boundary explicit: the agent's token is removed, then the
	// optional server-owned upstream token is added.
	rp := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(u)
			request.Out.Header.Del("Authorization")
			if h.targetAuthToken != "" {
				request.Out.Header.Set("Authorization", "Bearer "+h.targetAuthToken)
			}
		},
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream request failed", zap.Error(err), zap.String("agent", auth.AgentFromContext(r.Context())))
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	h.reverseProxy = rp

	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// WithTargetAuthToken configures the service credential sent to the upstream.
func WithTargetAuthToken(token string) func(*Handler) {
	return func(h *Handler) {
		h.targetAuthToken = token
	}
}

// WithMaxBodyBytes overrides the default request body cap.
func WithMaxBodyBytes(n int64) func(*Handler) {
	return func(h *Handler) { h.maxBodyBytes = n }
}

// ingressError returns a JSON-RPC rejection. A validated string or json.Number
// ID lets the client correlate the failure without losing numeric precision;
// malformed envelopes whose ID cannot be trusted use nil.
func ingressError(writer http.ResponseWriter, status, code int, message string, requestID any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	json.NewEncoder(writer).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// ingressRequest is the validated shape of a single JSON-RPC/MCP invocation.
type ingressRequest struct {
	method     string // the JSON-RPC protocol method (never the HTTP method)
	paramsName string // mirrored params.name or params.uri, depending on method
	tool       string // policy subject: params.name for tools/call, else method
	arguments  map[string]interface{}
	requestID  string // original ID text used by the ledger
	responseID any    // original string or json.Number used in JSON-RPC errors
}

// validateIngress strictly parses and validates an MCP/JSON-RPC invocation per
// the 2026-07-28 stateless profile: the body must be a SINGLE JSON-RPC 2.0
// request — no batches (batching is not in MCP) and no client-sent responses.
// It returns the validated request, or an error describing why the request
// must be rejected.
func validateIngress(body []byte) (ingressRequest, error) {
	requestBody, err := mcp.DecodeObject(body)
	if err != nil {
		return ingressRequest{}, err
	}
	request := ingressRequest{}
	if identifier, present := requestBody["id"]; present {
		switch identifier := identifier.(type) {
		case string:
			request.requestID = identifier
		case json.Number:
			request.requestID = identifier.String()
		default:
			return request, errors.New("id must be a string or number when present")
		}
		request.responseID = identifier
	}

	// A client-sent response ("result"/"error" without "method") is not a
	// request; an intermediary must never treat it as one.
	if _, hasResult := requestBody["result"]; hasResult {
		return request, errors.New("client-sent responses are not accepted")
	}
	if _, hasError := requestBody["error"]; hasError {
		return request, errors.New("client-sent error objects are not accepted")
	}

	if version, ok := requestBody["jsonrpc"].(string); !ok || version != "2.0" {
		return request, errors.New(`jsonrpc must be "2.0"`)
	}

	methodRaw, hasMethod := requestBody["method"]
	paramsRaw, hasParams := requestBody["params"]
	if !hasMethod || !hasParams {
		return request, errors.New("missing method or params — only bounded JSON-RPC/MCP invocations are accepted")
	}

	method, ok := methodRaw.(string)
	if !ok || method == "" {
		return request, errors.New("method must be a non-empty string")
	}

	parameters, ok := paramsRaw.(map[string]any)
	if !ok {
		return request, errors.New("params must be a JSON object")
	}
	request.method = method
	request.tool = method
	request.arguments = parameters
	nameField := ""
	switch method {
	case "tools/call", "prompts/get":
		nameField = "name"
	case "resources/read":
		nameField = "uri"
	}
	if nameField != "" {
		name, _ := parameters[nameField].(string)
		if name == "" {
			return request, fmt.Errorf("%s requires a non-empty params.%s", method, nameField)
		}
		request.paramsName = name
	}
	if method == "tools/call" {
		request.tool = request.paramsName
		request.arguments = nil
		if arguments, present := parameters["arguments"]; present {
			request.arguments, ok = arguments.(map[string]any)
			if !ok {
				return request, errors.New("tools/call params.arguments must be a JSON object when present")
			}
		}
	}
	return request, nil
}

// validateMirroredHeaders compares routing metadata against the body before
// policy evaluation. Legacy clients may omit headers, but a present header must
// be unambiguous. Values remain unchanged for forwarding and approved replay.
func validateMirroredHeaders(request *http.Request, ingress ingressRequest) error {
	method, present, err := singleHeader(request.Header, "Mcp-Method")
	if err != nil {
		return err
	}
	if present && method != ingress.method {
		return fmt.Errorf("Mcp-Method header %q contradicts body method %q", method, ingress.method)
	}
	name, present, err := singleHeader(request.Header, "Mcp-Name")
	if err != nil {
		return err
	}
	if present {
		decodedName, err := decodeHeaderName(name)
		if err != nil {
			return err
		}
		if ingress.paramsName == "" || decodedName != ingress.paramsName {
			return fmt.Errorf("Mcp-Name header %q contradicts the body's name or URI %q", name, ingress.paramsName)
		}
	}
	version, _, err := singleHeader(request.Header, "MCP-Protocol-Version")
	if err != nil {
		return err
	}
	if strings.Contains(version, ",") {
		return errors.New("MCP-Protocol-Version must contain one version")
	}
	return nil
}

// singleHeader distinguishes an omitted header from an empty or repeated one.
// Case-insensitive iteration also covers headers assembled directly in tests or
// middleware instead of through net/http's canonicalizing Header.Add method.
func singleHeader(header http.Header, expectedName string) (string, bool, error) {
	var values []string
	present := false
	for name, entries := range header {
		if strings.EqualFold(name, expectedName) {
			present = true
			values = append(values, entries...)
		}
	}
	if !present {
		return "", false, nil
	}
	if len(values) != 1 || values[0] == "" {
		return "", true, fmt.Errorf("%s must have exactly one non-empty value", expectedName)
	}
	value := values[0]
	if strings.Trim(value, " \t") != value {
		return "", true, fmt.Errorf("%s must not have leading or trailing whitespace", expectedName)
	}
	for _, character := range value {
		if (character < 0x20 && character != '\t') || character > 0x7e {
			return "", true, fmt.Errorf("%s contains invalid header characters", expectedName)
		}
	}
	return value, true, nil
}

// decodeHeaderName implements MCP's case-sensitive Base64 sentinel. Comparing
// decoded UTF-8 text permits Unicode names and URIs without changing wire bytes.
func decodeHeaderName(value string) (string, error) {
	const prefix = "=?base64?"
	const suffix = "?="
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return value, nil
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || !utf8.Valid(decoded) || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return "", errors.New("Mcp-Name contains invalid Base64-encoded UTF-8")
	}
	return string(decoded), nil
}

// ServeHTTP handles incoming requests.
//
// Ingress contract (fail closed): only POST requests whose bodies are valid,
// size-capped JSON-RPC/MCP invocations are processed. Anything else — wrong
// method, non-JSON, missing fields, unknown shapes — is rejected here and
// NEVER forwarded to the target, so no traffic can bypass OPA evaluation.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ingressError(w, http.StatusMethodNotAllowed, codeInvalidRequest, "only POST is accepted at the proxy endpoint", nil)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			ingressError(w, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body exceeds limit", nil)
			return
		}
		ingressError(w, http.StatusBadRequest, codeInvalidRequest, "failed to read request body", nil)
		return
	}

	ing, verr := validateIngress(body)
	if verr != nil {
		h.logger.Warn("rejected malformed ingress",
			zap.Error(verr),
			zap.String("agent", auth.AgentFromContext(r.Context())),
			zap.String("remote", r.RemoteAddr),
		)
		metrics.DecisionsTotal.WithLabelValues("reject").Inc()
		ingressError(w, http.StatusBadRequest, codeInvalidRequest, verr.Error(), ing.responseID)
		return
	}

	if herr := validateMirroredHeaders(r, ing); herr != nil {
		h.logger.Warn("rejected contradictory MCP metadata",
			zap.Error(herr),
			zap.String("agent", auth.AgentFromContext(r.Context())),
			zap.String("remote", r.RemoteAddr),
		)
		metrics.DecisionsTotal.WithLabelValues("reject").Inc()
		// -32020 BEFORE OPA evaluation: policy input must never be
		// attacker-spoofable via headers.
		ingressError(w, http.StatusBadRequest, codeHeaderBodyMismatch, herr.Error(), ing.responseID)
		return
	}

	input := EvalInput{
		Tool:      ing.tool,
		Arguments: ing.arguments,
		Agent:     auth.AgentFromContext(r.Context()),
		Timestamp: time.Now(),
		// RawMethod is the JSON-RPC protocol method from the validated body
		// ("tools/call", or the actual method for other calls) — never the
		// HTTP method, which is transport metadata, not policy input.
		RawMethod: ing.method,
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
	metrics.DecisionsTotal.WithLabelValues(string(decision.Action)).Inc()

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
		Decision:    string(decision.Action),
		PolicyRule:  decision.Rule,
		PayloadHash: payloadHash,
		RequestID:   ing.requestID,
	}
	if h.ledgerStore != nil {
		if err := h.ledgerStore.Append(r.Context(), entry); err != nil {
			h.logger.Error("Ledger append failed — failing closed", zap.Error(err))
			http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
			return
		}
	}

	switch decision.Action {
	// The engine validates actions before they reach here, so the default
	// case is unreachable defense-in-depth, not error handling.
	case types.ActionAllow:
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
	case types.ActionDeny:
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
	case types.ActionQuarantine:
		id, err := h.quarantineStore.Create(r.Context(), input.Agent, input.Tool, body, mcp.CaptureReplayHeaders(r.Header))
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
			"request_id":    ing.requestID,
			"timestamp":     time.Now(),
		}); err != nil {
			h.logger.Error("Failed to publish quarantine event", zap.Error(err))
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"quarantine_id": id, "status": "quarantined"})
	default:
		h.logger.Error("Unknown action", zap.String("action", string(decision.Action)))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// AgentFromContext extracts the agent ID from the request context.
// Retained for backwards compatibility with existing call sites.
func AgentFromContext(ctx context.Context) string {
	return auth.AgentFromContext(ctx)
}
