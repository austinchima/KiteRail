package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/austinchima/elodea/internal/auth"
	"github.com/austinchima/elodea/internal/types"
)

// Invocation is one agent action normalized out of its wire protocol. Policy,
// the ledger, quarantine, and replay only ever see this shape, so supporting a
// new agent protocol (A2A, a function-calling gateway, the next MCP revision)
// means writing an Adapter, not changing the enforcement core.
type Invocation struct {
	Protocol        string
	ProtocolVersion string
	Method          string         // protocol operation, e.g. "tools/call"
	Name            string         // mirrored name or URI, when the operation has one
	Tool            string         // policy subject
	Arguments       map[string]any // policy-visible arguments
	RequestID       string         // correlation id recorded in the ledger
	ResponseID      any            // id echoed back in protocol-native responses
}

// IngressError is a fail-closed rejection raised before policy evaluation.
type IngressError struct {
	Status     int
	Code       int
	Message    string
	ResponseID any
}

func (e *IngressError) Error() string { return e.Message }

// Adapter translates one agent protocol to and from Elodea's normalized
// Invocation. Parse must be strict: anything ambiguous is rejected, because a
// request the adapter cannot fully describe to policy must never be forwarded.
// One adapter serves one ingress route, so there is no protocol sniffing an
// attacker could steer.
type Adapter interface {
	Name() string
	Parse(r *http.Request, body []byte) (Invocation, *IngressError)
	WriteIngressError(w http.ResponseWriter, r *http.Request, err *IngressError)
	WriteDeny(w http.ResponseWriter, r *http.Request, inv Invocation, decision types.ProxyDecision)
	WriteQuarantine(w http.ResponseWriter, r *http.Request, inv Invocation, quarantineID string, decision types.ProxyDecision)
}

// WithAdapter replaces the default MCP adapter.
func WithAdapter(adapter Adapter) func(*Handler) {
	return func(h *Handler) { h.adapter = adapter }
}

// JSON-RPC server-error codes Elodea uses for enforcement outcomes.
const (
	codeDeniedByPolicy  = -32010
	codeQuarantined     = -32011
	mcpProtocolVersion  = "MCP-Protocol-Version"
	decisionMetaKey     = "elodea/decision"
	quarantineIDHeader  = "X-Elodea-Quarantine-ID"
	decisionHeader      = "X-Elodea-Decision"
	policyVersionHeader = "X-Elodea-Policy-Version"
)

// MCPAdapter handles MCP (JSON-RPC 2.0, stateless streamable-HTTP profile).
//
// Clients that declare MCP-Protocol-Version get protocol-native outcomes: a
// denied or quarantined tools/call returns a normal tool result with isError
// set, so the model reads why the action did not run and can adapt instead of
// failing on a transport error. Clients without the header keep the original
// REST-style responses (403 / 202) for backwards compatibility.
type MCPAdapter struct{}

func (MCPAdapter) Name() string { return "mcp" }

func (MCPAdapter) Parse(r *http.Request, body []byte) (Invocation, *IngressError) {
	ing, err := validateIngress(body)
	if err != nil {
		return Invocation{}, &IngressError{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: err.Error(), ResponseID: ing.responseID}
	}
	if err := validateMirroredHeaders(r, ing); err != nil {
		// -32020 before policy evaluation: policy input must never be
		// attacker-spoofable via headers.
		return Invocation{}, &IngressError{Status: http.StatusBadRequest, Code: codeHeaderBodyMismatch, Message: err.Error(), ResponseID: ing.responseID}
	}
	version, _, _ := singleHeader(r.Header, mcpProtocolVersion) // validated above
	return Invocation{
		Protocol:        "mcp",
		ProtocolVersion: version,
		Method:          ing.method,
		Name:            ing.paramsName,
		Tool:            ing.tool,
		Arguments:       ing.arguments,
		RequestID:       ing.requestID,
		ResponseID:      ing.responseID,
	}, nil
}

func (MCPAdapter) WriteIngressError(w http.ResponseWriter, _ *http.Request, err *IngressError) {
	ingressError(w, err.Status, err.Code, err.Message, err.ResponseID)
}

// sentence trims trailing punctuation so policy explanations written as full
// sentences read cleanly inside the surrounding message.
func sentence(explanation string) string {
	return strings.TrimRight(strings.TrimSpace(explanation), ".")
}

func nativeMCP(r *http.Request) bool { return r.Header.Get(mcpProtocolVersion) != "" }

func decisionMeta(outcome string, decision types.ProxyDecision, quarantineID string) map[string]any {
	meta := map[string]any{
		"decision":       outcome,
		"rule":           decision.Rule,
		"explanation":    decision.Explanation,
		"policy_version": decision.PolicyVersion,
	}
	if quarantineID != "" {
		meta["quarantine_id"] = quarantineID
	}
	return meta
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// writeOutcome renders a non-executed outcome. tools/call gets an isError tool
// result the model can read; other methods get a JSON-RPC error object.
func writeOutcome(w http.ResponseWriter, inv Invocation, code int, message, text string, meta map[string]any) {
	if inv.Method == "tools/call" {
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      inv.ResponseID,
			"result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": text}},
				"isError": true,
				"_meta":   map[string]any{decisionMetaKey: meta},
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      inv.ResponseID,
		"error":   map[string]any{"code": code, "message": message, "data": meta},
	})
}

func setDecisionHeaders(w http.ResponseWriter, outcome string, decision types.ProxyDecision) {
	w.Header().Set(decisionHeader, outcome)
	if decision.PolicyVersion != "" {
		w.Header().Set(policyVersionHeader, decision.PolicyVersion)
	}
}

func (MCPAdapter) WriteDeny(w http.ResponseWriter, r *http.Request, inv Invocation, decision types.ProxyDecision) {
	setDecisionHeaders(w, "deny", decision)
	if nativeMCP(r) {
		text := fmt.Sprintf("Blocked by Elodea policy %q: %s. The action was not executed.", decision.Rule, sentence(decision.Explanation))
		writeOutcome(w, inv, codeDeniedByPolicy, "Denied by policy", text, decisionMeta("deny", decision, ""))
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "Denied by policy", "explanation": decision.Explanation})
}

func (MCPAdapter) WriteQuarantine(w http.ResponseWriter, r *http.Request, inv Invocation, quarantineID string, decision types.ProxyDecision) {
	setDecisionHeaders(w, "quarantine", decision)
	w.Header().Set(quarantineIDHeader, quarantineID)
	if nativeMCP(r) {
		text := fmt.Sprintf("This action requires human approval (Elodea policy %q: %s). It has NOT been executed yet; "+
			"a reviewer will approve or deny it. Quarantine ID: %s. Do not retry the call.",
			decision.Rule, sentence(decision.Explanation), quarantineID)
		writeOutcome(w, inv, codeQuarantined, "Pending human approval", text, decisionMeta("quarantine", decision, quarantineID))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"quarantine_id": quarantineID, "status": "quarantined"})
}

// NewPolicyRecheck returns a function that re-derives the policy decision for
// a stored request exactly as ingress would: same adapter, same engine, same
// normalized input. The quarantine worker calls it before replaying.
func NewPolicyRecheck(adapter Adapter, engine OPAEngine) func(ctx context.Context, agentID string, payload []byte, headers http.Header) (types.ProxyDecision, error) {
	return func(ctx context.Context, agentID string, payload []byte, headers http.Header) (types.ProxyDecision, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(payload))
		if err != nil {
			return types.ProxyDecision{}, err
		}
		req.Header = headers.Clone()
		inv, ierr := adapter.Parse(req, payload)
		if ierr != nil {
			return types.ProxyDecision{}, fmt.Errorf("stored request no longer parses: %s", ierr.Message)
		}
		return engine.Evaluate(auth.WithIdentity(ctx, auth.Identity{ID: agentID, Role: auth.RoleAgent}), types.EvalInput{
			Protocol:        inv.Protocol,
			ProtocolVersion: inv.ProtocolVersion,
			Tool:            inv.Tool,
			Arguments:       inv.Arguments,
			Agent:           agentID,
			Timestamp:       time.Now(),
			RawMethod:       inv.Method,
		})
	}
}
