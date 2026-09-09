// Package types holds shared domain types used by both the proxy and the
// policy-evaluation engine. Keeping them here breaks the import cycle that
// would otherwise exist between internal/proxy and internal/opaengine.
package types

import "time"

// EvalInput is the payload passed to the OPA engine for every request.
type EvalInput struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Agent     string         `json:"agent"`
	Timestamp time.Time      `json:"timestamp"`
	// RawMethod is the JSON-RPC protocol method from the validated request
	// body ("tools/call", or the actual method for other calls) — never the
	// HTTP method, which is transport metadata. This is the one documented
	// meaning; the simulator passes it through verbatim so simulated and
	// enforced evaluations see semantically identical input.
	RawMethod string `json:"raw_method"`
}

// Action is the enforcement decision produced by the policy engine. Typed so
// the compiler — not convention — separates the three outcomes. Anything
// outside this set is invalid and fails closed at the trust boundary (see
// opaengine.Evaluate); the proxy switch treats it as unreachable.
type Action string

const (
	ActionAllow      Action = "allow"
	ActionDeny       Action = "deny"
	ActionQuarantine Action = "quarantine"
)

// Valid reports whether a is one of the three enforcement actions.
func (a Action) Valid() bool {
	switch a {
	case ActionAllow, ActionDeny, ActionQuarantine:
		return true
	default:
		return false
	}
}

// ProxyDecision is the result returned by the OPA engine after evaluating a
// request against the loaded policies.
type ProxyDecision struct {
	Action      Action  `json:"action"` // allow | deny | quarantine
	Rule        string  `json:"rule"`
	LatencyMs   float64 `json:"latency_ms"`
	Explanation string  `json:"explanation"`
}
