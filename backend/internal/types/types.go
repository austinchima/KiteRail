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
	RawMethod string         `json:"raw_method"`
}

// ProxyDecision is the result returned by the OPA engine after evaluating a
// request against the loaded policies.
type ProxyDecision struct {
	Action      string  `json:"action"` // allow | deny | quarantine
	Rule        string  `json:"rule"`
	LatencyMs   float64 `json:"latency_ms"`
	Explanation string  `json:"explanation"`
}
