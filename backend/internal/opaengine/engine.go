// Package opaengine compiles Git-managed Rego policies and validates every
// decision before it crosses the enforcement boundary into the proxy.
package opaengine

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/types"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine represents the OPA policy evaluation engine.
type Engine struct {
	policyDir string
	query     rego.PreparedEvalQuery
	ready     bool
	logger    *zap.Logger
	mu        sync.RWMutex
}

// New creates a new Engine and loads policies from the specified directory.
func New(ctx context.Context, policyDir string, logger *zap.Logger) (*Engine, error) {
	e := &Engine{policyDir: policyDir, logger: logger}
	if err := e.Reload(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload compiles the policy directory and atomically publishes the result.
// Compilation runs outside the lock so requests can use the previous query.
// A failed reload preserves both that query and its readiness state.
func (e *Engine) Reload(ctx context.Context) error {
	var query rego.PreparedEvalQuery
	var err error

	if _, statErr := os.Stat(e.policyDir); os.IsNotExist(statErr) {
		// Directory doesn't exist yet — prepare an empty engine rather than
		// failing startup. Every evaluation will fall through to the
		// fail-closed default in Evaluate.
		query, err = rego.New(
			rego.Query("data.kiterail.authz.decision"),
			rego.StrictBuiltinErrors(true),
		).PrepareForEval(ctx)
	} else {
		query, err = rego.New(
			rego.Query("data.kiterail.authz.decision"),
			rego.Load([]string{loaderPath(e.policyDir)}, nil),
			// A policy that hits a builtin error at runtime (bad JSON, division
			// by zero, ...) is BROKEN, not "no match". Without strict errors the
			// failure would be silently swallowed into the fallback deny, masking
			// the bug. Strict keeps it distinguishable as policy_eval_error.
			rego.StrictBuiltinErrors(true),
		).PrepareForEval(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to prepare rego query: %w", err)
	}

	ready := hasDecisionPolicy(query)
	e.mu.Lock()
	e.query = query
	e.ready = ready
	e.mu.Unlock()
	return nil
}

// Ready reports whether the active query has a compiled authorization decision
// rule. Missing, empty, or unrelated policy directories are not ready. This
// checks that the entry point exists; Evaluate still validates each result
// because a rule can return different values for different requests.
func (e *Engine) Ready() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ready
}

// hasDecisionPolicy checks the compiled rule paths instead of evaluating an
// invented request, which could miss a valid input-dependent policy.
func hasDecisionPolicy(query rego.PreparedEvalQuery) bool {
	for _, module := range query.Modules() {
		for _, rule := range module.Rules {
			path := rule.Ref().String()
			if len(rule.Head.Args) == 0 && (path == "data.kiterail.authz.decision" || strings.HasPrefix(path, "data.kiterail.authz.decision.")) {
				return true
			}
		}
	}
	return false
}

// loaderPath adapts a policy directory for rego.Load. OPA's loader
// URL-parses its path inputs: on Windows an absolute path such as
// `D:\policies` parses as a URL whose scheme is the drive letter, and the
// path is silently mangled ("\policies"). Absolute paths are therefore
// converted to file:// URLs, which the loader handles identically on every
// OS. Relative paths (the common shape, e.g. cfg.PolicyDir = "policies")
// pass through untouched.
func loaderPath(policyDir string) string {
	if !filepath.IsAbs(policyDir) {
		return policyDir
	}
	// The leading slash matters: without it url.URL.String() emits
	// "file://C:/..." and the drive letter is parsed as the URL host.
	// OPA's fileurl.Clean strips exactly one leading slash on Windows,
	// yielding the intact "C:/..." the OS APIs expect.
	path := filepath.ToSlash(policyDir)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return (&url.URL{Scheme: "file", Path: path}).String()
}

// Evaluate evaluates the input against the loaded policies.
// Fails closed on evaluation errors (returns deny with policy_eval_error rule).
func (e *Engine) Evaluate(ctx context.Context, input types.EvalInput) (types.ProxyDecision, error) {
	inputMap := map[string]interface{}{
		"tool":       input.Tool,
		"arguments":  input.Arguments,
		"agent":      input.Agent,
		"timestamp":  input.Timestamp,
		"raw_method": input.RawMethod,
	}

	e.mu.RLock()
	query := e.query
	e.mu.RUnlock()

	rs, err := query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		// Fail closed: log the error and return a deny decision
		e.logger.Error("policy evaluation failed — failing closed", zap.Error(err))
		return types.ProxyDecision{
			Action:      types.ActionDeny,
			Rule:        "policy_eval_error",
			Explanation: "Policy evaluation failed — failing closed",
		}, nil
	}

	// No result is different from a malformed result. Both must have a named
	// deny decision so the ledger can explain why upstream execution stopped.
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return types.ProxyDecision{
			Action:      types.ActionDeny,
			Rule:        "no_policy_decision",
			Explanation: "No policy produced a decision — failing closed",
		}, nil
	}

	expr := rs[0].Expressions[0].Value
	fields, ok := expr.(map[string]interface{})
	if !ok {
		e.logger.Error("policy returned a non-decision value — failing closed", zap.Any("value", expr))
		return invalidPolicyDecision(), nil
	}

	// Start with zero values: pre-filling action with deny would disguise a
	// missing, null, or non-string action as an intentionally authored deny.
	action, _ := fields["action"].(string)
	rule, _ := fields["rule"].(string)
	explanation, _ := fields["explanation"].(string)
	decision := types.ProxyDecision{
		Action:      types.Action(action),
		Rule:        rule,
		Explanation: explanation,
	}
	if !decision.Action.Valid() || strings.TrimSpace(decision.Rule) == "" {
		e.logger.Error("policy engine returned an invalid decision — failing closed",
			zap.String("action", string(decision.Action)),
			zap.String("rule", decision.Rule))
		return invalidPolicyDecision(), nil
	}

	return decision, nil
}

// invalidPolicyDecision is the fail-closed result for a policy that produced
// a malformed decision (unknown/empty action, empty rule, non-decision value).
func invalidPolicyDecision() types.ProxyDecision {
	return types.ProxyDecision{
		Action:      types.ActionDeny,
		Rule:        "invalid_policy_decision",
		Explanation: "Policy engine returned an invalid decision",
	}
}
