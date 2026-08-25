package opaengine

import (
	"context"
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/types"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine represents the OPA policy evaluation engine.
type Engine struct {
	policyDir string
	query     rego.PreparedEvalQuery
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

// Reload reads the policy directory and recompiles the policies.
func (e *Engine) Reload(ctx context.Context) error {
	_, err := os.Stat(e.policyDir)
	if os.IsNotExist(err) {
		// Ignore if directory doesn't exist, just an empty engine
		query, err := rego.New(
			rego.Query("data.kiterail.authz.decision"),
		).PrepareForEval(ctx)
		if err != nil {
			return err
		}
		e.query = query
		return nil
	}

	query, err := rego.New(
		rego.Query("data.kiterail.authz.decision"),
		rego.Load([]string{e.policyDir}, nil),
	).PrepareForEval(ctx)

	if err != nil {
		return fmt.Errorf("failed to prepare rego query: %w", err)
	}

	e.mu.Lock()
	e.query = query
	e.mu.Unlock()
	return nil
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
			Action:      "deny",
			Rule:        "policy_eval_error",
			Explanation: "Policy evaluation failed — failing closed",
		}, nil
	}

	decision := types.ProxyDecision{
		Action:      "deny", // default fail-closed
		Explanation: "No matching policy found (fallback)",
	}

	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		expr := rs[0].Expressions[0].Value
		if m, ok := expr.(map[string]interface{}); ok {
			if action, ok := m["action"].(string); ok {
				decision.Action = action
			}
			if rule, ok := m["rule"].(string); ok {
				decision.Rule = rule
			}
			if exp, ok := m["explanation"].(string); ok {
				decision.Explanation = exp
			}
		}
	}

	return decision, nil
}
