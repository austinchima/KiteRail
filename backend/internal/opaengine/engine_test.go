package opaengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoaderPath pins the absolute-path adaptation: rego.Load URL-parses its
// inputs, so a Windows absolute path ("C:\\policies") would be mangled (drive
// letter consumed as URL scheme) without conversion to a file:// URL.
// Relative paths — the common production shape — must pass through verbatim.
func TestLoaderPath(t *testing.T) {
	assert.Equal(t, "policies", loaderPath("policies"))
	assert.Equal(t, "./policies", loaderPath("./policies"))

	abs := filepath.Join(t.TempDir(), "policies")
	if filepath.IsAbs(abs) { // always true for t.TempDir, but pins the intent
		want := "file:///" + filepath.ToSlash(abs)
		assert.Equal(t, want, loaderPath(abs))
	}
}

func TestEngine_NoPolicies(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()
	engine, err := New(ctx, "nonexistent-dir", logger)
	require.NoError(t, err)
	assert.False(t, engine.Ready())

	input := types.EvalInput{
		Tool:      "test_tool",
		Agent:     "agent_1",
		Timestamp: time.Now(),
	}

	decision, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	// No loaded policy is distinct from a malformed policy decision: callers
	// receive a named fail-closed outcome that the ledger can explain.
	assert.Equal(t, types.ActionDeny, decision.Action)
	assert.Equal(t, "no_policy_decision", decision.Rule)
}

func TestEngine_WithPolicies(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	// t.TempDir is absolute ("C:\..." on Windows) — pins the engine's
	// absolute-path handling; see loaderPath.
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.rego")

	regoContent := `
package kiterail.authz

import rego.v1

severity := {"deny": 3, "quarantine": 2, "allow": 1}

default decision := {"action": "deny", "rule": "default_deny", "explanation": "No matching allow rule found"}

decision := result if {
    count(decisions) > 0
    max_sev := max({severity[d.action] | some d in decisions})
    winners := sort([json.marshal(d) | some d in decisions; severity[d.action] == max_sev])
    result := json.unmarshal(winners[0])
}

decisions contains {"action": "allow", "rule": "allow_agent_1", "explanation": "Agent 1 is allowed"} if {
	input.agent == "agent_1"
}

decisions contains {"action": "quarantine", "rule": "quarantine_agent_2", "explanation": "Agent 2 is quarantined"} if {
	input.agent == "agent_2"
}
`
	err := os.WriteFile(policyPath, []byte(regoContent), 0644)
	require.NoError(t, err)

	engine, err := New(ctx, tmpDir, logger)
	require.NoError(t, err)
	assert.True(t, engine.Ready())

	tests := []struct {
		name         string
		inputAgent   string
		expectAction types.Action
		expectRule   string
	}{
		{
			name:         "Allowed Agent",
			inputAgent:   "agent_1",
			expectAction: types.ActionAllow,
			expectRule:   "allow_agent_1",
		},
		{
			name:         "Quarantined Agent",
			inputAgent:   "agent_2",
			expectAction: types.ActionQuarantine,
			expectRule:   "quarantine_agent_2",
		},
		{
			name:         "Unknown Agent",
			inputAgent:   "agent_3",
			expectAction: types.ActionDeny,
			expectRule:   "default_deny",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := types.EvalInput{
				Tool:      "test_tool",
				Agent:     tc.inputAgent,
				Timestamp: time.Now(),
			}

			decision, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expectAction, decision.Action)
			assert.Equal(t, tc.expectRule, decision.Rule)
		})
	}
}

func TestEngine_RepositoryPolicies(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	policyDir := filepath.Clean(filepath.Join("..", "..", "..", "policies"))
	if _, err := os.Stat(policyDir); err != nil {
		t.Skipf("repository policy directory not available: %v", err)
	}

	engine, err := New(ctx, policyDir, logger)
	require.NoError(t, err)

	tests := []struct {
		name         string
		input        types.EvalInput
		expectAction types.Action
		expectRule   string
	}{
		{
			name: "Small refund allowed",
			input: types.EvalInput{
				Tool:      "stripe.charge.refund",
				Arguments: map[string]interface{}{"amount": 100},
				Agent:     "agent_1",
				Timestamp: time.Now(),
			},
			expectAction: types.ActionAllow,
			expectRule:   "refund_under_limit",
		},
		{
			name: "Large refund quarantined",
			input: types.EvalInput{
				Tool:      "stripe.charge.refund",
				Arguments: map[string]interface{}{"amount": 1500},
				Agent:     "agent_1",
				Timestamp: time.Now(),
			},
			expectAction: types.ActionQuarantine,
			expectRule:   "refund_over_limit",
		},
		{
			name: "Deny outranks quarantine",
			input: types.EvalInput{
				Tool: "swift.wire.initiate",
				Arguments: map[string]interface{}{
					"amount":       50000,
					"jurisdiction": "OFAC_FLAGGED",
				},
				Agent:     "agent_1",
				Timestamp: time.Now(),
			},
			expectAction: types.ActionDeny,
			expectRule:   "aml_jurisdiction_block",
		},
		{
			name: "Unknown tool default denied",
			input: types.EvalInput{
				Tool:      "unknown.tool",
				Arguments: map[string]interface{}{},
				Agent:     "agent_1",
				Timestamp: time.Now(),
			},
			expectAction: types.ActionDeny,
			expectRule:   "default_deny",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := engine.Evaluate(ctx, tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expectAction, decision.Action)
			assert.Equal(t, tc.expectRule, decision.Rule)
		})
	}
}

// TestEngine_InvalidDecisions pins the fail-closed property at the trust
// boundary: any decision the engine cannot fully explain (empty/unknown
// action, empty rule, or a non-decision value) becomes
// invalid_policy_decision — garbage in, deny out.
func TestEngine_InvalidDecisions(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// t.TempDir returns an ABSOLUTE path — on Windows "C:\..." — which is
	// precisely the shape rego.Load used to mangle (drive letter parsed as a
	// URL scheme). This test fails if that regression returns.
	tmpDir := t.TempDir()

	regoContent := `
package kiterail.authz

import rego.v1

default decision := {"action": "deny", "rule": "default_deny", "explanation": "No matching allow rule found"}

# Valid decisions for contrast
sane := {"action": "allow", "rule": "allow_sane", "explanation": "well-formed"}
decision := sane if { input.tool == "sane" }

# Malformed decisions: each must be rewritten to invalid_policy_decision
decision := {"action": "allow"} if { input.tool == "missing_rule" }
decision := {"action": "", "rule": "empty_action_rule"} if { input.tool == "empty_action" }
decision := {"action": "audit", "rule": "audit_only"} if { input.tool == "unknown_action" }
decision := "not-a-decision" if { input.tool == "non_decision" }
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "policy.rego"), []byte(regoContent), 0644))

	engine, err := New(ctx, tmpDir, logger)
	require.NoError(t, err)

	t.Run("well-formed decision passes through", func(t *testing.T) {
		decision, err := engine.Evaluate(ctx, types.EvalInput{Tool: "sane", Agent: "a", Timestamp: time.Now()})
		require.NoError(t, err)
		assert.Equal(t, types.ActionAllow, decision.Action)
		assert.Equal(t, "allow_sane", decision.Rule)
	})

	malformedTools := []string{"missing_rule", "empty_action", "unknown_action", "non_decision"}
	for _, tool := range malformedTools {
		t.Run(tool+" fails closed", func(t *testing.T) {
			decision, err := engine.Evaluate(ctx, types.EvalInput{Tool: tool, Agent: "a", Timestamp: time.Now()})
			require.NoError(t, err)
			assert.Equal(t, types.ActionDeny, decision.Action)
			assert.Equal(t, "invalid_policy_decision", decision.Rule)
			assert.NotEmpty(t, decision.Explanation)
		})
	}
}

// TestEngine_EvalError pins the existing fail-closed behaviour on evaluation
// errors (distinct rule from invalid_policy_decision).
func TestEngine_EvalError(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Absolute temp dir pins Windows path handling (see loaderPath).
	tmpDir := t.TempDir()

	// json.unmarshal on invalid input is a builtin runtime error: the policy
	// compiles but evaluation fails, exercising the fail-closed branch.
	regoContent := `
package kiterail.authz

import rego.v1

decision := json.unmarshal("not-json") if { input.tool == "x" }
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "policy.rego"), []byte(regoContent), 0644))

	engine, err := New(ctx, tmpDir, logger)
	require.NoError(t, err)

	decision, err := engine.Evaluate(ctx, types.EvalInput{Tool: "x", Agent: "a", Timestamp: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, types.ActionDeny, decision.Action)
	assert.Equal(t, "policy_eval_error", decision.Rule)
}
