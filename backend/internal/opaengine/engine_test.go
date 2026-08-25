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

func TestEngine_NoPolicies(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()
	engine, err := New(ctx, "nonexistent-dir", logger)
	require.NoError(t, err)

	input := types.EvalInput{
		Tool:      "test_tool",
		Agent:     "agent_1",
		Timestamp: time.Now(),
	}

	decision, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	// Without matching policy, default should be deny
	assert.Equal(t, "deny", decision.Action)
	assert.Equal(t, "No matching policy found (fallback)", decision.Explanation)
}

func TestEngine_WithPolicies(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewDevelopment()

	// Use a temp dir in the current working directory for Windows path compatibility with rego.Load
	tmpDir, err := os.MkdirTemp(".", "test-policy-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
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
	_ = os.WriteFile(policyPath, []byte(regoContent), 0644)
	require.NoError(t, err)

	engine, err := New(ctx, tmpDir, logger)
	require.NoError(t, err)

	tests := []struct {
		name         string
		inputAgent   string
		expectAction string
		expectRule   string
	}{
		{
			name:         "Allowed Agent",
			inputAgent:   "agent_1",
			expectAction: "allow",
			expectRule:   "allow_agent_1",
		},
		{
			name:         "Quarantined Agent",
			inputAgent:   "agent_2",
			expectAction: "quarantine",
			expectRule:   "quarantine_agent_2",
		},
		{
			name:         "Unknown Agent",
			inputAgent:   "agent_3",
			expectAction: "deny",
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
		expectAction string
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
			expectAction: "allow",
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
			expectAction: "quarantine",
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
			expectAction: "deny",
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
			expectAction: "deny",
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
