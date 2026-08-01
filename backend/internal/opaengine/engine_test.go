package opaengine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/austinchima/kiterail/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_NoPolicies(t *testing.T) {
	ctx := context.Background()
	engine, err := New(ctx, "nonexistent-dir")
	require.NoError(t, err)

	input := proxy.EvalInput{
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
	tmpDir, err := os.MkdirTemp(".", "test-policy-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	policyPath := filepath.Join(tmpDir, "policy.rego")

	regoContent := `
package kiterail.authz

default decision = {
	"action": "deny",
	"rule": "default",
	"explanation": "default deny"
}

decision = {
	"action": "allow",
	"rule": "allow_agent_1",
	"explanation": "Agent 1 is allowed"
} if {
	input.agent == "agent_1"
}

decision = {
	"action": "quarantine",
	"rule": "quarantine_agent_2",
	"explanation": "Agent 2 is quarantined"
} if {
	input.agent == "agent_2"
}
`
	err = os.WriteFile(policyPath, []byte(regoContent), 0644)
	require.NoError(t, err)

	engine, err := New(ctx, tmpDir)
	require.NoError(t, err)

	tests := []struct {
		name          string
		inputAgent    string
		expectAction  string
		expectRule    string
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
			expectRule:   "default",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := proxy.EvalInput{
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
