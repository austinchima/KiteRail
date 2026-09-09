package policystore

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/types"
)

// simulatePolicyDir writes a policy exercising every decision-validation path
// and returns its path. t.TempDir is absolute — on Windows "C:\..." — which
// pins the engine's absolute-path loading (drive letter must not be consumed
// as a URL scheme).
func simulatePolicyDir(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	regoContent := `
package kiterail.authz

import rego.v1

default decision := {"action": "deny", "rule": "default_deny", "explanation": "No matching allow rule found"}

# Well-formed decisions, one per outcome
sane := {"action": "allow", "rule": "allow_sane", "explanation": "well-formed"}
decision := sane if { input.tool == "sane" }

# Parity probe: fires only when raw_method is empty. If the simulator ever
# re-injects a "tools/call" default, this rule stops matching and the test
# sees default_deny instead — the divergence is caught, not silent.
decision := {"action": "allow", "rule": "no_raw_method_default"} if {
	input.tool == "raw_probe"
	input.raw_method == ""
}

# Malformed decisions: engine must rewrite these to invalid_policy_decision
decision := {"action": "allow"} if { input.tool == "missing_rule" }
decision := {"action": "", "rule": "empty_action_rule"} if { input.tool == "empty_action" }
decision := {"action": "audit", "rule": "audit_only"} if { input.tool == "unknown_action" }
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "policy.rego"), []byte(regoContent), 0644))
	return tmpDir
}

// TestSimulateParity pins the simulator contract: POST /simulate must run the
// identical input through the identical engine and return the enforcement
// outcome — action, rule, and explanation — with no simulator-only defaults.
func TestSimulateParity(t *testing.T) {
	ctx := context.Background()
	dir := simulatePolicyDir(t)

	store, err := New(dir)
	require.NoError(t, err)
	engine, err := opaengine.New(ctx, dir, zap.NewNop())
	require.NoError(t, err)
	handler := NewHandler(store, engine, zap.NewNop())

	tools := []string{"sane", "raw_probe", "missing_rule", "empty_action", "unknown_action"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			args := map[string]interface{}{"amount": 100}
			input := types.EvalInput{
				Tool:      tool,
				Arguments: args,
				Agent:     "sim",
				Timestamp: time.Now(),
			}

			// Runtime path: exactly what the proxy's EvalInput carries
			// (RawMethod unset ⇒ empty string).
			want, err := engine.Evaluate(ctx, input)
			require.NoError(t, err)

			// Simulator path.
			body, err := json.Marshal(map[string]interface{}{
				"tool":      tool,
				"arguments": args,
				"agent":     "sim",
			})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/simulate", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

			var got types.ProxyDecision
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))

			assert.Equal(t, want.Action, got.Action, "simulator action diverged from runtime")
			assert.Equal(t, want.Rule, got.Rule, "simulator rule diverged from runtime")
			assert.Equal(t, want.Explanation, got.Explanation, "simulator explanation diverged from runtime")
		})
	}
}
