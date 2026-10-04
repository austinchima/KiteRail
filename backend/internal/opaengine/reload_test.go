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

func writePolicy(t *testing.T, dir, rule string) {
	t.Helper()
	content := `package elodea.authz

import rego.v1

decision := {"action": "allow", "rule": "` + rule + `", "explanation": "x"}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(content), 0o644))
}

func TestEngine_PolicyVersionAndReload(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writePolicy(t, dir, "v1_rule")

	engine, err := New(ctx, dir, zap.NewNop())
	require.NoError(t, err)
	v1 := engine.Version()
	require.Regexp(t, `^sha256:[0-9a-f]{16}$`, v1)

	decision, err := engine.Evaluate(ctx, types.EvalInput{Tool: "t", Agent: "a", Timestamp: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, "v1_rule", decision.Rule)
	assert.Equal(t, v1, decision.PolicyVersion, "every decision names the bundle that made it")

	writePolicy(t, dir, "v2_rule")
	require.NoError(t, engine.Reload(ctx))
	assert.NotEqual(t, v1, engine.Version())
	decision, _ = engine.Evaluate(ctx, types.EvalInput{Tool: "t", Agent: "a", Timestamp: time.Now()})
	assert.Equal(t, "v2_rule", decision.Rule)

	// A broken bundle is rejected and the previous policy keeps enforcing.
	v2 := engine.Version()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.rego"), []byte("package elodea.authz\nthis is not rego"), 0o644))
	require.Error(t, engine.Reload(ctx))
	assert.Equal(t, v2, engine.Version())
	decision, _ = engine.Evaluate(ctx, types.EvalInput{Tool: "t", Agent: "a", Timestamp: time.Now()})
	assert.Equal(t, "v2_rule", decision.Rule)
}

func TestEngine_WatchForChangesReloadsNewBundle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	writePolicy(t, dir, "before")

	engine, err := New(ctx, dir, zap.NewNop())
	require.NoError(t, err)
	go engine.WatchForChanges(ctx, 10*time.Millisecond)

	writePolicy(t, dir, "after")
	require.Eventually(t, func() bool {
		d, _ := engine.Evaluate(ctx, types.EvalInput{Tool: "t", Agent: "a", Timestamp: time.Now()})
		return d.Rule == "after"
	}, 2*time.Second, 10*time.Millisecond)
}

func TestEngine_InputCarriesSchemaVersionAndProtocol(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	content := `package elodea.authz

import rego.v1

default decision := {"action": "deny", "rule": "default_deny", "explanation": "x"}

decision := {"action": "allow", "rule": "schema_ok", "explanation": "x"} if {
	input.schema_version == "elodea.eval/v1"
	input.protocol == "mcp"
	input.protocol_version == "2026-07-28"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(content), 0o644))
	engine, err := New(ctx, dir, zap.NewNop())
	require.NoError(t, err)

	d, err := engine.Evaluate(ctx, types.EvalInput{Protocol: "mcp", ProtocolVersion: "2026-07-28", Tool: "t", Agent: "a", Timestamp: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, "schema_ok", d.Rule)
}

func TestEngine_RejectsPreRenamePackage(t *testing.T) {
	dir := t.TempDir()
	content := "package kiterail.authz\n\nimport rego.v1\n\ndecision := {\"action\": \"allow\", \"rule\": \"r\", \"explanation\": \"x\"}\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(content), 0o644))

	_, err := New(context.Background(), dir, zap.NewNop())
	require.ErrorContains(t, err, "package elodea.authz")
}
