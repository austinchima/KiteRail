package policystore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_SaveListAndTogglePolicy(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	store, err := New(tmpDir)
	require.NoError(t, err)

	err = store.Save(ctx, "refund_review", `# Title: Refund Review
# Trigger: refund_requested
# Action: quarantine

package kiterail.authz

default allow := false
`, true)
	require.NoError(t, err)

	policies, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "refund_review", policies[0].ID)
	assert.Equal(t, "Refund Review", policies[0].Title)
	assert.Equal(t, "refund_requested", policies[0].TriggerRule)
	assert.Equal(t, "quarantine", policies[0].ActionType)
	assert.True(t, policies[0].Enabled)

	err = store.UpdateEnabled(ctx, "refund_review", false)
	require.NoError(t, err)
	assert.NoFileExists(t, filepath.Join(tmpDir, "refund_review.rego"))
	assert.FileExists(t, filepath.Join(tmpDir, "refund_review.rego.disabled"))

	policies, err = store.List(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.False(t, policies[0].Enabled)

	err = store.Save(ctx, "refund_review", "# Title: Refund Review Updated", true)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(tmpDir, "refund_review.rego"))
	assert.NoFileExists(t, filepath.Join(tmpDir, "refund_review.rego.disabled"))

	content, err := os.ReadFile(filepath.Join(tmpDir, "refund_review.rego"))
	require.NoError(t, err)
	assert.Equal(t, "# Title: Refund Review Updated", string(content))
}
