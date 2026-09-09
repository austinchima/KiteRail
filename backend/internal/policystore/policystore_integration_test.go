package policystore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_ListPolicies seeds a policy directory on disk (the GitOps
// shape production uses) and verifies the store's read model: enabled and
// disabled (.rego.disabled) files, metadata parsing, and content exposure.
// There is intentionally no mutation path to test — policies are immutable
// GitOps assets in v1.0 (see store.go).
func TestIntegration_ListPolicies(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "refund_review.rego"), []byte(`# Title: Refund Review
# Trigger: refund_requested
# Action: quarantine

package kiterail.authz

default allow := false
`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "legacy_deny.rego.disabled"), []byte(`# Title: Legacy Deny
# Trigger: old_rule
# Action: deny
`), 0644))

	store, err := New(tmpDir)
	require.NoError(t, err)

	policies, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 2)

	byID := map[string]Policy{}
	for _, p := range policies {
		byID[p.ID] = p
	}

	enabled := byID["refund_review"]
	assert.True(t, enabled.Enabled)
	assert.Equal(t, "Refund Review", enabled.Title)
	assert.Equal(t, "refund_requested", enabled.TriggerRule)
	assert.Equal(t, "quarantine", enabled.ActionType)
	assert.Contains(t, enabled.Code, "package kiterail.authz")

	disabled := byID["legacy_deny"]
	assert.False(t, disabled.Enabled)
	assert.Equal(t, "Legacy Deny", disabled.Title)
}
