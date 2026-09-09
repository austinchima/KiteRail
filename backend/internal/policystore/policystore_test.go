package policystore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := New(tmpDir)
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, tmpDir, store.policyDir)
}

func TestList(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test .rego files
	enabledPath := filepath.Join(tmpDir, "policy1.rego")
	disabledPath := filepath.Join(tmpDir, "policy2.rego.disabled")

	require.NoError(t, os.WriteFile(enabledPath, []byte(`# Title: Policy One
# Trigger: user_created
# Action: deny`), 0644))
	require.NoError(t, os.WriteFile(disabledPath, []byte(`# Title: Policy Two
# Trigger: order_placed
# Action: quarantine`), 0644))

	store, err := New(tmpDir)
	require.NoError(t, err)
	policies, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, policies, 2)

	// policy1 should be enabled
	policy1 := policies[0]
	assert.Equal(t, "policy1", policy1.ID)
	assert.Equal(t, "Policy One", policy1.Title)
	assert.Equal(t, "user_created", policy1.TriggerRule)
	assert.Equal(t, "deny", policy1.ActionType)
	assert.True(t, policy1.Enabled)

	// policy2 should be disabled
	policy2 := policies[1]
	assert.Equal(t, "policy2", policy2.ID)
	assert.Equal(t, "Policy Two", policy2.Title)
	assert.Equal(t, "order_placed", policy2.TriggerRule)
	assert.Equal(t, "quarantine", policy2.ActionType)
	assert.False(t, policy2.Enabled)
}

func TestListRecursivelySortsPoliciesByRelativePath(t *testing.T) {
	tmpDir := t.TempDir()
	nested := filepath.Join(tmpDir, "payments")
	require.NoError(t, os.MkdirAll(nested, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "refund.rego"), []byte("# nested"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "access.rego.disabled"), []byte("# disabled"), 0644))

	store, err := New(tmpDir)
	require.NoError(t, err)
	policies, err := store.List(context.Background())
	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.Equal(t, "access", policies[0].ID)
	assert.False(t, policies[0].Enabled)
	assert.Equal(t, "payments/refund", policies[1].ID)
	assert.True(t, policies[1].Enabled)
}

func TestParseMetadata(t *testing.T) {
	content := `# Title: Test Policy
# Trigger: user_signup
# Action: allow
# Description: This is a test policy`

	title, trigger, action := parseMetadata(content)
	assert.Equal(t, "Test Policy", title)
	assert.Equal(t, "user_signup", trigger)
	assert.Equal(t, "allow", action)
}

func TestParseMetadata_FallbackTitle(t *testing.T) {
	content := `# This is a comment
# Trigger: test
# Action: allow`

	title, trigger, action := parseMetadata(content)
	assert.Equal(t, "This is a comment", title)
	assert.Equal(t, "test", trigger)
	assert.Equal(t, "allow", action)
}

func TestParseMetadata_Empty(t *testing.T) {
	title, trigger, action := parseMetadata("")
	assert.Equal(t, "", title)
	assert.Equal(t, "", trigger)
	assert.Equal(t, "", action)
}
