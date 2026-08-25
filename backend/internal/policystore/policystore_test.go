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

func TestUpdateEnabled(t *testing.T) {
	tmpDir := t.TempDir()

	// Create enabled policy
	enabledPath := filepath.Join(tmpDir, "policy1.rego")
	require.NoError(t, os.WriteFile(enabledPath, []byte(`# Title: Policy One`), 0644))

	store, err := New(tmpDir)
	require.NoError(t, err)

	// Disable it
	err = store.UpdateEnabled(context.Background(), "policy1", false)
	require.NoError(t, err)

	// Check it's now disabled
	disabledPath := filepath.Join(tmpDir, "policy1.rego.disabled")
	if _, err := os.Stat(disabledPath); err != nil {
		t.Fatalf("expected disabled file to exist: %v", err)
	}
	if _, err := os.Stat(enabledPath); err == nil {
		t.Fatal("expected enabled file to be removed")
	}

	// Re-enable it
	err = store.UpdateEnabled(context.Background(), "policy1", true)
	require.NoError(t, err)

	// Check it's enabled again
	reEnabledPath := filepath.Join(tmpDir, "policy1.rego")
	if _, err := os.Stat(reEnabledPath); err != nil {
		t.Fatalf("expected enabled file to exist: %v", err)
	}
	if _, err := os.Stat(disabledPath); err == nil {
		t.Fatal("expected disabled file to be removed")
	}
}

func TestSave(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := New(tmpDir)
	require.NoError(t, err)

	// Save an enabled policy
	err = store.Save(context.Background(), "policy1", "# Title: Saved Policy\n# Trigger: test\n# Action: allow", true)
	require.NoError(t, err)

	enabledPath := filepath.Join(tmpDir, "policy1.rego")
	if _, err := os.Stat(enabledPath); err != nil {
		t.Fatalf("expected enabled file to exist: %v", err)
	}

	content, err := os.ReadFile(enabledPath)
	require.NoError(t, err)
	assert.Equal(t, "# Title: Saved Policy\n# Trigger: test\n# Action: allow", string(content))

	// Save the same policy as disabled
	err = store.Save(context.Background(), "policy1", "# Disabled policy code", false)
	require.NoError(t, err)

	disabledPath := filepath.Join(tmpDir, "policy1.rego.disabled")
	if _, err := os.Stat(disabledPath); err != nil {
		t.Fatalf("expected disabled file to exist: %v", err)
	}

	content2, err := os.ReadFile(disabledPath)
	require.NoError(t, err)
	assert.Equal(t, "# Disabled policy code", string(content2))

	// Check the enabled file is removed
	if _, err := os.Stat(enabledPath); err == nil {
		t.Fatal("expected enabled file to be removed")
	}
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

func FileExists(t *testing.T, path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func NotFileExists(t *testing.T, path string) bool {
	_, err := os.Stat(path)
	assert.Error(t, err)
	return false
}
