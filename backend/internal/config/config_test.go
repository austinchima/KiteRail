package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_Defaults(t *testing.T) {
	// Ensure no env vars interfere
	os.Clearenv()

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.ListenAddr)
	assert.Equal(t, "./policies", cfg.PolicyDir)
	assert.Equal(t, "nats://localhost:4222", cfg.NatsURL)
	assert.Equal(t, "postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable", cfg.PostgresDSN)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Empty(t, cfg.APIKeys)
	assert.Empty(t, cfg.TargetURL)
}

func TestLoad_EnvVars(t *testing.T) {
	os.Clearenv()
	os.Setenv("KITERAIL_LISTEN_ADDR", ":9090")
	os.Setenv("KITERAIL_TARGET_URL", "http://example.com")
	os.Setenv("KITERAIL_POLICY_DIR", "/custom/policies")
	os.Setenv("KITERAIL_NATS_URL", "nats://remote:4222")
	os.Setenv("KITERAIL_POSTGRES_DSN", "postgres://user:pass@remote/db")
	os.Setenv("KITERAIL_LOG_LEVEL", "debug")
	os.Setenv("KITERAIL_API_KEYS", "key1:val1,key2:val2")

	defer os.Clearenv()

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, ":9090", cfg.ListenAddr)
	assert.Equal(t, "http://example.com", cfg.TargetURL)
	assert.Equal(t, "/custom/policies", cfg.PolicyDir)
	assert.Equal(t, "nats://remote:4222", cfg.NatsURL)
	assert.Equal(t, "postgres://user:pass@remote/db", cfg.PostgresDSN)
	assert.Equal(t, "debug", cfg.LogLevel)

	assert.Len(t, cfg.APIKeys, 2)
	assert.Equal(t, "val1", cfg.APIKeys["key1"])
	assert.Equal(t, "val2", cfg.APIKeys["key2"])
}

func TestLoad_YAML(t *testing.T) {
	os.Clearenv()
	tmpFile, err := os.CreateTemp(".", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	yamlPath := tmpFile.Name()

	yamlContent := `
listen_addr: ":8081"
target_url: "http://yaml.com"
policy_dir: "/yaml/policies"
nats_url: "nats://yaml:4222"
postgres_dsn: "postgres://yaml/db"
log_level: "warn"
api_keys:
  yamlkey: yamlval
`
	err = os.WriteFile(yamlPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(yamlPath)
	require.NoError(t, err)

	assert.Equal(t, ":8081", cfg.ListenAddr)
	assert.Equal(t, "http://yaml.com", cfg.TargetURL)
	assert.Equal(t, "/yaml/policies", cfg.PolicyDir)
	assert.Equal(t, "nats://yaml:4222", cfg.NatsURL)
	assert.Equal(t, "postgres://yaml/db", cfg.PostgresDSN)
	assert.Equal(t, "warn", cfg.LogLevel)

	assert.Len(t, cfg.APIKeys, 1)
	assert.Equal(t, "yamlval", cfg.APIKeys["yamlkey"])
}
