package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clearKiteRailEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KITERAIL_") {
			os.Unsetenv(strings.SplitN(kv, "=", 2)[0])
		}
	}
	t.Cleanup(func() {
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "KITERAIL_") {
				os.Unsetenv(strings.SplitN(kv, "=", 2)[0])
			}
		}
	})
}

func TestLoad_Defaults(t *testing.T) {
	clearKiteRailEnv(t)

	cfg := defaultConfig()

	assert.Equal(t, ":8080", cfg.ListenAddr)
	assert.Equal(t, "./policies", cfg.PolicyDir)
	assert.Equal(t, "nats://localhost:4222", cfg.NatsURL)
	assert.Equal(t, "postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable", cfg.PostgresDSN)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Empty(t, cfg.APIKeys)
	assert.Empty(t, cfg.TargetURL)

	// Defaults alone are not a valid production configuration.
	require.Error(t, cfg.Validate())
}

func TestValidate_RequiresSeparatedTrustDomains(t *testing.T) {
	base := defaultConfig()
	base.TargetURL = "https://upstream.example.com"
	base.PostgresDSN = "postgres://prod@db/prod?sslmode=require"
	base.APIKeys = map[string]string{"sk_live_a": "agent-1"}

	// Agents only — must be rejected: agents could approve their own actions.
	err := base.Validate()
	require.Error(t, err)

	base.ReviewerAPIKeys = map[string]string{"rvw_key": "jane"}
	require.NoError(t, base.Validate())

	// Cross-role credential reuse must be rejected.
	base.AdminAPIKeys = map[string]string{"sk_live_a": "root"}
	err = base.Validate()
	require.ErrorContains(t, err, "duplicates")
}

func TestValidate_ProductionRejectsDevCredentials(t *testing.T) {
	t.Setenv("KITERAIL_ALLOW_DEV_CREDENTIALS", "")

	cfg := defaultConfig()
	cfg.Environment = "production"
	cfg.TargetURL = "https://upstream.example.com"
	cfg.PostgresDSN = "postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable"
	cfg.APIKeys = map[string]string{"sk_dev_123": "agent-1"}
	cfg.ReviewerAPIKeys = map[string]string{"rvw": "jane"}
	cfg.TLSCertFile = "/certs/tls.crt"
	cfg.TLSKeyFile = "/certs/tls.key"

	err := cfg.Validate()
	require.Error(t, err)

	// Explicit override is honoured.
	t.Setenv("KITERAIL_ALLOW_DEV_CREDENTIALS", "1")
	assert.NoError(t, cfg.Validate())
}

func TestLoad_EnvVars(t *testing.T) {
	clearKiteRailEnv(t)

	os.Setenv("KITERAIL_LISTEN_ADDR", ":9090")
	os.Setenv("KITERAIL_TARGET_URL", "http://example.com")
	os.Setenv("KITERAIL_POLICY_DIR", "/custom/policies")
	os.Setenv("KITERAIL_NATS_URL", "nats://remote:4222")
	os.Setenv("KITERAIL_POSTGRES_DSN", "postgres://user:pass@remote/db")
	os.Setenv("KITERAIL_LOG_LEVEL", "debug")
	os.Setenv("KITERAIL_API_KEYS", "key1:val1,key2:val2")
	os.Setenv("KITERAIL_REVIEWER_API_KEYS", "rvw1:jane")

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
	assert.Equal(t, "jane", cfg.ReviewerAPIKeys["rvw1"])
}

func TestLoad_YAML(t *testing.T) {
	clearKiteRailEnv(t)
	yamlPath := filepath.Join(t.TempDir(), "config.yaml")

	yamlContent := `
listen_addr: ":8081"
target_url: "http://yaml.com"
policy_dir: "/yaml/policies"
nats_url: "nats://yaml:4222"
postgres_dsn: "postgres://yaml/db"
log_level: "warn"
api_keys:
  yamlkey: yamlval
reviewer_api_keys:
  rvwyaml: janeyaml
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0644))

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
	assert.Equal(t, "janeyaml", cfg.ReviewerAPIKeys["rvwyaml"])
}
