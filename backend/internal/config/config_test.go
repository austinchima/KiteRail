package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clearElodeaEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "ELODEA_") || strings.HasPrefix(kv, "KITERAIL_") {
			os.Unsetenv(strings.SplitN(kv, "=", 2)[0])
		}
	}
	t.Cleanup(func() {
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "ELODEA_") || strings.HasPrefix(kv, "KITERAIL_") {
				os.Unsetenv(strings.SplitN(kv, "=", 2)[0])
			}
		}
	})
}

func TestLoad_Defaults(t *testing.T) {
	clearElodeaEnv(t)

	cfg := defaultConfig()

	assert.Equal(t, ":8080", cfg.ListenAddr)
	assert.Equal(t, "./policies", cfg.PolicyDir)
	assert.Equal(t, "postgres://elodea:elodea@localhost:5432/elodea?sslmode=disable", cfg.PostgresDSN)
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
	t.Setenv("ELODEA_ALLOW_DEV_CREDENTIALS", "")

	cfg := defaultConfig()
	cfg.Environment = "production"
	cfg.TargetURL = "https://upstream.example.com"
	cfg.PostgresDSN = "postgres://elodea:elodea@localhost:5432/elodea?sslmode=disable"
	cfg.APIKeys = map[string]string{"sk_dev_123": "agent-1"}
	cfg.ReviewerAPIKeys = map[string]string{"rvw": "jane"}
	cfg.AllowedOrigins = []string{"https://console.example.com"}
	cfg.TLSCertFile = "/certs/tls.crt"
	cfg.TLSKeyFile = "/certs/tls.key"

	err := cfg.Validate()
	require.Error(t, err)

	// Explicit override is honoured.
	t.Setenv("ELODEA_ALLOW_DEV_CREDENTIALS", "1")
	assert.NoError(t, cfg.Validate())
}

func TestValidate_ProductionRejectsWildcardOriginsAndTooSmallPool(t *testing.T) {
	cfg := defaultConfig()
	cfg.Environment = "production"
	cfg.TargetURL = "https://upstream.example.com"
	cfg.PostgresDSN = "postgres://prod@db/prod?sslmode=require"
	cfg.APIKeys = map[string]string{"live-agent-0123456789abcdef": "agent-1"}
	cfg.ReviewerAPIKeys = map[string]string{"reviewer-0123456789abcdef": "jane"}
	cfg.TLSCertFile = "/certs/tls.crt"
	cfg.TLSKeyFile = "/certs/tls.key"

	require.ErrorContains(t, cfg.Validate(), "wildcard allowed_origins")

	cfg.AllowedOrigins = []string{"https://console.example.com"}
	cfg.PGMaxOpenConns = 1
	require.ErrorContains(t, cfg.Validate(), "at least 2")
}

func TestLoad_EnvVars(t *testing.T) {
	clearElodeaEnv(t)

	os.Setenv("ELODEA_LISTEN_ADDR", ":9090")
	os.Setenv("ELODEA_TARGET_URL", "http://example.com")
	os.Setenv("ELODEA_POLICY_DIR", "/custom/policies")
	os.Setenv("ELODEA_POSTGRES_DSN", "postgres://user:pass@remote/db")
	os.Setenv("ELODEA_LOG_LEVEL", "debug")
	os.Setenv("ELODEA_API_KEYS", "key1:val1,key2:val2")
	os.Setenv("ELODEA_REVIEWER_API_KEYS", "rvw1:jane")

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, ":9090", cfg.ListenAddr)
	assert.Equal(t, "http://example.com", cfg.TargetURL)
	assert.Equal(t, "/custom/policies", cfg.PolicyDir)
	assert.Equal(t, "postgres://user:pass@remote/db", cfg.PostgresDSN)
	assert.Equal(t, "debug", cfg.LogLevel)

	assert.Len(t, cfg.APIKeys, 2)
	assert.Equal(t, "val1", cfg.APIKeys["key1"])
	assert.Equal(t, "val2", cfg.APIKeys["key2"])
	assert.Equal(t, "jane", cfg.ReviewerAPIKeys["rvw1"])
}

func TestLoad_YAML(t *testing.T) {
	clearElodeaEnv(t)
	yamlPath := filepath.Join(t.TempDir(), "config.yaml")

	yamlContent := `
listen_addr: ":8081"
target_url: "http://yaml.com"
policy_dir: "/yaml/policies"
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
	assert.Equal(t, "postgres://yaml/db", cfg.PostgresDSN)
	assert.Equal(t, "warn", cfg.LogLevel)

	assert.Len(t, cfg.APIKeys, 1)
	assert.Equal(t, "yamlval", cfg.APIKeys["yamlkey"])
	assert.Equal(t, "janeyaml", cfg.ReviewerAPIKeys["rvwyaml"])
}

func productionConfig() *Config {
	cfg := defaultConfig()
	cfg.Environment = "production"
	cfg.TargetURL = "https://upstream.example.com"
	cfg.PostgresDSN = "postgres://prod@db/prod?sslmode=require"
	cfg.APIKeys = map[string]string{"agent-token-0123456789abcdef": "agent-1"}
	cfg.ReviewerAPIKeys = map[string]string{"reviewer-token-0123456789abcdef": "jane"}
	cfg.AllowedOrigins = []string{"https://console.example.com"}
	cfg.TLSCertFile = "/certs/tls.crt"
	cfg.TLSKeyFile = "/certs/tls.key"
	return cfg
}

func TestValidate_SeparationOfDuties(t *testing.T) {
	cfg := productionConfig()
	cfg.ReviewerAPIKeys = map[string]string{"reviewer-token-0123456789abcdef": "agent-1"}
	require.ErrorContains(t, cfg.Validate(), "separation of duties")
}

func TestValidate_ProductionRejectsShortTokens(t *testing.T) {
	t.Setenv("ELODEA_ALLOW_DEV_CREDENTIALS", "")
	cfg := productionConfig()
	cfg.ReviewerAPIKeys = map[string]string{"short": "jane"}
	require.ErrorContains(t, cfg.Validate(), "shorter than")
}

func TestValidate_TLSTerminatedUpstreamSatisfiesProductionTLS(t *testing.T) {
	t.Setenv("ELODEA_ALLOW_DEV_CREDENTIALS", "")
	cfg := productionConfig()
	cfg.TLSCertFile, cfg.TLSKeyFile = "", ""
	require.ErrorContains(t, cfg.Validate(), "tls_terminated_upstream")
	cfg.TLSTerminatedUpstream = true
	require.NoError(t, cfg.Validate())
}

func TestValidate_RejectsBadTargetURLAndLogLevel(t *testing.T) {
	cfg := productionConfig()
	cfg.TargetURL = "upstream.example.com/no-scheme"
	require.ErrorContains(t, cfg.Validate(), "absolute http(s) URL")

	cfg = productionConfig()
	cfg.LogLevel = "verbose"
	require.ErrorContains(t, cfg.Validate(), "log_level")
}

func TestLoad_SecretsFromFiles(t *testing.T) {
	clearElodeaEnv(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	os.Setenv("ELODEA_TARGET_URL", "http://upstream.internal")
	os.Setenv("ELODEA_POSTGRES_DSN_FILE", write("dsn", "postgres://secret@db/kr?sslmode=require\n"))
	os.Setenv("ELODEA_TARGET_AUTH_TOKEN_FILE", write("token", "upstream-secret\n"))
	os.Setenv("ELODEA_API_KEYS_FILE", write("agents", "agent-key-1:agent-a\nagent-key-2:agent-b\n"))
	os.Setenv("ELODEA_REVIEWER_API_KEYS_FILE", write("reviewers", "reviewer-key:jane"))

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "postgres://secret@db/kr?sslmode=require", cfg.PostgresDSN)
	assert.Equal(t, "upstream-secret", cfg.TargetAuthToken)
	assert.Equal(t, "agent-a", cfg.APIKeys["agent-key-1"])
	assert.Equal(t, "agent-b", cfg.APIKeys["agent-key-2"])
	assert.Equal(t, "jane", cfg.ReviewerAPIKeys["reviewer-key"])

	os.Setenv("ELODEA_ADMIN_API_KEYS_FILE", filepath.Join(dir, "missing"))
	_, err = Load("")
	require.ErrorContains(t, err, "ELODEA_ADMIN_API_KEYS_FILE")
}

func TestLoad_LegacyEnvStillApplies(t *testing.T) {
	clearElodeaEnv(t)
	t.Setenv("KITERAIL_TARGET_URL", "http://legacy.example:9000")
	t.Setenv("KITERAIL_LOG_LEVEL", "debug")
	t.Setenv("ELODEA_LOG_LEVEL", "warn")
	t.Setenv("KITERAIL_API_KEYS", "key1:agent")
	t.Setenv("KITERAIL_REVIEWER_API_KEYS", "rvw1:jane")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "http://legacy.example:9000", cfg.TargetURL, "pre-rename names keep working")
	assert.Equal(t, "warn", cfg.LogLevel, "the new name wins when both are set")
	assert.Equal(t, "agent", cfg.APIKeys["key1"])
	assert.Equal(t, []string{"KITERAIL_API_KEYS", "KITERAIL_REVIEWER_API_KEYS", "KITERAIL_TARGET_URL"}, cfg.LegacyEnv)
}

func TestValidate_OIDC(t *testing.T) {
	base := func() *Config {
		c := defaultConfig()
		c.TargetURL = "http://upstream.test"
		c.APIKeys = map[string]string{"agentkey": "agent"}
		c.AllowedOrigins = []string{"https://console.corp.test"}
		c.OIDC = OIDCConfig{
			Issuer: "https://corp.okta.com", ClientID: "elodea", ClientSecret: "s",
			RedirectURL: "https://elodea.corp.test/auth/callback", ReviewerGroups: []string{"reviewers"},
		}
		return c
	}

	c := base()
	require.NoError(t, c.Validate(), "SSO alone is enough human access; static reviewer keys are optional")
	assert.Equal(t, "groups", c.OIDC.GroupsClaim)
	assert.Equal(t, "email", c.OIDC.IdentityClaim)
	assert.Equal(t, 8*time.Hour, c.OIDC.SessionTTL)
	assert.Equal(t, time.Hour, c.OIDC.SessionIdleTTL)
	assert.Equal(t, []string{"openid", "email", "profile"}, c.OIDC.Scopes)

	cases := map[string]func(*Config){
		"half configured":           func(c *Config) { c.OIDC.Issuer = "" },
		"missing secret":            func(c *Config) { c.OIDC.ClientSecret = "" },
		"no groups":                 func(c *Config) { c.OIDC.ReviewerGroups = nil },
		"relative redirect":         func(c *Config) { c.OIDC.RedirectURL = "/auth/callback" },
		"wildcard-only origins":     func(c *Config) { c.AllowedOrigins = []string{"*"} },
		"bad samesite":              func(c *Config) { c.OIDC.CookieSameSite = "loose" },
		"samesite none needs https": func(c *Config) { c.OIDC.CookieSameSite = "none"; c.OIDC.RedirectURL = "http://x.test/cb" },
		"idle longer than session":  func(c *Config) { c.OIDC.SessionTTL = time.Hour; c.OIDC.SessionIdleTTL = 2 * time.Hour },
		"production http issuer": func(c *Config) {
			c.Environment = "production"
			c.TLSTerminatedUpstream = true
			c.OIDC.Issuer = "http://corp.okta.com"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(c)
			assert.Error(t, c.Validate())
		})
	}
}

func TestLoad_OIDCFromEnv(t *testing.T) {
	clearElodeaEnv(t)
	t.Setenv("ELODEA_TARGET_URL", "http://upstream.test")
	t.Setenv("ELODEA_API_KEYS", "agentkey:agent")
	t.Setenv("ELODEA_ALLOWED_ORIGINS", "https://console.corp.test")
	t.Setenv("ELODEA_OIDC_ISSUER", "https://login.microsoftonline.com/tenant/v2.0")
	t.Setenv("ELODEA_OIDC_CLIENT_ID", "elodea")
	t.Setenv("ELODEA_OIDC_REDIRECT_URL", "https://elodea.corp.test/auth/callback")
	t.Setenv("ELODEA_OIDC_REVIEWER_GROUPS", "grp-a, grp-b")
	t.Setenv("ELODEA_OIDC_IDENTITY_CLAIM", "preferred_username")
	t.Setenv("ELODEA_SESSION_IDLE_TTL", "30m")
	secretFile := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secretFile, []byte("from-file\n"), 0o600))
	t.Setenv("ELODEA_OIDC_CLIENT_SECRET_FILE", secretFile)

	cfg, err := Load("")
	require.NoError(t, err)
	assert.True(t, cfg.OIDC.Enabled())
	assert.Equal(t, "from-file", cfg.OIDC.ClientSecret)
	assert.Equal(t, []string{"grp-a", "grp-b"}, cfg.OIDC.ReviewerGroups)
	assert.Equal(t, "preferred_username", cfg.OIDC.IdentityClaim)
	assert.Equal(t, 30*time.Minute, cfg.OIDC.SessionIdleTTL)
}

func TestValidate_Notify(t *testing.T) {
	base := func() *Config {
		c := defaultConfig()
		c.TargetURL = "http://upstream.test"
		c.APIKeys = map[string]string{"agentkey": "agent"}
		c.ReviewerAPIKeys = map[string]string{"rvwkey": "jane"}
		return c
	}
	c := base()
	c.Notify = NotifyConfig{SlackWebhookURL: "https://hooks.slack.com/services/T/B/X", WebhookURL: "http://localhost:9000/hook"}
	require.NoError(t, c.Validate(), "plain http and unsigned webhooks are fine outside production")

	c = base()
	c.Notify.WebhookURL = "not a url"
	assert.Error(t, c.Validate())

	prod := func(c *Config) *Config {
		c.Environment = "production"
		c.TLSTerminatedUpstream = true
		c.PostgresDSN = "postgres://u:p@db.internal:5432/elodea?sslmode=require"
		c.AllowedOrigins = []string{"https://console.corp.test"}
		c.APIKeys = map[string]string{"agent-token-0123456789abcdef": "agent"}
		c.ReviewerAPIKeys = map[string]string{"reviewer-token-0123456789abcdef": "jane"}
		return c
	}
	c = prod(base())
	c.Notify.WebhookURL = "https://hooks.corp.test/elodea"
	assert.ErrorContains(t, c.Validate(), "ELODEA_NOTIFY_WEBHOOK_SECRET", "production webhooks must be signed")
	c.Notify.WebhookSecret = "whsec_0123456789abcdef01234567"
	assert.NoError(t, c.Validate())
	c.Notify.SlackWebhookURL = "http://hooks.slack.com/x"
	assert.ErrorContains(t, c.Validate(), "https")
}

func TestValidate_Slack(t *testing.T) {
	base := func() *Config {
		c := defaultConfig()
		c.TargetURL = "http://upstream.test"
		c.APIKeys = map[string]string{"agentkey": "agent"}
		c.ReviewerAPIKeys = map[string]string{"rvwkey": "jane"}
		c.Slack = SlackConfig{BotToken: "xoxb-1", SigningSecret: "s", ChannelID: "C1", Reviewers: []string{"priya@corp.test"}}
		return c
	}
	require.NoError(t, base().Validate())

	cases := map[string]func(*Config){
		"missing signing secret": func(c *Config) { c.Slack.SigningSecret = "" },
		"missing channel":        func(c *Config) { c.Slack.ChannelID = "" },
		"no reviewers":           func(c *Config) { c.Slack.Reviewers = nil },
		"reviewer not an email":  func(c *Config) { c.Slack.Reviewers = []string{"priya"} },
		"agent as reviewer": func(c *Config) {
			c.APIKeys = map[string]string{"agentkey": "bot@corp.test"}
			c.Slack.Reviewers = []string{"bot@corp.test"}
		},
		"partial setup": func(c *Config) { c.Slack = SlackConfig{ChannelID: "C1"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(c)
			assert.Error(t, c.Validate())
		})
	}

	c := base()
	c.Environment = "production"
	c.TLSTerminatedUpstream = true
	c.PostgresDSN = "postgres://u:p@db.internal:5432/elodea?sslmode=require"
	c.AllowedOrigins = []string{"https://console.corp.test"}
	c.APIKeys = map[string]string{"agent-token-0123456789abcdef": "agent"}
	c.ReviewerAPIKeys = map[string]string{"reviewer-token-0123456789abcdef": "jane"}
	assert.ErrorContains(t, c.Validate(), "team_id", "production pins the workspace")
	c.Slack.TeamID = "T0ELODEA"
	assert.NoError(t, c.Validate())
}
