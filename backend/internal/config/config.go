package config

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr  string `yaml:"listen_addr"`
	TargetURL   string `yaml:"target_url"`
	PolicyDir   string `yaml:"policy_dir"`
	NatsURL     string `yaml:"nats_url"`
	PostgresDSN string `yaml:"postgres_dsn"`
	LogLevel    string `yaml:"log_level"`

	// APIKeys maps agent bearer tokens to agent IDs (machine trust domain).
	APIKeys map[string]string `yaml:"api_keys"`
	// ReviewerAPIKeys maps human reviewer tokens to reviewer IDs.
	// Reviewers can approve quarantined actions and read the ledger/dashboard.
	ReviewerAPIKeys map[string]string `yaml:"reviewer_api_keys"`
	// AdminAPIKeys maps admin tokens to admin IDs (policy mutation).
	AdminAPIKeys map[string]string `yaml:"admin_api_keys"`

	AllowedOrigins []string `yaml:"allowed_origins"`

	// Environment: "production" enables strict startup validation.
	Environment string `yaml:"environment"`

	// HTTP server timeouts.
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	MaxHeaderBytes    int           `yaml:"max_header_bytes"`
	MaxRequestBodyBytes int64       `yaml:"max_request_body_bytes"`

	// Postgres connection pool.
	PGMaxOpenConns     int           `yaml:"pg_max_open_conns"`
	PGMaxIdleConns     int           `yaml:"pg_max_idle_conns"`
	PGConnMaxLifetime  time.Duration `yaml:"pg_conn_max_lifetime"`

	// Per-agent rate limiting (requests/second, token bucket).
	RateLimitRPS   float64 `yaml:"rate_limit_rps"`
	RateLimitBurst int     `yaml:"rate_limit_burst"`

	// Optional TLS termination for the ingress listener.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	// Credential presented to the upstream target on forwarded/replayed
	// requests. Loaded from KITERAIL_TARGET_AUTH_TOKEN, never from YAML.
	TargetAuthToken string `yaml:"-"`
}

const (
	defaultReadTimeout  = 10 * time.Second
	defaultWriteTimeout = 30 * time.Second
	defaultIdleTimeout  = 120 * time.Second
)

func defaultConfig() *Config {
	return &Config{
		ListenAddr:          ":8080",
		PolicyDir:           "./policies",
		NatsURL:             "nats://localhost:4222",
		PostgresDSN:         "postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable",
		LogLevel:            "info",
		APIKeys:             make(map[string]string),
		ReviewerAPIKeys:     make(map[string]string),
		AdminAPIKeys:        make(map[string]string),
		AllowedOrigins:      []string{"*"},
		Environment:         "development",
		ReadTimeout:         defaultReadTimeout,
		WriteTimeout:        defaultWriteTimeout,
		IdleTimeout:         defaultIdleTimeout,
		MaxHeaderBytes:      http.DefaultMaxHeaderBytes,
		MaxRequestBodyBytes: 1 << 20,
		PGMaxOpenConns:      25,
		PGMaxIdleConns:      5,
		PGConnMaxLifetime:   30 * time.Minute,
		RateLimitRPS:        10,
		RateLimitBurst:      20,
	}
}

// Load loads the configuration from the specified file or environment variables.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}
	if cfg.APIKeys == nil {
		cfg.APIKeys = make(map[string]string)
	}
	if cfg.ReviewerAPIKeys == nil {
		cfg.ReviewerAPIKeys = make(map[string]string)
	}
	if cfg.AdminAPIKeys == nil {
		cfg.AdminAPIKeys = make(map[string]string)
	}

	setStringEnv(cfg, "KITERAIL_LISTEN_ADDR", &cfg.ListenAddr)
	setStringEnv(cfg, "KITERAIL_TARGET_URL", &cfg.TargetURL)
	setStringEnv(cfg, "KITERAIL_POLICY_DIR", &cfg.PolicyDir)
	setStringEnv(cfg, "KITERAIL_NATS_URL", &cfg.NatsURL)
	setStringEnv(cfg, "KITERAIL_POSTGRES_DSN", &cfg.PostgresDSN)
	setStringEnv(cfg, "KITERAIL_LOG_LEVEL", &cfg.LogLevel)
	setStringEnv(cfg, "KITERAIL_ENVIRONMENT", &cfg.Environment)

	if val := os.Getenv("KITERAIL_TARGET_AUTH_TOKEN"); val != "" {
		cfg.TargetAuthToken = val
	}

	if val := os.Getenv("KITERAIL_ALLOWED_ORIGINS"); val != "" {
		origins := strings.Split(val, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		cfg.AllowedOrigins = origins
	}
	loadKeyPairs(os.Getenv("KITERAIL_API_KEYS"), cfg.APIKeys)
	loadKeyPairs(os.Getenv("KITERAIL_REVIEWER_API_KEYS"), cfg.ReviewerAPIKeys)
	loadKeyPairs(os.Getenv("KITERAIL_ADMIN_API_KEYS"), cfg.AdminAPIKeys)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func setStringEnv(cfg *Config, key string, dst *string) {
	if val := os.Getenv(key); val != "" {
		*dst = val
	}
}

func loadKeyPairs(val string, dst map[string]string) {
	if val == "" {
		return
	}
	for _, pair := range strings.Split(val, ",") {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			dst[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
}

// Validate rejects configurations that are unsafe to run, especially in
// production. Development credentials are hard-failed when
// Environment == "production" unless KITERAIL_ALLOW_DEV_CREDENTIALS=1 is
// explicitly set (never recommended).
func (c *Config) Validate() error {
	if c.TargetURL == "" {
		return fmt.Errorf("target_url must be set")
	}
	if len(c.APIKeys) == 0 {
		return fmt.Errorf("at least one agent api key must be configured")
	}
	if len(c.ReviewerAPIKeys)+len(c.AdminAPIKeys) == 0 {
		return fmt.Errorf("at least one reviewer or admin key must be configured — agents must not be able to approve their own quarantined actions")
	}

	seen := make(map[string]string) // token -> first owner, for cross-role collision detection
	for tok, id := range c.APIKeys {
		seen[tok] = "agent:" + id
	}
	for role, keys := range map[string]map[string]string{
		"reviewer": c.ReviewerAPIKeys,
		"admin":    c.AdminAPIKeys,
	} {
		for tok, id := range keys {
			if owner, clash := seen[tok]; clash {
				return fmt.Errorf("%s key for %s duplicates %s — trust domains must not share credentials", role, id, owner)
			}
			seen[tok] = role + ":" + id
		}
	}

	if c.Environment == "production" && os.Getenv("KITERAIL_ALLOW_DEV_CREDENTIALS") != "1" {
		for _, dsn := range []string{c.PostgresDSN} {
			if strings.Contains(dsn, "sslmode=disable") && strings.Contains(dsn, "localhost") {
				return fmt.Errorf("refusing production start with local/no-TLS postgres DSN; set KITERAIL_ALLOW_DEV_CREDENTIALS=1 to override")
			}
		}
		for tok := range c.APIKeys {
			if strings.HasPrefix(tok, "sk_dev_") {
				return fmt.Errorf("refusing production start with development credential prefix sk_dev_; set KITERAIL_ALLOW_DEV_CREDENTIALS=1 to override")
			}
		}
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return fmt.Errorf("production requires tls_cert_file/tls_key_file (or terminate TLS in an identity-aware proxy in front of KiteRail)")
		}
	}

	if c.MaxRequestBodyBytes <= 0 {
		c.MaxRequestBodyBytes = 1 << 20
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = defaultReadTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = defaultWriteTimeout
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	return nil
}
