package config

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr  string `yaml:"listen_addr"`
	TargetURL   string `yaml:"target_url"`
	PolicyDir   string `yaml:"policy_dir"`
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

	// HTTP server timeouts. ReadHeaderTimeout is the Slowloris defense
	// (CVE-2025-53634): it bounds the time to read the request headers only,
	// so a client dribbling bytes into the header block cannot pin a
	// connection (and its goroutine) open indefinitely.
	ReadTimeout         time.Duration `yaml:"read_timeout"`
	ReadHeaderTimeout   time.Duration `yaml:"read_header_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout"`
	IdleTimeout         time.Duration `yaml:"idle_timeout"`
	ShutdownDrainDelay  time.Duration `yaml:"shutdown_drain_delay"`
	MaxHeaderBytes      int           `yaml:"max_header_bytes"`
	MaxRequestBodyBytes int64         `yaml:"max_request_body_bytes"`

	// Postgres connection pool.
	PGMaxOpenConns    int           `yaml:"pg_max_open_conns"`
	PGMaxIdleConns    int           `yaml:"pg_max_idle_conns"`
	PGConnMaxLifetime time.Duration `yaml:"pg_conn_max_lifetime"`

	// Per-agent rate limiting (requests/second, token bucket).
	RateLimitRPS   float64 `yaml:"rate_limit_rps"`
	RateLimitBurst int     `yaml:"rate_limit_burst"`

	// Optional TLS termination for the ingress listener.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// TLSTerminatedUpstream declares that TLS is terminated in front of
	// Elodea (ingress controller, service mesh, identity-aware proxy), which
	// satisfies the production TLS requirement without a local certificate.
	TLSTerminatedUpstream bool `yaml:"tls_terminated_upstream"`

	// PolicyReloadInterval polls the policy directory and hot-reloads a
	// changed bundle; 0 disables polling (SIGHUP and the admin endpoint still
	// reload).
	PolicyReloadInterval time.Duration `yaml:"policy_reload_interval"`

	// MetricsListenAddr serves /metrics on a separate, internal-only listener
	// instead of the public ingress port.
	MetricsListenAddr string `yaml:"metrics_listen_addr"`

	// Credential presented to the upstream target on forwarded/replayed
	// requests. Loaded from ELODEA_TARGET_AUTH_TOKEN, never from YAML.
	TargetAuthToken string `yaml:"-"`

	// OIDC configures SSO sign-in for reviewers and admins. An empty issuer
	// disables it; static reviewer/admin keys keep working either way.
	OIDC OIDCConfig `yaml:"oidc"`

	// ConsoleURL is where reviewers open the console; notifications link to
	// its approvals queue.
	ConsoleURL string `yaml:"console_url"`

	// Notify sends held-action notifications to Slack and/or a webhook.
	Notify NotifyConfig `yaml:"notify"`

	// LegacyEnv lists the pre-rename KITERAIL_* variables that were applied,
	// so startup can warn about them. Never read from YAML.
	LegacyEnv []string `yaml:"-"`
}

// OIDCConfig is the SSO configuration. Roles come from IdP groups: a user in
// an admin group is an admin, otherwise a user in a reviewer group is a
// reviewer, otherwise sign-in is refused.
type OIDCConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"-"` // ELODEA_OIDC_CLIENT_SECRET(_FILE) only
	RedirectURL  string `yaml:"redirect_url"`
	// ProviderName labels the console's sign-in button ("Okta", "Entra ID").
	ProviderName string `yaml:"provider_name"`
	// GroupsClaim names the ID-token claim listing the user's groups.
	GroupsClaim string `yaml:"groups_claim"`
	// IdentityClaim names the claim recorded as the reviewer's identity.
	// "email" (the default) also requires email_verified to be true.
	IdentityClaim string `yaml:"identity_claim"`
	// Scopes requested at sign-in. Okta and Dex need "groups" added; Entra
	// ID emits groups through app configuration instead.
	Scopes         []string `yaml:"scopes"`
	ReviewerGroups []string `yaml:"reviewer_groups"`
	AdminGroups    []string `yaml:"admin_groups"`
	// SessionTTL bounds a session's total life; SessionIdleTTL ends it after
	// inactivity. Removing someone from the IdP takes effect within these.
	SessionTTL     time.Duration `yaml:"session_ttl"`
	SessionIdleTTL time.Duration `yaml:"session_idle_ttl"`
	// CookieSameSite is lax (default), strict, or none (console on another site).
	CookieSameSite string `yaml:"cookie_same_site"`
}

// NotifyConfig configures held-action notifications. Webhook URLs and
// secrets are credentials, so they come from the environment or files only.
type NotifyConfig struct {
	SlackWebhookURL string `yaml:"-"` // ELODEA_NOTIFY_SLACK_WEBHOOK_URL(_FILE)
	WebhookURL      string `yaml:"webhook_url"`
	WebhookSecret   string `yaml:"-"` // ELODEA_NOTIFY_WEBHOOK_SECRET(_FILE)
}

// Enabled reports whether SSO is configured.
func (o OIDCConfig) Enabled() bool { return o.Issuer != "" }

// SecureCookies reports whether session cookies must be Secure, which is
// whenever the IdP redirects back over https.
func (o OIDCConfig) SecureCookies() bool { return strings.HasPrefix(o.RedirectURL, "https://") }

func (o OIDCConfig) anySet() bool {
	return o.Issuer != "" || o.ClientID != "" || o.ClientSecret != "" || o.RedirectURL != "" ||
		len(o.ReviewerGroups) > 0 || len(o.AdminGroups) > 0
}

// legacyEnvPrefix is the environment prefix used before the product was
// renamed to Elodea. It is still honoured so existing deployments keep
// working; when both names are set, ELODEA_* wins.
const legacyEnvPrefix = "KITERAIL_"

// ApplyLegacyEnv copies each KITERAIL_* variable to its ELODEA_* name when
// the new name is unset, and returns the legacy names it applied.
func ApplyLegacyEnv() []string {
	var used []string
	for _, kv := range os.Environ() {
		name, val, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(strings.ToUpper(name), legacyEnvPrefix) {
			continue
		}
		next := "ELODEA_" + name[len(legacyEnvPrefix):]
		if _, set := os.LookupEnv(next); set {
			continue
		}
		if err := os.Setenv(next, val); err == nil {
			used = append(used, name)
		}
	}
	slices.Sort(used)
	return used
}

const (
	defaultReadTimeout        = 10 * time.Second
	defaultReadHeaderTimeout  = 5 * time.Second
	defaultWriteTimeout       = 30 * time.Second
	defaultIdleTimeout        = 120 * time.Second
	defaultShutdownDrainDelay = 5 * time.Second
)

func defaultConfig() *Config {
	return &Config{
		ListenAddr:           ":8080",
		PolicyDir:            "./policies",
		PostgresDSN:          "postgres://elodea:elodea@localhost:5432/elodea?sslmode=disable",
		LogLevel:             "info",
		APIKeys:              make(map[string]string),
		ReviewerAPIKeys:      make(map[string]string),
		AdminAPIKeys:         make(map[string]string),
		AllowedOrigins:       []string{"*"},
		Environment:          "development",
		ReadTimeout:          defaultReadTimeout,
		ReadHeaderTimeout:    defaultReadHeaderTimeout,
		WriteTimeout:         defaultWriteTimeout,
		IdleTimeout:          defaultIdleTimeout,
		ShutdownDrainDelay:   defaultShutdownDrainDelay,
		MaxHeaderBytes:       http.DefaultMaxHeaderBytes,
		MaxRequestBodyBytes:  1 << 20,
		PGMaxOpenConns:       25,
		PGMaxIdleConns:       5,
		PGConnMaxLifetime:    30 * time.Minute,
		RateLimitRPS:         10,
		RateLimitBurst:       20,
		PolicyReloadInterval: 30 * time.Second,
	}
}

// validateOIDC checks the SSO settings. A half-configured SSO setup is an
// error rather than silently disabled, so a typo cannot leave reviewers with
// only shared tokens.
func (c *Config) validateOIDC() error {
	o := c.OIDC
	if !o.anySet() {
		return nil
	}
	if !o.Enabled() {
		return fmt.Errorf("oidc: issuer must be set when any other oidc setting is")
	}
	if o.ClientID == "" || o.ClientSecret == "" || o.RedirectURL == "" {
		return fmt.Errorf("oidc: client_id, client secret (ELODEA_OIDC_CLIENT_SECRET or _FILE), and redirect_url are required")
	}
	for name, raw := range map[string]string{"issuer": o.Issuer, "redirect_url": o.RedirectURL} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("oidc: %s must be an absolute http(s) URL", name)
		}
		if c.Environment == "production" && u.Scheme != "https" {
			return fmt.Errorf("oidc: %s must use https in production", name)
		}
	}
	if len(o.ReviewerGroups)+len(o.AdminGroups) == 0 {
		return fmt.Errorf("oidc: set reviewer_groups and/or admin_groups; without them no one can be given a role")
	}
	switch strings.ToLower(o.CookieSameSite) {
	case "", "lax", "strict":
	case "none":
		if !o.SecureCookies() {
			return fmt.Errorf("oidc: cookie_same_site none requires an https redirect_url")
		}
	default:
		return fmt.Errorf("oidc: cookie_same_site must be lax, strict, or none")
	}
	explicit := false
	for _, origin := range c.AllowedOrigins {
		if origin != "*" && origin != "" {
			explicit = true
		}
	}
	if !explicit {
		return fmt.Errorf("oidc: allowed_origins must list the console's origin; sign-in only returns to an allowed origin")
	}
	return nil
}

// validateNotify checks notification endpoints. In production they must use
// HTTPS, and a generic webhook must be signed so its receiver can tell a real
// Elodea event from a forged one.
func (c *Config) validateNotify() error {
	for name, raw := range map[string]string{
		"console_url":              c.ConsoleURL,
		"notify slack webhook url": c.Notify.SlackWebhookURL,
		"notify.webhook_url":       c.Notify.WebhookURL,
	} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s must be an absolute http(s) URL", name)
		}
		if c.Environment == "production" && u.Scheme != "https" {
			return fmt.Errorf("%s must use https in production", name)
		}
	}
	if c.Environment == "production" && c.Notify.WebhookURL != "" && len(c.Notify.WebhookSecret) < minProductionTokenBytes {
		return fmt.Errorf("notify.webhook_url requires ELODEA_NOTIFY_WEBHOOK_SECRET of at least %d bytes in production, so receivers can verify events", minProductionTokenBytes)
	}
	return nil
}

// minProductionTokenBytes is the shortest bearer token accepted in production.
const minProductionTokenBytes = 24

// Load loads the configuration from the specified file or environment variables.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()
	cfg.LegacyEnv = ApplyLegacyEnv()

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

	setStringEnv(cfg, "ELODEA_LISTEN_ADDR", &cfg.ListenAddr)
	setStringEnv(cfg, "ELODEA_TARGET_URL", &cfg.TargetURL)
	setStringEnv(cfg, "ELODEA_POLICY_DIR", &cfg.PolicyDir)
	setStringEnv(cfg, "ELODEA_POSTGRES_DSN", &cfg.PostgresDSN)
	setStringEnv(cfg, "ELODEA_LOG_LEVEL", &cfg.LogLevel)
	setStringEnv(cfg, "ELODEA_ENVIRONMENT", &cfg.Environment)
	setStringEnv(cfg, "ELODEA_METRICS_LISTEN_ADDR", &cfg.MetricsListenAddr)
	if val := os.Getenv("ELODEA_POLICY_RELOAD_INTERVAL"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, fmt.Errorf("ELODEA_POLICY_RELOAD_INTERVAL: %w", err)
		}
		cfg.PolicyReloadInterval = d
	}
	if val := os.Getenv("ELODEA_TLS_TERMINATED_UPSTREAM"); val != "" {
		b, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("ELODEA_TLS_TERMINATED_UPSTREAM: %w", err)
		}
		cfg.TLSTerminatedUpstream = b
	}

	if val := os.Getenv("ELODEA_TARGET_AUTH_TOKEN"); val != "" {
		cfg.TargetAuthToken = val
	}

	setStringEnv(cfg, "ELODEA_CONSOLE_URL", &cfg.ConsoleURL)
	setStringEnv(cfg, "ELODEA_NOTIFY_SLACK_WEBHOOK_URL", &cfg.Notify.SlackWebhookURL)
	setStringEnv(cfg, "ELODEA_NOTIFY_WEBHOOK_URL", &cfg.Notify.WebhookURL)
	setStringEnv(cfg, "ELODEA_NOTIFY_WEBHOOK_SECRET", &cfg.Notify.WebhookSecret)

	setStringEnv(cfg, "ELODEA_OIDC_ISSUER", &cfg.OIDC.Issuer)
	setStringEnv(cfg, "ELODEA_OIDC_CLIENT_ID", &cfg.OIDC.ClientID)
	setStringEnv(cfg, "ELODEA_OIDC_CLIENT_SECRET", &cfg.OIDC.ClientSecret)
	setStringEnv(cfg, "ELODEA_OIDC_REDIRECT_URL", &cfg.OIDC.RedirectURL)
	setStringEnv(cfg, "ELODEA_OIDC_PROVIDER_NAME", &cfg.OIDC.ProviderName)
	setStringEnv(cfg, "ELODEA_OIDC_GROUPS_CLAIM", &cfg.OIDC.GroupsClaim)
	setStringEnv(cfg, "ELODEA_OIDC_IDENTITY_CLAIM", &cfg.OIDC.IdentityClaim)
	setStringEnv(cfg, "ELODEA_SESSION_COOKIE_SAMESITE", &cfg.OIDC.CookieSameSite)
	setListEnv("ELODEA_OIDC_REVIEWER_GROUPS", &cfg.OIDC.ReviewerGroups)
	setListEnv("ELODEA_OIDC_ADMIN_GROUPS", &cfg.OIDC.AdminGroups)
	setListEnv("ELODEA_OIDC_SCOPES", &cfg.OIDC.Scopes)
	for key, dst := range map[string]*time.Duration{
		"ELODEA_SESSION_TTL":      &cfg.OIDC.SessionTTL,
		"ELODEA_SESSION_IDLE_TTL": &cfg.OIDC.SessionIdleTTL,
	} {
		if val := os.Getenv(key); val != "" {
			d, err := time.ParseDuration(val)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			*dst = d
		}
	}

	// *_FILE variants read secrets from mounted files (Kubernetes secrets,
	// Vault agent, Docker secrets) so they never appear in the environment.
	for key, dst := range map[string]*string{
		"ELODEA_POSTGRES_DSN_FILE":             &cfg.PostgresDSN,
		"ELODEA_TARGET_AUTH_TOKEN_FILE":        &cfg.TargetAuthToken,
		"ELODEA_OIDC_CLIENT_SECRET_FILE":       &cfg.OIDC.ClientSecret,
		"ELODEA_NOTIFY_SLACK_WEBHOOK_URL_FILE": &cfg.Notify.SlackWebhookURL,
		"ELODEA_NOTIFY_WEBHOOK_SECRET_FILE":    &cfg.Notify.WebhookSecret,
	} {
		if err := setFromFile(key, dst); err != nil {
			return nil, err
		}
	}
	for key, dst := range map[string]map[string]string{
		"ELODEA_API_KEYS_FILE":          cfg.APIKeys,
		"ELODEA_REVIEWER_API_KEYS_FILE": cfg.ReviewerAPIKeys,
		"ELODEA_ADMIN_API_KEYS_FILE":    cfg.AdminAPIKeys,
	} {
		var pairs string
		if err := setFromFile(key, &pairs); err != nil {
			return nil, err
		}
		loadKeyPairs(strings.ReplaceAll(pairs, "\n", ","), dst)
	}

	setListEnv("ELODEA_ALLOWED_ORIGINS", &cfg.AllowedOrigins)
	loadKeyPairs(os.Getenv("ELODEA_API_KEYS"), cfg.APIKeys)
	loadKeyPairs(os.Getenv("ELODEA_REVIEWER_API_KEYS"), cfg.ReviewerAPIKeys)
	loadKeyPairs(os.Getenv("ELODEA_ADMIN_API_KEYS"), cfg.AdminAPIKeys)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// setFromFile reads the file named by env var key, trimming surrounding
// whitespace. An unreadable file is an error, never a silent fallback.
func setFromFile(key string, dst *string) error {
	path := os.Getenv(key)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = strings.TrimSpace(string(data))
	return nil
}

// setListEnv reads a comma-separated list, trimming each entry.
func setListEnv(key string, dst *[]string) {
	val := os.Getenv(key)
	if val == "" {
		return
	}
	items := strings.Split(val, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}
	*dst = items
}

func setStringEnv(_ *Config, key string, dst *string) {
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
// Environment == "production" unless ELODEA_ALLOW_DEV_CREDENTIALS=1 is
// explicitly set (never recommended).
func (c *Config) Validate() error {
	if c.TargetURL == "" {
		return fmt.Errorf("target_url must be set")
	}
	if target, err := url.Parse(c.TargetURL); err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return fmt.Errorf("target_url must be an absolute http(s) URL")
	}
	switch strings.ToLower(c.LogLevel) {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be one of debug, info, warn, error")
	}
	if c.PolicyReloadInterval < 0 {
		return fmt.Errorf("policy_reload_interval must not be negative")
	}
	if len(c.APIKeys) == 0 {
		return fmt.Errorf("at least one agent api key must be configured")
	}
	if len(c.ReviewerAPIKeys)+len(c.AdminAPIKeys) == 0 && !c.OIDC.Enabled() {
		return fmt.Errorf("at least one reviewer or admin key, or SSO (oidc), must be configured — agents must not be able to approve their own quarantined actions")
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	if err := c.validateNotify(); err != nil {
		return err
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

	// Separation of duties: an identity that acts as an agent must never also
	// review, or it could approve its own quarantined actions.
	agentIDs := make(map[string]bool, len(c.APIKeys))
	for _, id := range c.APIKeys {
		agentIDs[id] = true
	}
	for _, keys := range []map[string]string{c.ReviewerAPIKeys, c.AdminAPIKeys} {
		for _, id := range keys {
			if agentIDs[id] {
				return fmt.Errorf("identity %q is configured as both an agent and a reviewer/admin — separation of duties requires distinct identities", id)
			}
		}
	}

	if c.Environment == "production" {
		if slices.Contains(c.AllowedOrigins, "*") {
			return fmt.Errorf("production must not use wildcard allowed_origins")
		}
	}

	if c.Environment == "production" && os.Getenv("ELODEA_ALLOW_DEV_CREDENTIALS") != "1" {
		for _, dsn := range []string{c.PostgresDSN} {
			if strings.Contains(dsn, "sslmode=disable") && strings.Contains(dsn, "localhost") {
				return fmt.Errorf("refusing production start with local/no-TLS postgres DSN; set ELODEA_ALLOW_DEV_CREDENTIALS=1 to override")
			}
		}
		for tok := range c.APIKeys {
			if strings.HasPrefix(tok, "sk_dev_") {
				return fmt.Errorf("refusing production start with development credential prefix sk_dev_; set ELODEA_ALLOW_DEV_CREDENTIALS=1 to override")
			}
		}
		for _, keys := range []map[string]string{c.APIKeys, c.ReviewerAPIKeys, c.AdminAPIKeys} {
			for tok, id := range keys {
				if len(tok) < minProductionTokenBytes {
					return fmt.Errorf("token for %q is shorter than %d bytes; use a high-entropy secret in production", id, minProductionTokenBytes)
				}
			}
		}
		if (c.TLSCertFile == "" || c.TLSKeyFile == "") && !c.TLSTerminatedUpstream {
			return fmt.Errorf("production requires tls_cert_file/tls_key_file, or tls_terminated_upstream: true when TLS is terminated in front of Elodea")
		}
	}

	if c.MaxRequestBodyBytes <= 0 {
		c.MaxRequestBodyBytes = 1 << 20
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = defaultReadTimeout
	}
	if c.ReadHeaderTimeout <= 0 {
		c.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = defaultWriteTimeout
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	if c.ShutdownDrainDelay <= 0 {
		c.ShutdownDrainDelay = defaultShutdownDrainDelay
	}
	if c.OIDC.Enabled() {
		if c.OIDC.GroupsClaim == "" {
			c.OIDC.GroupsClaim = "groups"
		}
		if c.OIDC.IdentityClaim == "" {
			c.OIDC.IdentityClaim = "email"
		}
		if c.OIDC.SessionTTL <= 0 {
			c.OIDC.SessionTTL = 8 * time.Hour
		}
		if c.OIDC.SessionIdleTTL <= 0 {
			c.OIDC.SessionIdleTTL = time.Hour
		}
		if c.OIDC.SessionIdleTTL > c.OIDC.SessionTTL {
			return fmt.Errorf("session_idle_ttl must not exceed session_ttl")
		}
		if c.OIDC.ProviderName == "" {
			c.OIDC.ProviderName = "SSO"
		}
		if len(c.OIDC.Scopes) == 0 {
			c.OIDC.Scopes = []string{"openid", "email", "profile"}
		}
		if !slices.Contains(c.OIDC.Scopes, "openid") {
			c.OIDC.Scopes = append([]string{"openid"}, c.OIDC.Scopes...)
		}
	}
	if c.PGMaxOpenConns > 0 && c.PGMaxOpenConns < 2 {
		return fmt.Errorf("pg_max_open_conns must be at least 2: the replay advisory-lock connection must not starve normal database work")
	}
	return nil
}
