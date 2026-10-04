package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/config"
	"github.com/austinchima/kiterail/internal/dashboard"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/metrics"
	"github.com/austinchima/kiterail/internal/notify"
	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/policystore"
	"github.com/austinchima/kiterail/internal/proxy"
	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/austinchima/kiterail/internal/slackapp"
	"github.com/austinchima/kiterail/internal/sso"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var (
	version   = "2.0.0-dev"
	startTime = time.Now()
)

func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && !originAllowed(origin, allowedOrigins) {
				http.Error(w, `{"error":"origin is not allowed"}`, http.StatusForbidden)
				return
			}
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				// Session cookies ride along only for an explicitly listed
				// origin, never one admitted by the development wildcard.
				if slices.Contains(allowedOrigins, origin) {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+auth.CSRFHeader)
			w.Header().Set("Access-Control-Expose-Headers", "X-Next-Before, X-Elodea-Policy-Version")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// originAllowed compares origins exactly. CORS origins are serialized URLs,
// not host suffixes: a suffix match would allow an attacker-controlled domain
// such as trusted.example.evil. The wildcard is development-only and is
// rejected by Config.Validate in production.
func originAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// rateLimiterMiddleware enforces a per-identity token bucket.
type rateLimiter struct {
	mu    sync.Mutex
	lim   map[string]*rate.Limiter
	rps   float64
	burst int
}

func newRateLimiter(rps float64, burst int) *rateLimiter {
	return &rateLimiter{lim: make(map[string]*rate.Limiter), rps: rps, burst: burst}
}

func (rl *rateLimiter) get(id string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	l, ok := rl.lim[id]
	if !ok {
		l = rate.NewLimiter(rate.Limit(rl.rps), rl.burst)
		rl.lim[id] = l
	}
	return l
}

// middleware enforces a per-identity token bucket keyed by the authenticated
// identity. Requests without one fail closed: silently skipping the limit
// would turn any future middleware-ordering mistake into an open relay.
func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := auth.FromContext(r.Context())
		if !ok {
			http.Error(w, `{"error": "authenticated identity required for rate limiting"}`, http.StatusInternalServerError)
			return
		}
		if !rl.get(identity.ID).Allow() {
			http.Error(w, `{"error": "rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		metrics.HTTPRequestsTotal.Inc()
		next.ServeHTTP(w, r)
		metrics.HTTPRequestDuration.Observe(time.Since(start).Seconds())
	})
}

// drainMiddleware rejects new protected requests after readiness flips false.
// It intentionally sits before authentication: the process is no longer an
// ingress target, and spending work authenticating traffic during shutdown
// extends the very drain window that protects in-flight requests.
func drainMiddleware(ready *atomic.Bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ready == nil || !ready.Load() {
				http.Error(w, `{"error":"server is draining"}`, http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// httpDeps carries the collaborators needed to assemble the HTTP surface.
// It exists so integration tests can wire fakes without Postgres or an upstream.
type httpDeps struct {
	version        string
	startTime      time.Time
	dbConn         *sql.DB
	proxy          http.Handler
	quarantine     http.Handler
	ledger         http.Handler
	policy         http.Handler
	dashboard      http.Handler
	identities     map[string]auth.Identity
	rateLimitRPS   float64
	rateLimitBurst int
	allowedOrigins []string

	// ready gates /readyz: true once the process finished startup wiring and
	// flipped to false at the first sign of shutdown (SIGTERM), so an
	// orchestrator stops routing NEW traffic before the listener drains.
	ready *atomic.Bool

	// policyReady reports whether the active OPA query contains Elodea's
	// authorization entry point. A nil function is used only by focused HTTP
	// tests that do not construct an engine.
	policyReady func() bool

	// policyVersion reports the active policy bundle fingerprint for /readyz.
	policyVersion func() string

	// slack receives Slack's interactivity requests (approve/deny buttons);
	// nil when the Slack app is not configured. It authenticates each request
	// by Slack's signature, not by a bearer token.
	slack http.Handler

	// sso serves SSO sign-in and resolves session cookies; nil when SSO is
	// not configured, leaving bearer tokens as the only human credential.
	sso ssoProvider

	// metricsOnSeparateListener removes /metrics from the public mux because
	// it is served on an internal-only listener instead.
	metricsOnSeparateListener bool
}

// slackHandler avoids storing a typed nil *slackapp.App in an http.Handler.
func slackHandler(app *slackapp.App) http.Handler {
	if app == nil {
		return nil
	}
	return app
}

// ssoProvider is the part of *sso.Service the HTTP layer uses.
type ssoProvider interface {
	auth.SessionAuthenticator
	Routes() http.Handler
	ConfigHandler() http.Handler
}

// buildHTTPHandler wires three trust domains, each with its own explicit
// middleware stack so authorization is visible at every route registration:
//
//	public — metrics → CORS (health/readiness/Prometheus stay unauthenticated)
//	agent  — metrics → CORS → auth → RequireRole(agent) → per-agent rate limit
//	human  — metrics → CORS → auth → RequireRole(reviewer|admin)
//
// Authentication always precedes the rate limiter, so buckets key off the
// authenticated identity from the validated Bearer token — never client-
// controlled input such as X-Agent-ID, query parameters or request bodies.
func buildHTTPHandler(d httpDeps, logger *zap.Logger) http.Handler {
	limiter := newRateLimiter(d.rateLimitRPS, d.rateLimitBurst)

	publicChain := func(next http.Handler) http.Handler {
		return prometheusMiddleware(corsMiddleware(d.allowedOrigins)(next))
	}
	agentChain := func(next http.Handler) http.Handler {
		guarded := auth.RequireRole(auth.RoleAgent)(next)
		limited := limiter.middleware(guarded)
		authenticated := auth.Middleware(d.identities, logger, limited)
		return prometheusMiddleware(corsMiddleware(d.allowedOrigins)(drainMiddleware(d.ready)(authenticated)))
	}
	var sessions auth.SessionAuthenticator
	if d.sso != nil {
		sessions = d.sso
	}
	allowOrigin := func(origin string) bool { return originAllowed(origin, d.allowedOrigins) }
	humanChain := func(next http.Handler) http.Handler {
		guarded := auth.ReviewerOrAdmin()(next)
		authenticated := auth.HumanMiddleware(d.identities, sessions, allowOrigin, logger, guarded)
		return prometheusMiddleware(corsMiddleware(d.allowedOrigins)(drainMiddleware(d.ready)(authenticated)))
	}

	mux := http.NewServeMux()

	// --- Liveness vs Readiness ---
	// /api/v1/health: process alive ONLY (never pings the DB, never touches
	// dependencies — a wedged DB must NOT get the process killed and
	// rescheduled by a liveness probe).
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "ok",
			"version":        d.version,
			"uptime_seconds": time.Since(d.startTime).Seconds(),
		})
	})
	// /readyz: 503 while draining (SIGTERM), when Postgres does not answer, or
	// when OPA has no compiled authorization entry point. An empty policy
	// directory fails closed during request handling, but it is not healthy to
	// advertise that replica as ready to receive production traffic.
	readyzHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !d.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{"ready": false, "draining": true})
			return
		}
		if d.policyReady != nil && !d.policyReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{"ready": false, "policy": false})
			return
		}
		pingCtx, pingCancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer pingCancel()
		if err := d.dbConn.PingContext(pingCtx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{"ready": false, "postgres": false})
			return
		}
		body := map[string]interface{}{"ready": true, "postgres": true}
		if d.policyVersion != nil {
			body["policy_version"] = d.policyVersion()
		}
		json.NewEncoder(w).Encode(body)
	})

	mux.Handle("/api/v1/health", publicChain(healthHandler))

	// --- Slack interactivity (authenticated by Slack's request signature) ---
	if d.slack != nil {
		mux.Handle("/integrations/slack/interactions", publicChain(drainMiddleware(d.ready)(d.slack)))
	}

	// --- SSO sign-in (browser redirects; no prior authentication) ---
	if d.sso != nil {
		mux.Handle("/auth/", publicChain(d.sso.Routes()))
		mux.Handle("/api/v1/auth/config", publicChain(d.sso.ConfigHandler()))
	} else {
		mux.Handle("/api/v1/auth/config", publicChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sso":false}`))
		})))
	}
	mux.Handle("/readyz", publicChain(readyzHandler))

	// --- Human trust domain (reviewer/admin only) ---
	mux.Handle("/api/v1/quarantine", humanChain(http.StripPrefix("/api/v1/quarantine", d.quarantine)))
	mux.Handle("/api/v1/quarantine/", humanChain(http.StripPrefix("/api/v1/quarantine", d.quarantine)))

	mux.Handle("/api/v1/ledger", humanChain(http.StripPrefix("/api/v1/ledger", d.ledger)))
	mux.Handle("/api/v1/ledger/", humanChain(http.StripPrefix("/api/v1/ledger", d.ledger)))

	mux.Handle("/api/v1/policies", humanChain(http.StripPrefix("/api/v1/policies", d.policy)))
	mux.Handle("/api/v1/policies/", humanChain(http.StripPrefix("/api/v1/policies", d.policy)))

	mux.Handle("/api/v1/dashboard/stats", humanChain(d.dashboard))

	// Who am I: lets a reviewer console show the authenticated identity and
	// gate admin-only actions without parsing tokens client-side.
	mux.Handle("/api/v1/me", humanChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := auth.FromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": identity.ID, "role": string(identity.Role)})
	})))

	// --- Machine trust domain (agents): POST / only; the proxy rejects other methods ---
	mux.Handle("/", agentChain(d.proxy))

	// /metrics is public for Prometheus scraping inside the trust boundary,
	// unless an internal-only metrics listener is configured.
	if !d.metricsOnSeparateListener {
		mux.Handle("/metrics", publicChain(promhttp.Handler()))
	}

	return mux
}

func main() {
	configPath := flag.String("config", "", "Path to config file")
	port := flag.String("port", "", "Override listen address")
	healthcheck := flag.Bool("healthcheck", false, "Probe the local liveness endpoint and exit 0/1 (for container HEALTHCHECK in shell-less images)")
	flag.Parse()

	if *healthcheck {
		config.ApplyLegacyEnv()
		os.Exit(runHealthcheck())
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	if *port != "" {
		cfg.ListenAddr = *port
	}

	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting Elodea", zap.String("version", version), zap.String("environment", cfg.Environment))
	if len(cfg.LegacyEnv) > 0 {
		logger.Warn("KITERAIL_* environment variables are deprecated; rename them to ELODEA_*", zap.Strings("variables", cfg.LegacyEnv))
	}
	metrics.BuildInfo.WithLabelValues(version).Set(1)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	dbConn, err := connectPostgres(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to connect to postgres", zap.Error(err))
	}
	defer func() { _ = dbConn.Close() }()

	// Apply versioned schema migrations before anything touches the DB.
	if err := db.Migrate(ctx, dbConn); err != nil {
		logger.Fatal("Failed to apply database migrations", zap.Error(err))
	}

	// Event-bus publishing (NATS) was deleted in Phase 4: it was orphaned
	// code with zero production value — main has always wired NoOpPublisher
	// and every audit event goes straight to the Postgres ledger. All audit
	// events are written directly to the Postgres ledger.
	engine, err := opaengine.New(ctx, cfg.PolicyDir, logger)
	if err != nil {
		logger.Fatal("Failed to initialise OPA engine", zap.Error(err))
	}
	logger.Info("Policy bundle loaded", zap.String("policy_version", engine.Version()), zap.Bool("ready", engine.Ready()))

	// Hot reload: SIGHUP and (optionally) polling apply a newly deployed
	// bundle without a restart. A bundle that fails to compile is rejected and
	// the previous policy keeps enforcing.
	go reloadOnSignal(ctx, engine, logger)
	if cfg.PolicyReloadInterval > 0 {
		go engine.WatchForChanges(ctx, cfg.PolicyReloadInterval)
	}

	qStore, err := quarantine.New(dbConn)
	if err != nil {
		logger.Fatal("Failed to initialise quarantine store", zap.Error(err))
	}
	lStore, err := ledger.New(dbConn)
	if err != nil {
		logger.Fatal("Failed to initialise ledger store", zap.Error(err))
	}
	pStore, err := policystore.New(cfg.PolicyDir)
	if err != nil {
		logger.Fatal("Failed to initialise policy store", zap.Error(err))
	}

	proxyHandler, err := proxy.NewHandler(logger, cfg.TargetURL, engine,
		proxy.NoOpPublisher{}, qStore, lStore,
		proxy.WithTargetAuthToken(cfg.TargetAuthToken),
		proxy.WithMaxBodyBytes(cfg.MaxRequestBodyBytes),
		proxy.WithUpstreamHeaderTimeout(cfg.WriteTimeout),
	)
	if err != nil {
		logger.Fatal("Failed to create proxy handler", zap.Error(err))
	}

	quarantineHandler := quarantine.NewHandler(qStore, lStore, logger)

	// Approve/deny from Slack goes through the same audited decision path
	// as the console.
	var slackApp *slackapp.App
	if cfg.Slack.Enabled() {
		slackApp = slackapp.New(slackapp.Config{
			BotToken: cfg.Slack.BotToken, SigningSecret: cfg.Slack.SigningSecret,
			ChannelID: cfg.Slack.ChannelID, TeamID: cfg.Slack.TeamID,
			Reviewers: cfg.Slack.Reviewers, ConsoleURL: cfg.ConsoleURL,
			APIBase: cfg.Slack.APIBase,
		}, quarantineHandler, logger)
	}
	ledgerHandler := ledger.NewHandler(lStore, logger)
	policyHandler := policystore.NewHandler(pStore, engine, logger)
	dashboardHandler := dashboard.NewHandler(lStore, qStore, logger)

	identities := make(map[string]auth.Identity)
	for tok, agentID := range cfg.APIKeys {
		identities[tok] = auth.Identity{ID: agentID, Role: auth.RoleAgent}
	}
	for tok, reviewerID := range cfg.ReviewerAPIKeys {
		identities[tok] = auth.Identity{ID: reviewerID, Role: auth.RoleReviewer}
	}
	for tok, adminID := range cfg.AdminAPIKeys {
		identities[tok] = auth.Identity{ID: adminID, Role: auth.RoleAdmin}
	}

	// Assigned only when enabled: a typed nil pointer in the interface would
	// look configured to buildHTTPHandler.
	var ssoDeps ssoProvider
	if cfg.OIDC.Enabled() {
		ssoService := sso.New(cfg.OIDC, cfg.AllowedOrigins, db.New(dbConn), logger)
		ssoDeps = ssoService
		go ssoService.Run(ctx)
		if cfg.Environment == "production" && len(cfg.ReviewerAPIKeys)+len(cfg.AdminAPIKeys) > 0 {
			logger.Warn("SSO is enabled and static reviewer/admin tokens are still configured; keep them only as break-glass access",
				zap.Int("static_human_tokens", len(cfg.ReviewerAPIKeys)+len(cfg.AdminAPIKeys)))
		}
	}

	// Ready only after every dependency above has been constructed — the
	// listener goroutine starts below, and /readyz answers 200 from then on.
	ready := &atomic.Bool{}
	ready.Store(true)

	finalHandler := buildHTTPHandler(httpDeps{
		version:        version,
		startTime:      startTime,
		dbConn:         dbConn,
		proxy:          proxyHandler,
		quarantine:     quarantineHandler,
		ledger:         ledgerHandler,
		policy:         policyHandler,
		dashboard:      dashboardHandler,
		slack:          slackHandler(slackApp),
		identities:     identities,
		rateLimitRPS:   cfg.RateLimitRPS,
		rateLimitBurst: cfg.RateLimitBurst,
		allowedOrigins: cfg.AllowedOrigins,
		ready:          ready,
		policyReady:    engine.Ready,
		policyVersion:  engine.Version,
		sso:            ssoDeps,

		metricsOnSeparateListener: cfg.MetricsListenAddr != "",
	}, logger)

	var metricsSrv *http.Server
	if cfg.MetricsListenAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		metricsSrv = &http.Server{Addr: cfg.MetricsListenAddr, Handler: metricsMux, ReadHeaderTimeout: cfg.ReadHeaderTimeout}
		go func() {
			logger.Info("Metrics listening", zap.String("addr", cfg.MetricsListenAddr))
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("Metrics listener failed", zap.Error(err))
			}
		}()
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           finalHandler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, // Slowloris defense (CVE-2025-53634)
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	go func() {
		logger.Info("Elodea listening",
			zap.String("addr", cfg.ListenAddr),
			zap.Bool("tls", cfg.TLSCertFile != ""),
		)
		var serveErr error
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			serveErr = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(serveErr))
		}
	}()

	// Durable quarantine replay worker — owns all approved→replayed transitions.
	// Replays carry the same upstream credential as ALLOW requests; without it
	// an authenticated upstream would 401/403 every approved replay.
	worker := quarantine.NewWorker(qStore, lStore, logger, cfg.TargetURL,
		quarantine.WithTargetAuthToken(cfg.TargetAuthToken),
		quarantine.WithPolicyRecheck(proxy.NewPolicyRecheck(proxy.MCPAdapter{}, engine)),
	)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.Run(workerCtx)
	}()

	// Held-action notifications go through the Postgres outbox, so restarts
	// and multiple replicas neither lose nor duplicate them.
	var channels []notify.Channel
	if cfg.Notify.SlackWebhookURL != "" {
		channels = append(channels, notify.NewSlack(cfg.Notify.SlackWebhookURL))
	}
	if cfg.Notify.WebhookURL != "" {
		channels = append(channels, notify.NewWebhook(cfg.Notify.WebhookURL, cfg.Notify.WebhookSecret))
	}
	if slackApp != nil {
		channels = append(channels, slackApp)
	}
	if len(channels) > 0 {
		go notify.NewWorker(db.New(dbConn), channels, cfg.ConsoleURL, logger).Run(workerCtx)
		logger.Info("Held-action notifications enabled", zap.Int("channels", len(channels)))
	}

	<-ctx.Done()
	logger.Info("Shutting down gracefully...")

	// Readiness-first drain: flip /readyz to 503 BEFORE stopping the listener
	// so the orchestrator stops routing NEW traffic here while in-flight
	// requests finish inside the Shutdown window below.
	ready.Store(false)
	logger.Info("Readiness flipped to draining (/readyz -> 503)")

	workerCancel()
	select {
	case <-workerDone:
		logger.Info("Quarantine replay worker stopped")
	case <-time.After(5 * time.Second):
		logger.Warn("Quarantine replay worker did not stop before shutdown window")
	}

	// Keep the listener available long enough for an orchestrator to observe
	// the failed readiness probe. drainMiddleware rejects new protected work
	// during this period; existing requests are allowed to finish below.
	drainTimer := time.NewTimer(cfg.ShutdownDrainDelay)
	<-drainTimer.C

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shutdownCtx)
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		// Shutdown's return is checked: a timeout here means in-flight
		// requests did not finish in the window — say so loudly rather than
		// exiting "cleanly" with work still running.
		logger.Error("Graceful shutdown failed: in-flight requests did not drain in time", zap.Error(err))
	} else {
		logger.Info("All in-flight requests drained")
	}

	logger.Info("Shutdown complete")
}

// newLogger builds the production JSON logger at the configured level.
func newLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	if level != "" {
		parsed, err := zapcore.ParseLevel(level)
		if err != nil {
			return nil, err
		}
		cfg.Level = zap.NewAtomicLevelAt(parsed)
	}
	return cfg.Build()
}

// connectPostgres opens one pool and pings it with bounded, cancellable
// retries, so a database that is still starting does not crash-loop the pod.
func connectPostgres(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*sql.DB, error) {
	dbConn, err := sql.Open("postgres", cfg.PostgresDSN)
	if err != nil {
		return nil, err
	}
	dbConn.SetMaxOpenConns(cfg.PGMaxOpenConns)
	dbConn.SetMaxIdleConns(cfg.PGMaxIdleConns)
	dbConn.SetConnMaxLifetime(cfg.PGConnMaxLifetime)

	const attempts = 10
	for attempt := 1; ; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = dbConn.PingContext(pingCtx)
		cancel()
		if err == nil {
			return dbConn, nil
		}
		if attempt == attempts {
			_ = dbConn.Close()
			return nil, fmt.Errorf("postgres unreachable after %d attempts: %w", attempts, err)
		}
		logger.Warn("Postgres not reachable yet, retrying", zap.Error(err), zap.Int("attempt", attempt))
		select {
		case <-ctx.Done():
			_ = dbConn.Close()
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// reloadOnSignal reloads the policy bundle on SIGHUP.
func reloadOnSignal(ctx context.Context, engine *opaengine.Engine, logger *zap.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			if err := engine.Reload(ctx); err != nil {
				logger.Error("SIGHUP policy reload rejected, keeping previous policy", zap.Error(err))
				continue
			}
			logger.Info("Policy bundle reloaded on SIGHUP", zap.String("policy_version", engine.Version()))
		}
	}
}

// runHealthcheck probes the liveness endpoint. The URL defaults to the
// standard port and can be overridden with ELODEA_HEALTHCHECK_URL.
func runHealthcheck() int {
	target := os.Getenv("ELODEA_HEALTHCHECK_URL")
	if target == "" {
		target = "http://127.0.0.1:8080/api/v1/health"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
