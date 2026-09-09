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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/austinchima/kiterail/internal/auth"
	"github.com/austinchima/kiterail/internal/config"
	"github.com/austinchima/kiterail/internal/dashboard"
	"github.com/austinchima/kiterail/internal/db"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/metrics"
	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/policystore"
	"github.com/austinchima/kiterail/internal/proxy"
	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version   = "1.1.0"
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
			}
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

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

	// policyReady reports whether the active OPA query contains KiteRail's
	// authorization entry point. A nil function is used only by focused HTTP
	// tests that do not construct an engine.
	policyReady func() bool
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
	humanChain := func(next http.Handler) http.Handler {
		guarded := auth.ReviewerOrAdmin()(next)
		authenticated := auth.Middleware(d.identities, logger, guarded)
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
		json.NewEncoder(w).Encode(map[string]interface{}{"ready": true, "postgres": true})
	})

	mux.Handle("/api/v1/health", publicChain(healthHandler))
	mux.Handle("/readyz", publicChain(readyzHandler))

	// --- Human trust domain (reviewer/admin only) ---
	mux.Handle("/api/v1/quarantine", humanChain(http.StripPrefix("/api/v1/quarantine", d.quarantine)))
	mux.Handle("/api/v1/quarantine/", humanChain(http.StripPrefix("/api/v1/quarantine", d.quarantine)))

	mux.Handle("/api/v1/ledger", humanChain(http.StripPrefix("/api/v1/ledger", d.ledger)))
	mux.Handle("/api/v1/ledger/", humanChain(http.StripPrefix("/api/v1/ledger", d.ledger)))

	mux.Handle("/api/v1/policies", humanChain(http.StripPrefix("/api/v1/policies", d.policy)))
	mux.Handle("/api/v1/policies/", humanChain(http.StripPrefix("/api/v1/policies", d.policy)))

	mux.Handle("/api/v1/dashboard/stats", humanChain(d.dashboard))

	// --- Machine trust domain (agents): POST / only; the proxy rejects other methods ---
	mux.Handle("/", agentChain(d.proxy))

	// /metrics is public for Prometheus scraping inside the trust boundary.
	mux.Handle("/metrics", publicChain(promhttp.Handler()))

	return mux
}

func main() {
	configPath := flag.String("config", "", "Path to config file")
	port := flag.String("port", "", "Override listen address")
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting KiteRail", zap.String("version", version))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}
	if *port != "" {
		cfg.ListenAddr = *port
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Connect to Postgres with retry.
	var dbConn *sql.DB
	for i := range 5 {
		dbConn, err = sql.Open("postgres", cfg.PostgresDSN)
		if err == nil {
			dbConn.SetMaxOpenConns(cfg.PGMaxOpenConns)
			dbConn.SetMaxIdleConns(cfg.PGMaxIdleConns)
			dbConn.SetConnMaxLifetime(cfg.PGConnMaxLifetime)
			err = dbConn.PingContext(ctx)
			if err == nil {
				break
			}
		}
		logger.Warn("Failed to connect to postgres, retrying...", zap.Error(err), zap.Int("attempt", i+1))
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		logger.Fatal("Failed to connect to postgres after 5 attempts", zap.Error(err))
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
	)
	if err != nil {
		logger.Fatal("Failed to create proxy handler", zap.Error(err))
	}

	quarantineHandler := quarantine.NewHandler(qStore, lStore, logger)
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
		identities:     identities,
		rateLimitRPS:   cfg.RateLimitRPS,
		rateLimitBurst: cfg.RateLimitBurst,
		allowedOrigins: cfg.AllowedOrigins,
		ready:          ready,
		policyReady:    engine.Ready,
	}, logger)

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
		logger.Info("KiteRail listening",
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
	)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.Run(workerCtx)
	}()

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
