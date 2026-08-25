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
	version   = "1.0.0"
	startTime = time.Now()
)

func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			if allowed && origin != "" {
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

// rateLimiterMiddleware enforces a per-identity token bucket.
type rateLimiter struct {
	mu      sync.Mutex
	lim     map[string]*rate.Limiter
	rps     float64
	burst   int
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

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := auth.AgentFromContext(r.Context())
		if id != "unknown" && !rl.get(id).Allow() {
			http.Error(w, `{"error": "rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		metrics.HttpRequestsTotal.Inc()
		next.ServeHTTP(w, r)
		metrics.HttpRequestDuration.Observe(time.Since(start).Seconds())
	})
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
	defer dbConn.Close()

	// Apply versioned schema migrations before anything touches the DB.
	if err := db.Migrate(ctx, dbConn); err != nil {
		logger.Fatal("Failed to apply database migrations", zap.Error(err))
	}

	// NOTE: NATS JetStream is intentionally not initialised in v1.0.
	// All audit events are written directly to the Postgres ledger.
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

	reviewerGuard := auth.ReviewerOrAdmin()
	human := func(h http.Handler) http.Handler { return reviewerGuard(h) }

	mux := http.NewServeMux()

	// --- Liveness vs Readiness ---
	// /api/v1/health: process alive ONLY (never pings the DB).
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "ok",
			"version":        version,
			"uptime_seconds": time.Since(startTime).Seconds(),
		})
	})
	// /readyz: 503 unless Postgres answers. Orchestrators gate traffic on this.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		pingCtx, pingCancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer pingCancel()
		if err := dbConn.PingContext(pingCtx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{"ready": false, "postgres": false})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ready": true, "postgres": true})
	})

	// --- Human trust domain (reviewer/admin only) ---
	stripQuarantine := http.StripPrefix("/api/v1/quarantine", quarantineHandler)
	mux.Handle("/api/v1/quarantine", human(stripQuarantine))
	mux.Handle("/api/v1/quarantine/", human(stripQuarantine))

	stripLedger := http.StripPrefix("/api/v1/ledger", ledgerHandler)
	mux.Handle("/api/v1/ledger", human(stripLedger))
	mux.Handle("/api/v1/ledger/", human(stripLedger))

	stripPolicy := http.StripPrefix("/api/v1/policies", policyHandler)
	mux.Handle("/api/v1/policies", human(stripPolicy))
	mux.Handle("/api/v1/policies/", human(stripPolicy))

	mux.Handle("/api/v1/dashboard/stats", human(dashboardHandler))

	// --- Machine trust domain (agents) ---
	mux.Handle("/", proxyHandler)

	// /metrics is public for Prometheus scraping inside the trust boundary.
	mux.Handle("/metrics", promhttp.Handler())

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

	limiter := newRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	// Middleware chain: Metrics → CORS → Auth → Per-agent rate limit → Mux.
	authenticated := auth.Middleware(identities, logger, mux)
	rateLimited := limiter.middleware(authenticated)
	corsHandler := corsMiddleware(cfg.AllowedOrigins)(rateLimited)
	finalHandler := prometheusMiddleware(corsHandler)

	srv := &http.Server{
		Addr:           cfg.ListenAddr,
		Handler:        finalHandler,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		IdleTimeout:    cfg.IdleTimeout,
		MaxHeaderBytes: cfg.MaxHeaderBytes,
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
	worker := quarantine.NewWorker(qStore, lStore, logger, cfg.TargetURL)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	go worker.Run(workerCtx)

	<-ctx.Done()
	logger.Info("Shutting down gracefully...")

	workerCancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Graceful shutdown failed", zap.Error(err))
	}

	logger.Info("Shutdown complete")
}
