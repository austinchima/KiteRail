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
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/austinchima/kiterail/internal/config"
	"github.com/austinchima/kiterail/internal/dashboard"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/opaengine"
	"github.com/austinchima/kiterail/internal/policystore"
	"github.com/austinchima/kiterail/internal/proxy"
	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/austinchima/kiterail/internal/metrics"
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
			} else if len(allowedOrigins) > 0 && allowedOrigins[0] == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
		})
	}
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

	fmt.Println("🚂 Starting KiteRail v1.0.0...")

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}
	if *port != "" {
		cfg.ListenAddr = *port
	}
	if cfg.TargetURL == "" {
		logger.Fatal("KITERAIL_TARGET_URL must be set")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Connect to Postgres with retry.
	var db *sql.DB
	for i := 0; i < 5; i++ {
		db, err = sql.Open("postgres", cfg.PostgresDSN)
		if err == nil {
			err = db.PingContext(ctx)
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
	defer db.Close()

	// NOTE: NATS JetStream is intentionally not initialised in v1.0.
	// All audit events are written directly to the Postgres ledger.
	// NATS will be re-introduced in v1.1 for real-time streaming.

	// Init OPA engine.
	engine, err := opaengine.New(ctx, cfg.PolicyDir)
	if err != nil {
		logger.Fatal("Failed to initialise OPA engine", zap.Error(err))
	}

	// Init stores.
	qStore, err := quarantine.New(db)
	if err != nil {
		logger.Fatal("Failed to initialise quarantine store", zap.Error(err))
	}

	lStore, err := ledger.New(db)
	if err != nil {
		logger.Fatal("Failed to initialise ledger store", zap.Error(err))
	}

	pStore, err := policystore.New(cfg.PolicyDir)
	if err != nil {
		logger.Fatal("Failed to initialise policy store", zap.Error(err))
	}

	// Wire up handlers.
	// proxy.NewHandler uses NoOpPublisher to skip NATS publishing when nil.
	proxyHandler, err := proxy.NewHandler(logger, cfg.TargetURL, engine, proxy.NoOpPublisher{}, qStore, lStore)
	if err != nil {
		logger.Fatal("Failed to create proxy handler", zap.Error(err))
	}

	quarantineHandler := quarantine.NewHandler(qStore, lStore, logger, cfg.TargetURL)
	ledgerHandler := ledger.NewHandler(lStore, logger)
	policyHandler := policystore.NewHandler(pStore, engine, logger)
	dashboardHandler := dashboard.NewHandler(lStore, qStore, logger)
	sseHandler := proxy.NewSSEHandler() // returns 501 in v1.0

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "ok",
			"version":        version,
			"uptime_seconds": time.Since(startTime).Seconds(),
			"services": map[string]bool{
				"postgres": db.PingContext(ctx) == nil,
			},
		})
	})

	stripQuarantine := http.StripPrefix("/api/v1/quarantine", quarantineHandler)
	mux.Handle("/api/v1/quarantine", stripQuarantine)
	mux.Handle("/api/v1/quarantine/", stripQuarantine)

	mux.Handle("/api/v1/topology/stream", sseHandler)

	stripLedger := http.StripPrefix("/api/v1/ledger", ledgerHandler)
	mux.Handle("/api/v1/ledger", stripLedger)
	mux.Handle("/api/v1/ledger/", stripLedger)

	stripPolicy := http.StripPrefix("/api/v1/policies", policyHandler)
	mux.Handle("/api/v1/policies", stripPolicy)
	mux.Handle("/api/v1/policies/", stripPolicy)

	mux.Handle("/api/v1/dashboard/stats", dashboardHandler)
	mux.Handle("/", proxyHandler)

	// ⚠️ Metrics Endpoint is completely open by default for easy Prometheus scraping.
	// If you wish to secure it with KiteRail API keys, wrap it like so:
	// mux.Handle("/metrics", proxy.AuthMiddleware(cfg.APIKeys, logger, promhttp.Handler()))
	mux.Handle("/metrics", promhttp.Handler())

	// Middleware chain: Metrics → CORS → Auth → Mux.
	authenticatedHandler := proxy.AuthMiddleware(cfg.APIKeys, logger, mux)
	corsHandler := corsMiddleware(cfg.AllowedOrigins)(authenticatedHandler)
	finalHandler := prometheusMiddleware(corsHandler)

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: finalHandler,
	}

	go func() {
		logger.Info("KiteRail listening", zap.String("addr", cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(err))
		}
	}()

	<-ctx.Done()
	logger.Info("Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Graceful shutdown failed", zap.Error(err))
	}

	logger.Info("Shutdown complete")
}
