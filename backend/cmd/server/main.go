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
	"github.com/austinchima/kiterail/internal/events"
	"github.com/austinchima/kiterail/internal/ledger"
	"github.com/austinchima/kiterail/internal/opa"
	"github.com/austinchima/kiterail/internal/policy"
	"github.com/austinchima/kiterail/internal/proxy"
	"github.com/austinchima/kiterail/internal/quarantine"
	"github.com/austinchima/kiterail/internal/dashboard"
)

var (
	version   = "dev"
	startTime = time.Now()
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	configPath := flag.String("config", "", "Path to config file")
	port := flag.String("port", "", "Override listen address")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	fmt.Println("🚂 Starting KiteRail...")

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}
	if *port != "" {
		cfg.ListenAddr = *port
	}
	if cfg.TargetURL == "" {
		cfg.TargetURL = "http://localhost:8081" // fallback target
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Connect to Postgres
	var db *sql.DB
	for i := 0; i < 5; i++ {
		db, err = sql.Open("postgres", cfg.PostgresDSN)
		if err == nil {
			err = db.PingContext(ctx)
			if err == nil {
				break
			}
		}
		logger.Warn("Failed to connect to postgres, retrying...", zap.Error(err))
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		logger.Fatal("Failed to connect to postgres after 5 attempts", zap.Error(err))
	}
	defer db.Close()

	// Connect to NATS
	var pub *events.Publisher
	for i := 0; i < 5; i++ {
		pub, err = events.New(ctx, cfg.NatsURL)
		if err == nil {
			break
		}
		logger.Warn("Failed to connect to NATS, retrying...", zap.Error(err))
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		logger.Fatal("Failed to connect to NATS after 5 attempts", zap.Error(err))
	}
	defer pub.Close()

	// Connect to NATS (Subscriber)
	var sub *events.Subscriber
	for i := 0; i < 5; i++ {
		sub, err = events.NewSubscriber(ctx, cfg.NatsURL)
		if err == nil {
			break
		}
		logger.Warn("Failed to connect NATS subscriber, retrying...", zap.Error(err))
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		logger.Fatal("Failed to connect NATS subscriber after 5 attempts", zap.Error(err))
	}
	defer sub.Close()

	if err := sub.Start(ctx); err != nil {
		logger.Fatal("Failed to start NATS subscriber", zap.Error(err))
	}

	// Init OPA
	engine, err := opa.New(ctx, cfg.PolicyDir)
	if err != nil {
		logger.Fatal("Failed to initialize OPA engine", zap.Error(err))
	}

	// Init Stores
	qStore, err := quarantine.New(db)
	if err != nil {
		logger.Fatal("Failed to initialize quarantine store", zap.Error(err))
	}

	lStore, err := ledger.New(db)
	if err != nil {
		logger.Fatal("Failed to initialize ledger store", zap.Error(err))
	}

	pStore, err := policy.New(db)
	if err != nil {
		logger.Fatal("Failed to initialize policy store", zap.Error(err))
	}

	// Quarantine Handler
	quarantineHandler := quarantine.NewHandler(qStore, pub, lStore, logger)

	// Ledger Handler
	ledgerHandler := ledger.NewHandler(lStore, logger)

	// Proxy Handler
	proxyHandler, err := proxy.NewHandler(logger, cfg.TargetURL, engine, pub, qStore, lStore, pStore)
	if err != nil {
		logger.Fatal("Failed to create proxy handler", zap.Error(err))
	}

	// Policy Handler
	policyHandler := policy.NewHandler(pStore, logger)

	// Dashboard Handler
	dashboardHandler := dashboard.NewHandler(lStore, qStore, logger)

	// SSE Handler
	sseHandler := proxy.NewSSEHandler(sub)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "ok",
			"version":        version,
			"uptime_seconds": time.Since(startTime).Seconds(),
			"services": map[string]bool{
				"postgres": db.PingContext(ctx) == nil,
				"nats":     pub != nil && pub.IsHealthy(),
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

	// Wrap mux: CORS (outermost) -> Auth -> Mux
	authenticatedHandler := proxy.AuthMiddleware(cfg.APIKeys, logger, mux)
	finalHandler := corsMiddleware(authenticatedHandler)

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: finalHandler,
	}

	go func() {
		logger.Info("Starting server", zap.String("addr", cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	<-ctx.Done()
	logger.Info("Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Failed to shutdown server gracefully", zap.Error(err))
	}

	logger.Info("Shutdown complete")
}
