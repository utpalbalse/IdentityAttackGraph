package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nhiid/nhiid/internal/api"
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/log"
	"github.com/nhiid/nhiid/internal/risk"
	"github.com/nhiid/nhiid/internal/store"
)

func main() {
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(cfg.Telemetry.LogLevel, cfg.Telemetry.LogFormat)
	slog.SetDefault(logger)

	ctx := context.Background()
	s, err := store.New(ctx, cfg.Database.DSN, cfg.Database.MaxConns, cfg.Database.MinConns)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}
	defer s.Close()

	weights, err := risk.LoadWeights(cfg.Risk.WeightsFile)
	if err != nil {
		logger.Error("load risk weights", "err", err)
		os.Exit(1)
	}

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Health
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	router.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Pool().Ping(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	// API routes
	h := &api.Handler{Store: s, RiskEngine: risk.NewEngine(weights), Logger: logger}
	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/version", h.GetVersion)
		r.Get("/identities", h.ListIdentities)
		r.Get("/identities/{id}", h.GetIdentity)
		r.Get("/identities/{id}/risk", h.GetIdentityRisk)
		r.Get("/identities/{id}/attack-paths", h.GetAttackPaths)
		r.Get("/identities/{id}/blast-radius", h.GetBlastRadius)
		r.Get("/graph", h.GetGraph)
		r.Get("/graph/neighborhood", h.GetNeighborhood)
		r.Get("/findings", h.ListFindings)
		r.Get("/findings/{id}", h.GetFinding)
		r.Patch("/findings/{id}", h.UpdateFinding)
		r.Get("/triage", h.GetTriage)
	})

	addr := cfg.Server.HTTPAddr
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	go func() {
		logger.Info("starting API server", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "err", err)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown error", "err", err)
	}
}
