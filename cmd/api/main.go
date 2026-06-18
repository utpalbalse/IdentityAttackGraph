package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nhiid/nhiid/internal/api"
	"github.com/nhiid/nhiid/internal/auth"
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/log"
	"github.com/nhiid/nhiid/internal/metrics"
	"github.com/nhiid/nhiid/internal/queue"
	"github.com/nhiid/nhiid/internal/ratelimit"
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

	// Auth (RBAC). Mode "off" by default; "token" enforces bearer-token roles; "jwt" validates OIDC
	// bearer JWTs (HS256 secret or RS256 public key) and reads a role claim.
	tokens, err := auth.LoadTokens(cfg.Auth.TokensFile)
	if err != nil {
		logger.Error("load auth tokens", "err", err)
		os.Exit(1)
	}
	var jwtCfg *auth.JWTConfig
	if cfg.Auth.Mode == "jwt" {
		jwtCfg = &auth.JWTConfig{
			Secret:    cfg.Auth.JWTSecret,
			RoleClaim: cfg.Auth.JWTRoleClaim,
			Issuer:    cfg.Auth.JWTIssuer,
			Audience:  cfg.Auth.JWTAudience,
		}
		if cfg.Auth.JWTPublicKeyFile != "" {
			pem, perr := os.ReadFile(cfg.Auth.JWTPublicKeyFile)
			if perr != nil {
				logger.Error("read jwt public key", "err", perr)
				os.Exit(1)
			}
			jwtCfg.PublicKeyPEM = pem
		}
	}
	authn, err := auth.New(cfg.Auth.Mode, tokens, jwtCfg)
	if err != nil {
		logger.Error("configure auth", "err", err)
		os.Exit(1)
	}
	logger.Info("auth configured", "mode", cfg.Auth.Mode, "enforced", authn.Enforced())

	// Redis-backed per-principal rate limiter (fails open if Redis is down).
	var limiter *ratelimit.Limiter
	if cfg.Server.RateLimitPerMin > 0 {
		if limiter, err = ratelimit.Connect(cfg.Cache.RedisURL, cfg.Server.RateLimitPerMin, time.Minute); err != nil {
			logger.Warn("rate limiter disabled (bad redis url)", "err", err)
			limiter = nil
		} else {
			logger.Info("rate limiter enabled", "per_min", cfg.Server.RateLimitPerMin)
		}
	}

	// Prometheus metrics: separate listener + derived-gauge refresher.
	go serveMetrics(cfg.Server.MetricsAddr, s, logger)
	metrics.StartRefresher(ctx, s, 30*time.Second)

	// Job queue (optional). When connected, /collect enqueues to NATS; otherwise it falls back to
	// running the collection in-process.
	q, err := queue.Connect(cfg.Queue.NATSURL, cfg.Queue.Stream)
	if err != nil {
		logger.Warn("job queue unavailable; /collect will run in-process", "err", err)
		q = nil
	} else {
		defer q.Close()
		logger.Info("job queue connected", "stream", cfg.Queue.Stream)
	}

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(metricsMiddleware)

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

	// API routes, grouped by minimum RBAC role (viewer < analyst < admin).
	h := &api.Handler{Store: s, RiskEngine: risk.NewEngine(weights), Logger: logger, WeightsFile: cfg.Risk.WeightsFile, Queue: q}
	router.Route("/api/v1", func(r chi.Router) {
		r.Use(authn.Authenticate)
		if limiter != nil {
			r.Use(limiter.Middleware)
		}

		// viewer — read
		r.Group(func(r chi.Router) {
			r.Use(authn.Require(auth.RoleViewer))
			r.Get("/version", h.GetVersion)
			r.Get("/identities", h.ListIdentities)
			r.Get("/identities/{id}", h.GetIdentity)
			r.Get("/identities/{id}/risk", h.GetIdentityRisk)
			r.Get("/identities/{id}/credentials", h.GetIdentityCredentials)
			r.Get("/identities/{id}/usage", h.GetIdentityUsage)
			r.Get("/credentials", h.ListCredentials)
			r.Get("/secrets", h.ListSecrets)
			r.Get("/workloads", h.ListWorkloads)
			r.Get("/repositories", h.ListRepositories)
			r.Get("/identities/{id}/attack-paths", h.GetAttackPaths)
			r.Get("/identities/{id}/blast-radius", h.GetBlastRadius)
			r.Get("/graph", h.GetGraph)
			r.Get("/graph/neighborhood", h.GetNeighborhood)
			r.Get("/findings", h.ListFindings)
			r.Get("/findings/{id}", h.GetFinding)
			r.Get("/findings/{id}/remediations", h.GetFindingRemediations)
			r.Get("/triage", h.GetTriage)
			r.Get("/metrics/risk-reduction", h.GetRiskReduction)
			r.Get("/snapshots", h.ListSnapshots)
		})

		// analyst — triage + remediation + exports
		r.Group(func(r chi.Router) {
			r.Use(authn.Require(auth.RoleAnalyst))
			r.Patch("/findings/{id}", h.UpdateFinding)
			r.Patch("/remediations/{id}", h.UpdateRemediation)
			r.Get("/export/findings", h.ExportFindings)
			r.Get("/export/inventory", h.ExportInventory)
			r.Get("/collector-runs", h.ListCollectorRuns)
		})

		// admin — collection, suppression, config, audit
		r.Group(func(r chi.Router) {
			r.Use(authn.Require(auth.RoleAdmin))
			r.Post("/collect", h.Collect)
			r.Post("/findings/{id}/suppress", h.SuppressFinding)
			r.Get("/config/risk-weights", h.GetRiskWeights)
			r.Put("/config/risk-weights", h.PutRiskWeights)
			r.Get("/audit", h.ListAudit)
		})
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

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Error("shutdown error", "err", err)
	}
}

// metricsMiddleware records request latency labelled by method, matched route, and status.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = r.URL.Path
		}
		metrics.HTTPDuration.WithLabelValues(r.Method, route, strconv.Itoa(ww.Status())).
			Observe(time.Since(start).Seconds())
	})
}

// serveMetrics exposes Prometheus metrics + readiness on the metrics address.
func serveMetrics(addr string, s *store.Store, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	logger.Info("metrics listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("metrics server stopped", "err", err)
	}
}
