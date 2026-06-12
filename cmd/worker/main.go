package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/detect"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/log"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/risk"
	"github.com/nhiid/nhiid/internal/store"
)

func main() {
	once := flag.Bool("once", false, "run once and exit (for testing)")
	job := flag.String("job", "all", "graph, score, detect, or all")
	flag.Parse()

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

	riskEngine := risk.NewEngine(weights)
	detectionEngine := detect.NewEngine()
	detectionCfg := detect.Config{
		StaleWindow:         time.Duration(cfg.Detection.StaleWindowDays) * 24 * time.Hour,
		MaxCredAge:          time.Duration(cfg.Detection.MaxCredAgeDays) * 24 * time.Hour,
		MaxRotationAge:      time.Duration(cfg.Detection.MaxRotationAgeDays) * 24 * time.Hour,
		ImpossibleTravelKMH: cfg.Detection.ImpossibleTravelMaxKMH,
		UsageSpikeSigma:     cfg.Detection.UsageSpikeSigma,
		AnomalyWarmupEvents: cfg.Detection.AnomalyWarmupEvents,
	}

	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()

	for {
		// List all identities and process them
		ids, err := s.Identities.List(ctx, store.IdentityFilter{Limit: 1000})
		if err != nil {
			logger.Error("list identities", "err", err)
			goto next
		}

		if *job == "graph" || *job == "all" {
			if err := runGraphBuild(ctx, s, logger); err != nil {
				logger.Error("graph build", "err", err)
			}
		}

		if *job == "score" || *job == "all" {
			if err := runScoring(ctx, s, ids, riskEngine, logger); err != nil {
				logger.Error("scoring", "err", err)
			}
		}

		if *job == "detect" || *job == "all" {
			if err := runDetection(ctx, s, ids, detectionEngine, detectionCfg, logger); err != nil {
				logger.Error("detection", "err", err)
			}
		}

	next:
		if *once {
			break
		}
		<-tick.C
	}
}

func runGraphBuild(ctx context.Context, s *store.Store, logger *slog.Logger) error {
	logger.Info("building graph")
	// Load all graph_nodes and graph_edges from store (stub for MVP).
	return nil
}

func runScoring(ctx context.Context, s *store.Store, ids []models.Identity, engine *risk.Engine, logger *slog.Logger) error {
	logger.Info("scoring identities", "count", len(ids))
	for _, id := range ids {
		creds, _ := s.Credentials.ForIdentity(ctx, id.ID)
		roles, _ := s.Roles.ForIdentity(ctx, id.ID)
		bindings, _ := s.Bindings.ForIdentity(ctx, id.ID)
		trust, _ := s.TrustEdges.ForIdentity(ctx, id.ID)
		exposures, _ := s.Exposures.ForIdentity(ctx, id.ID)

		input := risk.Input{
			Identity:           id,
			Creds:              creds,
			Roles:              roles,
			Bindings:           bindings,
			Trust:              trust,
			Exposures:          exposures,
			Blast:              graph.BlastRadius{},
			PeerPermissionP90:  100,
			PeerReachableP90:   50,
			Now:                time.Now(),
		}
		breakdown := engine.Score(input)
		// Convert Factor map to map[string]any for storage
		factorMap := make(map[string]any)
		for k, v := range breakdown.Factors {
			factorMap[k] = v
		}
		if err := s.Identities.UpdateRiskScore(ctx, id.ID, breakdown.Composite, factorMap); err != nil {
			logger.Error("update risk", "identity", id.Name, "err", err)
		}
	}
	return nil
}

func runDetection(ctx context.Context, s *store.Store, ids []models.Identity, engine *detect.Engine, cfg detect.Config, logger *slog.Logger) error {
	logger.Info("detecting anomalies", "count", len(ids))
	for _, id := range ids {
		creds, _ := s.Credentials.ForIdentity(ctx, id.ID)
		roles, _ := s.Roles.ForIdentity(ctx, id.ID)
		bindings, _ := s.Bindings.ForIdentity(ctx, id.ID)
		trust, _ := s.TrustEdges.ForIdentity(ctx, id.ID)
		exposures, _ := s.Exposures.ForIdentity(ctx, id.ID)
		workloads, _ := s.Workloads.ForIdentity(ctx, id.ID)
		usage, _ := s.Usage.RecentForIdentity(ctx, id.ID, time.Now().Add(-90*24*time.Hour))

		subject := detect.Subject{
			Identity:  id,
			Creds:     creds,
			Roles:     roles,
			Bindings:  bindings,
			Trust:     trust,
			Exposures: exposures,
			Workloads: workloads,
			Usage:     usage,
			Blast:     graph.BlastRadius{},
			Paths:     nil,
		}
		findings := engine.Run(subject, cfg, time.Now())
		for _, f := range findings {
			if _, err := s.Findings.Upsert(ctx, f); err != nil {
				logger.Error("upsert finding", "detector", f.Detector, "err", err)
			}
		}
	}
	return nil
}
