package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/collectors"
	awscollector "github.com/nhiid/nhiid/internal/collectors/aws"
	"github.com/nhiid/nhiid/internal/collectors/fixture"
	gcpcollector "github.com/nhiid/nhiid/internal/collectors/gcp"
	repocollector "github.com/nhiid/nhiid/internal/collectors/repo"
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/detect"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/log"
	"github.com/nhiid/nhiid/internal/metrics"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/queue"
	"github.com/nhiid/nhiid/internal/remediate"
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

	// Prometheus metrics + derived-gauge refresher + job-queue consumer (long-running only).
	if !*once {
		go serveMetrics(cfg.Server.MetricsAddr, logger)
		metrics.StartRefresher(ctx, s, 30*time.Second)
		if q, err := queue.Connect(cfg.Queue.NATSURL, cfg.Queue.Stream); err != nil {
			logger.Warn("job queue unavailable; collection only via CLI/in-process API", "err", err)
		} else {
			defer q.Close()
			startCollectConsumer(ctx, q, s, logger)
		}
	}

	weights, err := risk.LoadWeights(cfg.Risk.WeightsFile)
	if err != nil {
		logger.Error("load risk weights", "err", err)
		os.Exit(1)
	}

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
		// Reload risk weights each cycle so PUT /config/risk-weights takes effect (hot reload).
		riskEngine := risk.NewEngine(effectiveWeights(ctx, s, weights))

		// List all identities and process them
		ids, err := s.Identities.List(ctx, store.IdentityFilter{Limit: 1000})
		if err != nil {
			logger.Error("list identities", "err", err)
			goto next
		}

		if *job == "graph" || *job == "all" {
			runJob("graph", logger, func() error { return runGraphBuild(ctx, s, logger) })
		}

		if *job == "score" || *job == "all" {
			runJob("score", logger, func() error { return runScoring(ctx, s, ids, riskEngine, logger) })
		}

		if *job == "detect" || *job == "all" {
			runJob("detect", logger, func() error {
				if err := runDetection(ctx, s, ids, detectionEngine, detectionCfg, riskEngine, logger); err != nil {
					return err
				}
				return runExposureFindings(ctx, s, logger)
			})
		}

	next:
		if *once {
			break
		}
		<-tick.C
	}
}

// startCollectConsumer subscribes to collect jobs, runs the requested collector, and records a
// snapshot. Job handler errors Nak the message for redelivery.
func startCollectConsumer(ctx context.Context, q *queue.Queue, s *store.Store, logger *slog.Logger) {
	err := q.ConsumeCollect("nhiid-worker", func(job queue.CollectJob) error {
		coll, account, err := buildCollector(job, logger)
		if err != nil {
			logger.Error("build collector from job", "provider", job.Provider, "err", err)
			return err
		}
		logger.Info("consuming collect job", "provider", job.Provider, "account", account, "by", job.RequestedBy)
		if err := collectors.Run(ctx, s, coll, account, logger); err != nil {
			return err
		}
		_, _ = s.Snapshots.Create(ctx, map[string]any{"provider": job.Provider, "account": account, "requested_by": job.RequestedBy})
		return nil
	})
	if err != nil {
		logger.Error("collect consumer subscribe failed", "err", err)
		return
	}
	logger.Info("collect job consumer started")
}

// buildCollector constructs a collector from a job spec.
func buildCollector(job queue.CollectJob, logger *slog.Logger) (collectors.Collector, string, error) {
	switch job.Provider {
	case "fixture":
		path := job.Fixture
		if path == "" {
			path = "fixtures/demo_env.json"
		}
		return fixture.New(path), "fixture", nil
	case "aws":
		region := job.Region
		if region == "" {
			region = "us-east-1"
		}
		acct := job.Account
		if acct == "" {
			acct = "aws"
		}
		return awscollector.New(awscollector.Options{RoleARN: job.RoleARN, ExternalID: job.ExternalID, Region: region, CloudTrailLookbackHours: 24}, logger), acct, nil
	case "gcp":
		proj := job.Project
		if proj == "" {
			proj = job.Account
		}
		if proj == "" {
			return nil, "", fmt.Errorf("gcp requires project")
		}
		return gcpcollector.New(gcpcollector.Options{ProjectID: proj, CredentialsFile: job.GCPCredentials, AuditLookbackHours: 24}, logger), "gcp:" + proj, nil
	case "repo":
		if job.Report == "" {
			return nil, "", fmt.Errorf("repo requires a report path")
		}
		return repocollector.New(repocollector.Options{
			ReportPath: job.Report, Provider: job.RepoProvider, Repo: job.Repo, Visibility: job.RepoVisibility,
		}), "repo:" + job.Repo, nil
	default:
		return nil, "", fmt.Errorf("unknown provider %q", job.Provider)
	}
}

// runJob runs a worker job, recording success/failure metrics.
func runJob(name string, logger *slog.Logger, fn func() error) {
	metrics.JobsTotal.WithLabelValues(name).Inc()
	if err := fn(); err != nil {
		metrics.JobsFailed.WithLabelValues(name).Inc()
		logger.Error(name+" job failed", "err", err)
	}
}

// serveMetrics exposes Prometheus metrics + a liveness endpoint on the metrics address.
func serveMetrics(addr string, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	logger.Info("worker metrics listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("metrics server stopped", "err", err)
	}
}

func runGraphBuild(ctx context.Context, s *store.Store, logger *slog.Logger) error {
	logger.Info("building graph")
	return projectGraph(ctx, s, logger)
}

// peerCache memoizes the per-(account,kind) permission P90 within one scoring/detection run.
type peerCache struct {
	s *store.Store
	m map[string]int
}

func newPeerCache(s *store.Store) *peerCache { return &peerCache{s: s, m: map[string]int{}} }

// effectiveWeights returns DB-stored risk weights if present and valid, else the fallback (file).
func effectiveWeights(ctx context.Context, s *store.Store, fallback *risk.Weights) *risk.Weights {
	if raw, ok, _ := s.Config.Get(ctx, "risk_weights"); ok {
		if w, err := risk.ParseWeightsJSON(raw); err == nil {
			return w
		}
	}
	return fallback
}

// suppressor builds a matcher from active suppressions. A suppression with a detector but no
// identity suppresses that detector everywhere; with an identity but no detector, all findings for
// that identity; with both, the specific pair.
func suppressor(sups []models.Suppression) func(detector string, identityID uuid.UUID) bool {
	return func(detector string, identityID uuid.UUID) bool {
		for _, sp := range sups {
			if sp.Detector != "" && sp.Detector != detector {
				continue
			}
			if sp.IdentityID != nil && *sp.IdentityID != identityID {
				continue
			}
			return true
		}
		return false
	}
}

func (p *peerCache) p90(ctx context.Context, id models.Identity) int {
	key := id.Prov.AccountRef + "|" + string(id.Kind)
	if v, ok := p.m[key]; ok {
		return v
	}
	v, _ := p.s.Identities.PeerPermissionP90(ctx, id.Prov.AccountRef, id.Kind)
	p.m[key] = v
	return v
}

func runScoring(ctx context.Context, s *store.Store, ids []models.Identity, engine *risk.Engine, logger *slog.Logger) error {
	logger.Info("scoring identities", "count", len(ids))
	g, reachP90, err := loadGraph(ctx, s)
	if err != nil {
		logger.Warn("load graph for scoring (blast radius disabled)", "err", err)
	}
	peers := newPeerCache(s)
	for _, id := range ids {
		creds, _ := s.Credentials.ForIdentity(ctx, id.ID)
		roles, _ := s.Roles.ForIdentity(ctx, id.ID)
		bindings, _ := s.Bindings.ForIdentity(ctx, id.ID)
		trust, _ := s.TrustEdges.ForIdentity(ctx, id.ID)
		exposures, _ := s.Exposures.ForIdentity(ctx, id.ID)

		blast := blastFor(g, id.ID)
		input := risk.Input{
			Identity:          id,
			Creds:             creds,
			Roles:             roles,
			Bindings:          bindings,
			Trust:             trust,
			Exposures:         exposures,
			Blast:             blast,
			PeerPermissionP90: peers.p90(ctx, id),
			PeerReachableP90:  reachP90,
			Now:               time.Now(),
		}
		breakdown := engine.Score(input)
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

func runDetection(ctx context.Context, s *store.Store, ids []models.Identity, engine *detect.Engine, cfg detect.Config, riskEngine *risk.Engine, logger *slog.Logger) error {
	logger.Info("detecting anomalies", "count", len(ids))
	g, reachP90, err := loadGraph(ctx, s)
	if err != nil {
		logger.Warn("load graph for detection (blast/attack-path disabled)", "err", err)
	}
	peers := newPeerCache(s)
	sups, _ := s.Suppressions.ListActive(ctx)
	isSuppressed := suppressor(sups)
	snapID, _ := s.Snapshots.Latest(ctx) // stamp findings with the collection snapshot for provenance
	for _, id := range ids {
		creds, _ := s.Credentials.ForIdentity(ctx, id.ID)
		roles, _ := s.Roles.ForIdentity(ctx, id.ID)
		bindings, _ := s.Bindings.ForIdentity(ctx, id.ID)
		trust, _ := s.TrustEdges.ForIdentity(ctx, id.ID)
		exposures, _ := s.Exposures.ForIdentity(ctx, id.ID)
		workloads, _ := s.Workloads.ForIdentity(ctx, id.ID)
		usage, _ := s.Usage.RecentForIdentity(ctx, id.ID, time.Now().Add(-90*24*time.Hour))

		blast := blastFor(g, id.ID)
		var paths []graph.Path
		if g != nil {
			if nid, ok := g.NodeIDForEntity(id.ID); ok {
				paths = g.AttackPaths(nid, blastMaxHops, 5)
			}
		}
		peerP90 := peers.p90(ctx, id)
		subject := detect.Subject{
			Identity:          id,
			Creds:             creds,
			Roles:             roles,
			Bindings:          bindings,
			Trust:             trust,
			Exposures:         exposures,
			Workloads:         workloads,
			Usage:             usage,
			Blast:             blast,
			Paths:             paths,
			PeerPermissionP90: peerP90,
		}

		// Risk input for re-scoring remediation deltas — same data, same engine as scoring.
		rin := risk.Input{
			Identity: id, Creds: creds, Roles: roles, Bindings: bindings, Trust: trust,
			Exposures: exposures, Blast: blast, PeerPermissionP90: peerP90,
			PeerReachableP90: reachP90, Now: time.Now(),
		}
		current := riskEngine.Score(rin).Composite

		findings := engine.Run(subject, cfg, time.Now())
		for _, f := range findings {
			if isSuppressed(f.Detector, id.ID) {
				continue // admin-gated, audited suppression — don't surface or re-open
			}
			f.SnapshotID = snapID
			findingID, err := s.Findings.Upsert(ctx, f)
			if err != nil {
				logger.Error("upsert finding", "detector", f.Detector, "err", err)
				continue
			}
			for _, plan := range remediate.Recommend(f.Detector, rin, riskEngine, current) {
				if err := s.Remediation.Upsert(ctx, models.RemediationAction{
					FindingID:  findingID,
					Action:     plan.Action,
					Status:     "recommended",
					RiskBefore: current,
					RiskAfter:  plan.RiskAfter,
					RiskDelta:  plan.RiskDelta,
					Notes:      plan.Rationale,
				}); err != nil {
					logger.Error("upsert remediation", "action", plan.Action, "err", err)
				}
			}
		}
	}
	return nil
}

// runExposureFindings raises repository-scoped secret_exposed_in_repo findings for scanner-
// discovered exposures that aren't linked to a specific identity (e.g. from SecretSweep reports).
func runExposureFindings(ctx context.Context, s *store.Store, logger *slog.Logger) error {
	exps, err := s.Exposures.RepoScoped(ctx)
	if err != nil {
		return err
	}
	if len(exps) == 0 {
		return nil
	}
	sups, _ := s.Suppressions.ListActive(ctx)
	isSuppressed := suppressor(sups)
	snapID, _ := s.Snapshots.Latest(ctx)
	raised := 0
	for _, re := range exps {
		if isSuppressed("secret_exposed_in_repo", uuid.Nil) {
			continue
		}
		f := detect.ExposureFinding(re.Exposure, nil, re.RepoLabel)
		f.SnapshotID = snapID
		if _, err := s.Findings.Upsert(ctx, f); err != nil {
			logger.Error("upsert exposure finding", "err", err)
			continue
		}
		raised++
	}
	logger.Info("repo-scoped exposure findings", "exposures", len(exps), "raised", raised)
	return nil
}

// blastFor returns the blast radius for an identity, or a zero value if the graph is unavailable
// or the identity has no projected node.
func blastFor(g *graph.Graph, identityID uuid.UUID) graph.BlastRadius {
	if g == nil {
		return graph.BlastRadius{}
	}
	if nid, ok := g.NodeIDForEntity(identityID); ok {
		return g.ComputeBlastRadius(nid, blastMaxHops)
	}
	return graph.BlastRadius{}
}
