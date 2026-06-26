// Package collectors defines the Collector interface and the harness for running collectors.
// Each collector is a pure function of (provider creds, cursor) → normalized records.
package collectors

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nhiid/nhiid/internal/metrics"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/store"
	"github.com/nhiid/nhiid/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Collector is the interface that each provider (AWS, GCP, K8s, GitHub) must implement.
type Collector interface {
	ID() string // stable identifier (e.g. "aws_iam", "gcp_iam")

	// Collect runs the collector once. Returns normalized records and the new cursor state.
	// On first run, cursor is empty; on replay, cursor is the last-saved position for resumption.
	Collect(ctx context.Context, accountRef string, cursor map[string]any) (Result, error)
}

type Result struct {
	Identities       []models.Identity
	Credentials      []models.Credential
	Secrets          []models.Secret
	Roles            []models.Role
	TrustEdges       []models.TrustEdge
	ResourceBindings []models.ResourceBinding
	Workloads        []models.Workload
	Repositories     []models.Repository
	Exposures        []models.Exposure
	UsageEvents      []models.UsageEvent
	Owners           []models.Owner

	NewCursor map[string]any // to be saved in collector_state for next run
}

// Run is the harness that executes a collector, stores results, and manages cursor state.
func Run(ctx context.Context, s *store.Store, coll Collector, accountRef string, log *slog.Logger) error {
	id := coll.ID()
	log = log.With("collector", id, "account", accountRef)

	// Load the cursor.
	cursor, err := s.Collectors.GetCursor(ctx, id, accountRef)
	if err != nil {
		log.Warn("failed to load cursor", "err", err)
		cursor = map[string]any{}
	}

	// Start the run record.
	runID, err := s.Collectors.StartRun(ctx, id, accountRef)
	if err != nil {
		return fmt.Errorf("start run: %w", err)
	}
	log = log.With("run_id", runID)

	// Trace the collection (no-op unless OTLP tracing is configured).
	ctx, span := tracing.Tracer("nhiid/collector").Start(ctx, "collect",
		trace.WithAttributes(
			attribute.String("collector", id),
			attribute.String("account", accountRef),
			attribute.String("run_id", runID.String()),
		))
	defer span.End()

	// Collect.
	start := time.Now()
	defer func() { metrics.CollectorDuration.WithLabelValues(id).Observe(time.Since(start).Seconds()) }()
	result, err := coll.Collect(ctx, accountRef, cursor)
	if err != nil {
		metrics.CollectorErrors.WithLabelValues(id).Inc()
		span.RecordError(err)
		span.SetStatus(codes.Error, "collect failed")
		log.Error("collection failed", "err", err, "duration", time.Since(start))
		_ = s.Collectors.FinishRun(ctx, runID, "error", 0, 0, 1)
		return err
	}

	// Upsert all records (idempotent — keyed by external_id).
	upserted := 0
	for _, id := range result.Identities {
		id.Prov.CollectorRunID = &runID
		id.Prov.Source = coll.ID()
		if _, err := s.Identities.Upsert(ctx, id); err != nil {
			log.Error("upsert identity", "err", err)
		} else {
			upserted++
		}
	}
	for _, c := range result.Credentials {
		c.Source = coll.ID()
		if _, err := s.Credentials.Upsert(ctx, c); err != nil {
			log.Error("upsert credential", "err", err)
		} else {
			upserted++
		}
	}
	for _, sec := range result.Secrets {
		sec.Source = coll.ID()
		if _, err := s.Secrets.Upsert(ctx, sec); err != nil {
			log.Error("upsert secret", "err", err)
		} else {
			upserted++
		}
	}
	for _, r := range result.Roles {
		r.Source = coll.ID()
		if _, err := s.Roles.Upsert(ctx, r); err != nil {
			log.Error("upsert role", "err", err)
		} else {
			upserted++
		}
	}
	for _, e := range result.TrustEdges {
		e.Source = coll.ID()
		if err := s.TrustEdges.Upsert(ctx, e); err != nil {
			log.Error("upsert trust edge", "err", err)
		} else {
			upserted++
		}
	}
	for _, b := range result.ResourceBindings {
		b.Source = coll.ID()
		if err := s.Bindings.Upsert(ctx, b); err != nil {
			log.Error("upsert binding", "err", err)
		} else {
			upserted++
		}
	}
	for _, w := range result.Workloads {
		w.Source = coll.ID()
		if _, err := s.Workloads.Upsert(ctx, w); err != nil {
			log.Error("upsert workload", "err", err)
		} else {
			upserted++
		}
	}
	for _, repo := range result.Repositories {
		repo.Source = coll.ID()
		if _, err := s.Repos.Upsert(ctx, repo); err != nil {
			log.Error("upsert repo", "err", err)
		} else {
			upserted++
		}
	}
	for _, ex := range result.Exposures {
		ex.Source = coll.ID()
		if err := s.Exposures.Upsert(ctx, ex); err != nil {
			log.Error("upsert exposure", "err", err)
		} else {
			upserted++
		}
	}
	for _, ev := range result.UsageEvents {
		ev.Source = coll.ID()
		if err := s.Usage.Insert(ctx, ev); err != nil {
			log.Error("upsert usage event", "err", err)
		} else {
			upserted++
		}
	}

	// Save the new cursor.
	if err := s.Collectors.SetCursor(ctx, id, accountRef, result.NewCursor); err != nil {
		log.Warn("failed to save cursor", "err", err)
	}

	// Finish the run.
	span.SetAttributes(attribute.Int("records_in", len(result.Identities)), attribute.Int("upserted", upserted))
	metrics.RecordsUpserted.WithLabelValues(id).Add(float64(upserted))
	if err := s.Collectors.FinishRun(ctx, runID, "success", len(result.Identities), upserted, 0); err != nil {
		log.Warn("failed to finish run record", "err", err)
	}

	log.Info("collection complete", "duration", time.Since(start), "records_in", len(result.Identities), "upserted", upserted)
	return nil
}
