package metrics

import (
	"context"
	"time"

	"github.com/nhiid/nhiid/internal/store"
)

// StartRefresher periodically refreshes the derived gauges (identities, open findings, ingestion
// lag) from the store. Cheap aggregate queries; safe to run in both api and worker.
func StartRefresher(ctx context.Context, s *store.Store, interval time.Duration) {
	go func() {
		refresh(ctx, s)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh(ctx, s)
			}
		}
	}()
}

func refresh(ctx context.Context, s *store.Store) {
	if n, err := s.Identities.Count(ctx); err == nil {
		IdentitiesTotal.Set(float64(n))
	}
	if m, err := s.Findings.CountOpenBySeverity(ctx); err == nil {
		FindingsOpen.Reset()
		for sev, c := range m {
			FindingsOpen.WithLabelValues(sev).Set(float64(c))
		}
	}
	if m, err := s.Usage.NewestEventBySource(ctx); err == nil {
		now := time.Now()
		for src, t := range m {
			IngestionLagSeconds.WithLabelValues(src).Set(now.Sub(t).Seconds())
		}
	}
}
