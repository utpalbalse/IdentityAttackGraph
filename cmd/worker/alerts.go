package main

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/metrics"
	"github.com/nhiid/nhiid/internal/notify"
	"github.com/nhiid/nhiid/internal/store"
)

// runAlerts dispatches not-yet-alerted open findings (at or above the configured severity) to the
// notifier. alerted_at is stamped only after a successful Send, so a notifier outage is retried on
// the next sweep rather than dropped (at-least-once).
func runAlerts(ctx context.Context, s *store.Store, notifier notify.Notifier, severities []string, logger *slog.Logger) error {
	rows, err := s.Findings.ClaimUnalerted(ctx, severities, 100)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}

	alerts := make([]notify.Alert, 0, len(rows))
	ids := make([]uuid.UUID, 0, len(rows))
	for _, f := range rows {
		alerts = append(alerts, notify.Alert{
			FindingID: f.ID.String(), Detector: f.Detector, Severity: f.Severity, Category: f.Category,
			Title: f.Title, Narrative: f.Narrative, IdentityName: f.IdentityName, Account: f.Account,
			FirstSeen: f.FirstSeenAt, Evidence: f.Evidence,
		})
		ids = append(ids, f.ID)
	}

	if err := notifier.Send(ctx, alerts); err != nil {
		metrics.AlertsFailed.Add(float64(len(alerts)))
		return err // leave alerted_at NULL -> retried next sweep
	}
	if err := s.Findings.MarkAlerted(ctx, ids); err != nil {
		// Sent but not stamped: a later sweep may re-send. Log loudly; not fatal.
		logger.Warn("alerts sent but mark-alerted failed (may re-send)", "err", err)
	}
	for _, a := range alerts {
		metrics.AlertsSent.WithLabelValues(a.Severity).Inc()
	}
	logger.Info("alerts dispatched", "count", len(alerts), "kind", notifier.Kind())
	return nil
}
