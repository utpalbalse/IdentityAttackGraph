package gcp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nhiid/nhiid/internal/collectors"
)

// Collector implements collectors.Collector for a single GCP project.
type Collector struct {
	opts Options
	log  *slog.Logger
}

// New constructs a GCP collector. Authentication is via ADC/WIF (or an optional credentials file);
// no long-lived keys are stored by NHIID.
func New(opts Options, log *slog.Logger) *Collector {
	return &Collector{opts: opts, log: log}
}

func (c *Collector) ID() string { return "gcp" }

// Collect runs IAM discovery (service accounts, keys, impersonation trust, project bindings) and
// Cloud Audit Log usage ingestion (incremental). Audit-log failure is non-fatal.
func (c *Collector) Collect(ctx context.Context, accountRef string, cursor map[string]any) (collectors.Result, error) {
	if c.opts.ProjectID == "" {
		return collectors.Result{}, fmt.Errorf("gcp: project id is required")
	}
	cl, err := newClients(ctx, c.opts)
	if err != nil {
		return collectors.Result{}, err
	}
	b := newBuilder(c.opts.ProjectID)

	if err := cl.collectIAM(ctx, b, c.opts.ProjectID); err != nil {
		return collectors.Result{}, fmt.Errorf("collect iam: %w", err)
	}

	newCursor, err := cl.collectAudit(ctx, b, c.opts.ProjectID, c.opts.AuditLookbackHours, cursor)
	if err != nil {
		if c.log != nil {
			c.log.Warn("gcp audit log collection degraded", "err", err)
		}
		newCursor = cursor
	}

	res := b.result(newCursor)
	if c.log != nil {
		c.log.Info("gcp collection complete", "project", c.opts.ProjectID,
			"identities", len(res.Identities), "credentials", len(res.Credentials),
			"roles", len(res.Roles), "trust_edges", len(res.TrustEdges),
			"bindings", len(res.ResourceBindings), "usage_events", len(res.UsageEvents))
	}
	return res, nil
}
