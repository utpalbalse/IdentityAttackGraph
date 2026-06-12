// Package gcp collects GCP IAM, Cloud Audit Logs, and related metadata from a single project.
// It uses workload identity federation for authentication (no stored credentials).
package gcp

import (
	"context"

	"github.com/nhiid/nhiid/internal/collectors"
	"github.com/nhiid/nhiid/internal/models"
)

type Collector struct {
	projectID string
}

// New creates a GCP collector for a specific project.
func New(projectID string) *Collector {
	return &Collector{projectID: projectID}
}

func (c *Collector) ID() string { return "gcp" }

// Collect performs a snapshot of IAM service accounts, keys, bindings, and Cloud Audit Logs.
func (c *Collector) Collect(ctx context.Context, accountRef string, cursor map[string]any) (collectors.Result, error) {
	// TODO: use WIF to authenticate; establish clients for IAM, Asset Inventory, Cloud Audit Logs.
	// For now, return empty (placeholder for Phase 2).
	return collectors.Result{
		Identities: []models.Identity{},
		NewCursor:  map[string]any{"type": "cloud_audit_log_timestamp", "timestamp": "2025-06-11T00:00:00Z"},
	}, nil
}
