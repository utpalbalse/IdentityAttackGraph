// Package aws collects AWS IAM, CloudTrail, and related metadata from a single account.
// It uses assume-role for cross-account access (no stored credentials).
package aws

import (
	"context"
	"fmt"

	"github.com/nhiid/nhiid/internal/collectors"
	"github.com/nhiid/nhiid/internal/models"
)

type Collector struct {
	roleARN    string
	externalID string
}

// New creates an AWS collector for a specific account role.
func New(roleARN, externalID string) *Collector {
	return &Collector{roleARN: roleARN, externalID: externalID}
}

func (c *Collector) ID() string { return "aws" }

// Collect performs a full snapshot of IAM, CloudTrail (if cursor is old), and Secrets Manager
// in a single account. On subsequent runs, it fetches only deltas from CloudTrail.
func (c *Collector) Collect(ctx context.Context, accountRef string, cursor map[string]any) (collectors.Result, error) {
	// TODO: assume the role using STS; establish CloudTrail, IAM, Secrets Manager clients.
	// For now, return empty (placeholder for Phase 1 full implementation).
	return collectors.Result{
		Identities: []models.Identity{},
		NewCursor:  map[string]any{"type": "cloudtrail_timestamp", "timestamp": "2025-06-11T00:00:00Z"},
	}, nil
}
