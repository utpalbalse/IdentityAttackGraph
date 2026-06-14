// Package fixture is a demo collector that loads a synthetic multi-account AWS+GCP environment
// from a JSON file. It is used for local development and demos (no cloud credentials required).
package fixture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nhiid/nhiid/internal/collectors"
	"github.com/nhiid/nhiid/internal/models"
)

type Collector struct {
	path string
}

func New(path string) *Collector {
	return &Collector{path: path}
}

func (c *Collector) ID() string { return "fixture" }

type FixtureData struct {
	Identities       []models.Identity        `json:"identities"`
	Credentials      []models.Credential      `json:"credentials"`
	Roles            []models.Role            `json:"roles"`
	TrustEdges       []models.TrustEdge       `json:"trust_edges"`
	ResourceBindings []models.ResourceBinding `json:"resource_bindings"`
	UsageEvents      []models.UsageEvent      `json:"usage_events"`
}

func (c *Collector) Collect(ctx context.Context, accountRef string, cursor map[string]any) (collectors.Result, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return collectors.Result{}, fmt.Errorf("read fixture %s: %w", c.path, err)
	}
	var fixture FixtureData
	if err := json.Unmarshal(data, &fixture); err != nil {
		return collectors.Result{}, fmt.Errorf("parse fixture: %w", err)
	}
	now := time.Now()
	return collectors.Result{
		Identities:       fixture.Identities,
		Credentials:      fixture.Credentials,
		Roles:            fixture.Roles,
		TrustEdges:       fixture.TrustEdges,
		ResourceBindings: fixture.ResourceBindings,
		UsageEvents:      fixture.UsageEvents,
		NewCursor:        map[string]any{"loaded_at": now.Format(time.RFC3339)},
	}, nil
}
