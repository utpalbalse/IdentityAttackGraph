package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/nhiid/nhiid/internal/collectors"
)

// Options configures the Kubernetes collector.
type Options struct {
	ClusterName string // logical cluster name; forms the account ref "k8s:<name>"
	ExportPath  string // path to a kubectl `-o json` export (see package doc)
}

// Collector implements collectors.Collector for a Kubernetes cluster export.
type Collector struct {
	opts Options
	log  *slog.Logger
}

func New(opts Options, log *slog.Logger) *Collector {
	return &Collector{opts: opts, log: log}
}

func (c *Collector) ID() string { return "k8s" }

// Collect parses the cluster export and normalizes ServiceAccounts, effective RBAC, pod workloads,
// token credentials, and cloud federation (IRSA / Workload Identity) edges.
func (c *Collector) Collect(ctx context.Context, accountRef string, cursor map[string]any) (collectors.Result, error) {
	if c.opts.ExportPath == "" {
		return collectors.Result{}, fmt.Errorf("k8s: export path is required")
	}
	cluster := c.opts.ClusterName
	if cluster == "" {
		cluster = "default"
	}

	data, err := os.ReadFile(c.opts.ExportPath)
	if err != nil {
		return collectors.Result{}, fmt.Errorf("k8s: read export: %w", err)
	}
	snap, err := parseExport(data)
	if err != nil {
		return collectors.Result{}, err
	}

	b := newBuilder(cluster)
	b.load(snap)
	res := b.finalize(cursor)

	if c.log != nil {
		c.log.Info("k8s collection complete", "cluster", cluster,
			"identities", len(res.Identities), "roles", len(res.Roles),
			"trust_edges", len(res.TrustEdges), "bindings", len(res.ResourceBindings),
			"workloads", len(res.Workloads), "credentials", len(res.Credentials))
	}
	return res, nil
}
