package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/nhiid/nhiid/internal/collectors"
)

// Options configures the Kubernetes collector. Provide ExportPath to ingest a kubectl `-o json`
// export, or leave it empty to collect from a live cluster via client-go (Kubeconfig path, else
// in-cluster config, else the default kubeconfig).
type Options struct {
	ClusterName string // logical cluster name; forms the account ref "k8s:<name>"
	ExportPath  string // path to a kubectl `-o json` export (see package doc)
	Kubeconfig  string // kubeconfig path for live collection (empty => in-cluster/default)
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

// Collect normalizes ServiceAccounts, effective RBAC, pod workloads, token credentials, and cloud
// federation (IRSA / Workload Identity) edges — from a kubectl export (ExportPath) or a live cluster
// via client-go. Both sources feed the identical normalization.
func (c *Collector) Collect(ctx context.Context, accountRef string, cursor map[string]any) (collectors.Result, error) {
	cluster := c.opts.ClusterName
	if cluster == "" {
		cluster = "default"
	}

	var (
		snap snapshot
		mode string
		err  error
	)
	if c.opts.ExportPath != "" {
		mode = "export"
		data, rerr := os.ReadFile(c.opts.ExportPath)
		if rerr != nil {
			return collectors.Result{}, fmt.Errorf("k8s: read export: %w", rerr)
		}
		snap, err = parseExport(data)
	} else {
		mode = "live"
		cs, cerr := buildClientset(c.opts.Kubeconfig)
		if cerr != nil {
			return collectors.Result{}, fmt.Errorf("k8s: %w", cerr)
		}
		snap, err = liveSnapshot(ctx, cs)
	}
	if err != nil {
		return collectors.Result{}, err
	}

	b := newBuilder(cluster)
	b.load(snap)
	res := b.finalize(cursor)

	if c.log != nil {
		c.log.Info("k8s collection complete", "cluster", cluster, "mode", mode,
			"identities", len(res.Identities), "roles", len(res.Roles),
			"trust_edges", len(res.TrustEdges), "bindings", len(res.ResourceBindings),
			"workloads", len(res.Workloads), "credentials", len(res.Credentials))
	}
	return res, nil
}
