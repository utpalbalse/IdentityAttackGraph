package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/nhiid/nhiid/internal/collectors"
	awscollector "github.com/nhiid/nhiid/internal/collectors/aws"
	"github.com/nhiid/nhiid/internal/collectors/fixture"
	gcpcollector "github.com/nhiid/nhiid/internal/collectors/gcp"
	k8scollector "github.com/nhiid/nhiid/internal/collectors/k8s"
	repocollector "github.com/nhiid/nhiid/internal/collectors/repo"
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/log"
	"github.com/nhiid/nhiid/internal/store"
)

func main() {
	provider := flag.String("provider", "aws", "aws, gcp, k8s, repo, or fixture")
	account := flag.String("account", "", "account id / project id")
	fixtureFile := flag.String("fixture", "fixtures/demo_env.json", "fixture file for demo collector")
	roleARN := flag.String("role-arn", "", "AWS role ARN to assume for cross-account collection")
	externalID := flag.String("external-id", "", "ExternalId for the assume-role trust (recommended)")
	region := flag.String("region", "us-east-1", "AWS region for API calls")
	ctLookback := flag.Int("cloudtrail-lookback-hours", 24, "hours of CloudTrail history on first run")
	project := flag.String("project", "", "GCP project id")
	gcpCreds := flag.String("gcp-credentials", "", "path to GCP credentials/WIF file (else uses ADC)")
	auditLookback := flag.Int("audit-lookback-hours", 24, "hours of GCP Cloud Audit Log history on first run")
	report := flag.String("report", "", "secret-scanner report (SecretSweep JSON or SARIF) for --provider repo")
	scanPath := flag.String("scan-path", "", "path to a checked-out repo to scan directly for --provider repo")
	repoName := flag.String("repo", "", "repository org/name for --provider repo")
	repoProvider := flag.String("repo-provider", "github", "repo provider (github|gitlab)")
	repoVisibility := flag.String("repo-visibility", "private", "repo visibility (public|private|internal)")
	cluster := flag.String("cluster", "", "Kubernetes cluster name for --provider k8s")
	k8sExport := flag.String("k8s-export", "", "path to a `kubectl get ... -o json` export for --provider k8s (omit for live collection)")
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig path for live --provider k8s (empty = in-cluster/default)")
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

	var coll collectors.Collector
	switch *provider {
	case "fixture":
		coll = fixture.New(*fixtureFile)
		if *account == "" {
			*account = "fixture"
		}
	case "aws":
		// account is resolved from STS GetCallerIdentity; -account is optional/informational.
		coll = awscollector.New(awscollector.Options{
			RoleARN:                 *roleARN,
			ExternalID:              *externalID,
			Region:                  *region,
			CloudTrailLookbackHours: *ctLookback,
		}, logger)
		if *account == "" {
			*account = "aws"
		}
	case "gcp":
		projectID := *project
		if projectID == "" {
			projectID = *account
		}
		if projectID == "" {
			logger.Error("gcp requires -project (or -account)")
			os.Exit(1)
		}
		coll = gcpcollector.New(gcpcollector.Options{
			ProjectID:          projectID,
			CredentialsFile:    *gcpCreds,
			AuditLookbackHours: *auditLookback,
		}, logger)
		*account = "gcp:" + projectID
	case "repo":
		if *report == "" && *scanPath == "" {
			logger.Error("repo requires -report (SecretSweep JSON/SARIF) or -scan-path (directory to scan)")
			os.Exit(1)
		}
		coll = repocollector.New(repocollector.Options{
			ReportPath: *report, ScanPath: *scanPath, Provider: *repoProvider, Repo: *repoName, Visibility: *repoVisibility,
		})
		*account = "repo:" + *repoName
	case "k8s":
		clusterName := *cluster
		if clusterName == "" {
			clusterName = "default"
		}
		// Live collection (via client-go) when no export is given.
		coll = k8scollector.New(k8scollector.Options{ClusterName: clusterName, ExportPath: *k8sExport, Kubeconfig: *kubeconfig}, logger)
		*account = "k8s:" + clusterName
	default:
		logger.Error("unknown provider", "provider", *provider)
		os.Exit(1)
	}

	if err := collectors.Run(ctx, s, coll, *account, logger); err != nil {
		logger.Error("collection failed", "err", err)
		os.Exit(1)
	}
}
