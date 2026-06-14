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
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/log"
	"github.com/nhiid/nhiid/internal/store"
)

func main() {
	provider := flag.String("provider", "aws", "aws, gcp, or fixture")
	account := flag.String("account", "", "account id / project id")
	fixtureFile := flag.String("fixture", "fixtures/demo_env.json", "fixture file for demo collector")
	roleARN := flag.String("role-arn", "", "AWS role ARN to assume for cross-account collection")
	externalID := flag.String("external-id", "", "ExternalId for the assume-role trust (recommended)")
	region := flag.String("region", "us-east-1", "AWS region for API calls")
	ctLookback := flag.Int("cloudtrail-lookback-hours", 24, "hours of CloudTrail history on first run")
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
		if *account == "" {
			logger.Error("gcp requires -account")
			os.Exit(1)
		}
		// For MVP, use placeholder.
		// coll = gcp.New(projectID)
		logger.Error("gcp collector not yet implemented")
		os.Exit(1)
	default:
		logger.Error("unknown provider", "provider", *provider)
		os.Exit(1)
	}

	if err := collectors.Run(ctx, s, coll, *account, logger); err != nil {
		logger.Error("collection failed", "err", err)
		os.Exit(1)
	}
}
