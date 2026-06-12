package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/log"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: migrate [up|down|status]\n")
		os.Exit(1)
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		args = []string{"up"}
	}
	cmd := args[0]

	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(cfg.Telemetry.LogLevel, cfg.Telemetry.LogFormat)
	slog.SetDefault(logger)

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, cfg.Database.DSN)
	if err != nil {
		logger.Error("connect to database", "err", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	// Read and execute migrations from migrations/*.sql (alphabetically)
	// For MVP, we do this manually; in prod, use sql-migrate or similar.
	migrationSQL := readMigrations()
	switch cmd {
	case "up":
		if migrationSQL != "" {
			_, err := conn.Exec(ctx, migrationSQL)
			if err != nil {
				logger.Error("run migrations", "err", err)
				os.Exit(1)
			}
			logger.Info("migrations applied")
		} else {
			logger.Info("no migrations to apply (0001_init.sql needs manual import)")
		}
	case "status":
		logger.Info("migration status check (stub)")
	default:
		logger.Error("unknown command", "cmd", cmd)
		os.Exit(1)
	}
}

func readMigrations() string {
	// Placeholder: in real code, read from migrations/*.sql in order.
	// For MVP, we skip this and rely on manual schema import or docker init script.
	return ""
}
