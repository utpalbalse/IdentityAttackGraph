// Command migrate applies the embedded SQL migrations to the configured database. Each migration
// runs once (tracked in schema_migrations) inside its own transaction, so `up` is idempotent and
// safe to run on every boot.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/log"
	"github.com/nhiid/nhiid/migrations"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: migrate [up|status]\n")
		os.Exit(2)
	}
	flag.Parse()
	cmd := "up"
	if args := flag.Args(); len(args) > 0 {
		cmd = args[0]
	}

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

	files, err := listMigrations()
	if err != nil {
		logger.Error("read embedded migrations", "err", err)
		os.Exit(1)
	}

	switch cmd {
	case "up":
		if err := up(ctx, conn, files, logger); err != nil {
			logger.Error("migrate up", "err", err)
			os.Exit(1)
		}
	case "status":
		if err := status(ctx, conn, files, logger); err != nil {
			logger.Error("migrate status", "err", err)
			os.Exit(1)
		}
	default:
		flag.Usage()
	}
}

func listMigrations() ([]string, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > 4 && e.Name()[len(e.Name())-4:] == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // lexical order = apply order (0001_, 0002_, ...)
	return names, nil
}

func ensureTable(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`)
	return err
}

func applied(ctx context.Context, conn *pgx.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	done := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		done[v] = true
	}
	return done, rows.Err()
}

func up(ctx context.Context, conn *pgx.Conn, files []string, logger *slog.Logger) error {
	if err := ensureTable(ctx, conn); err != nil {
		return err
	}
	done, err := applied(ctx, conn)
	if err != nil {
		return err
	}
	n := 0
	for _, name := range files {
		if done[name] {
			continue
		}
		sqlBytes, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		// Each migration + its bookkeeping row commit atomically.
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		logger.Info("applied migration", "version", name)
		n++
	}
	if n == 0 {
		logger.Info("database is up to date", "migrations", len(files))
	} else {
		logger.Info("migrations applied", "count", n)
	}
	return nil
}

func status(ctx context.Context, conn *pgx.Conn, files []string, _ *slog.Logger) error {
	done, err := applied(ctx, conn)
	if err != nil {
		// schema_migrations may not exist yet — treat everything as pending.
		done = map[string]bool{}
	}
	for _, name := range files {
		state := "pending"
		if done[name] {
			state = "applied"
		}
		fmt.Printf("%-24s %s\n", name, state)
	}
	return nil
}
