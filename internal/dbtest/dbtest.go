//go:build integration

// Package dbtest provides the shared plumbing for DB-backed tests: it creates a scratch database,
// applies the embedded migrations to it, and clears state between tests.
//
// It deliberately does not import internal/store. That keeps it usable from `package store`'s own
// tests (which would otherwise form an import cycle) and from any package that layers on top —
// callers pass in the pgx pool they already hold.
//
// Everything here is behind the `integration` build tag, so a plain `go test ./...` neither
// compiles nor requires it.
package dbtest

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/utpalbalse/IdentityAttackGraph/migrations"
)

// DefaultDSN targets a scratch database on the local docker-compose Postgres. It is intentionally
// *not* the dev/demo database: the helpers here truncate freely.
const DefaultDSN = "postgres://nhiid:nhiid@localhost:5432/nhiid_test?sslmode=disable"

// DSN returns the base database under test, overridable for CI or a remote server.
func DSN() string {
	if d := os.Getenv("NHIID_TEST_DATABASE_DSN"); d != "" {
		return d
	}
	return DefaultDSN
}

// DSNFor derives a package-private database from the base DSN (nhiid_test -> nhiid_test_api).
//
// `go test ./...` runs package binaries in parallel, so two suites sharing one database would
// truncate each other's rows mid-test — a failure that only appears in a full-repo run and looks
// maddeningly like flakiness. One database per package removes the interference entirely while
// keeping the parallelism.
func DSNFor(suffix string) string {
	base := DSN()
	u, err := url.Parse(base)
	if err != nil || u.Path == "" || u.Path == "/" {
		return base
	}
	u.Path = "/" + strings.TrimPrefix(u.Path, "/") + "_" + suffix
	return u.String()
}

// Prepare makes the target database exist and brings it up to the current schema. Safe to call
// from every test package: creating and migrating are both idempotent.
func Prepare(ctx context.Context, dsn string) error {
	if err := ensureDatabase(ctx, dsn); err != nil {
		return err
	}
	return applyMigrations(ctx, dsn)
}

// Unavailable renders a consistent, actionable message when Postgres cannot be reached.
func Unavailable(err error) string {
	return fmt.Sprintf("integration tests need a reachable PostgreSQL.\n"+
		"  start one with: docker compose -f deploy/docker-compose.yml up -d postgres\n"+
		"  or set NHIID_TEST_DATABASE_DSN.\n  error: %v\n", err)
}

// ensureDatabase creates the target database if absent, connecting to the server's default
// `postgres` database to do it.
func ensureDatabase(ctx context.Context, dsn string) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("parse dsn: %w", err)
	}
	target := cfg.Database
	if target == "" {
		return fmt.Errorf("dsn has no database name")
	}

	adminCfg := cfg.Copy()
	adminCfg.Database = "postgres"
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		return fmt.Errorf("connect to maintenance db: %w", err)
	}
	defer admin.Close(ctx)

	var exists bool
	if err := admin.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)`, target).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	// CREATE DATABASE cannot be parameterised.
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{target}.Sanitize()); err != nil {
		return fmt.Errorf("create database %s: %w", target, err)
	}
	return nil
}

// applyMigrations runs the embedded SQL migrations, mirroring cmd/migrate. Running the real
// migrations rather than a hand-maintained test schema means these tests also prove the shipped
// migrations apply cleanly from scratch.
func applyMigrations(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return err
	}

	done := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		done[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, name := range MigrationFiles() {
		if done[name] {
			continue
		}
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
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
	}
	return nil
}

// MigrationFiles lists the embedded migrations in apply order.
func MigrationFiles() []string {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // lexical order = apply order (0001_, 0002_, ...)
	return names
}

// TruncateAll clears every table except the migration ledger, so each test starts from a known
// empty schema and tests can run in any order.
func TruncateAll(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT tablename FROM pg_tables
		WHERE schemaname='public' AND tablename <> 'schema_migrations'`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, pgx.Identifier{name}.Sanitize())
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(tables) == 0 {
		return nil
	}
	// One statement so foreign-key ordering resolves itself; CASCADE covers partitions.
	_, err = pool.Exec(ctx, "TRUNCATE TABLE "+strings.Join(tables, ", ")+" CASCADE")
	return err
}

// CountRows reports how many rows a table holds — the primary assertion for idempotency.
func CountRows(ctx context.Context, pool *pgxpool.Pool, table string) (int, error) {
	var n int
	err := pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n)
	return n, err
}
