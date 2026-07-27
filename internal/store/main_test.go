//go:build integration

// Integration tests for the persistence layer. These exercise the real SQL against a real
// PostgreSQL, which is the only way to catch the class of bug that lives in the gap between a query
// and the schema it assumes — an ON CONFLICT clause naming a constraint that does not exist, a
// natural key that fails to dedupe, an ORDER BY that is unstable under ties. Unit tests with a
// mocked DB cannot see any of it: a mock returns what you told it to.
//
// Run:
//
//	go test -tags=integration ./internal/store/...
//
// Target DB via NHIID_TEST_DATABASE_DSN, else a local docker-compose Postgres. The suite uses its
// own database (default `nhiid_test`) and never touches the dev/demo database, creating it on first
// run and applying the embedded migrations.
package store

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nhiid/nhiid/migrations"
)

const defaultTestDSN = "postgres://nhiid:nhiid@localhost:5432/nhiid_test?sslmode=disable"

// testStore is opened once for the package and shared; tests reset state between runs.
var testStore *Store

func testDSN() string {
	if d := os.Getenv("NHIID_TEST_DATABASE_DSN"); d != "" {
		return d
	}
	return defaultTestDSN
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	if err := ensureTestDatabase(ctx, testDSN()); err != nil {
		fmt.Fprintf(os.Stderr, "integration tests need a reachable PostgreSQL.\n"+
			"  start one with: docker compose -f deploy/docker-compose.yml up -d postgres\n"+
			"  or set NHIID_TEST_DATABASE_DSN.\n  error: %v\n", err)
		os.Exit(1)
	}

	s, err := New(ctx, testDSN(), 8, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open test store: %v\n", err)
		os.Exit(1)
	}
	testStore = s

	if err := applyMigrations(ctx, testDSN()); err != nil {
		fmt.Fprintf(os.Stderr, "apply migrations: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	s.Close()
	os.Exit(code)
}

// ensureTestDatabase creates the target database if it does not exist, connecting to the server's
// default `postgres` database to do so. Keeping the suite in its own database is what makes it safe
// to TRUNCATE aggressively between tests.
func ensureTestDatabase(ctx context.Context, dsn string) error {
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)`, target).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	// CREATE DATABASE cannot be parameterised.
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, pgx.Identifier{target}.Sanitize())); err != nil {
		return fmt.Errorf("create database %s: %w", target, err)
	}
	return nil
}

// applyMigrations runs the embedded SQL migrations, mirroring cmd/migrate. Running the real
// migrations (rather than a hand-maintained test schema) is deliberate: it means these tests also
// prove the shipped migrations apply cleanly from scratch.
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

	for _, name := range migrationFiles() {
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

func migrationFiles() []string {
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
	sort.Strings(names)
	return names
}

// ---- per-test helpers -------------------------------------------------------

// newTestStore returns the shared store with all data cleared, so each test starts from a known
// empty schema and tests can run in any order.
func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	truncateAll(t, testStore, ctx)
	return testStore, ctx
}

func truncateAll(t *testing.T, s *Store, ctx context.Context) {
	t.Helper()
	rows, err := s.Pool().Query(ctx, `
		SELECT tablename FROM pg_tables
		WHERE schemaname='public' AND tablename <> 'schema_migrations'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, pgx.Identifier{name}.Sanitize())
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) == 0 {
		return
	}
	// One statement so foreign-key ordering resolves itself; CASCADE covers partitions.
	if _, err := s.Pool().Exec(ctx, "TRUNCATE TABLE "+strings.Join(tables, ", ")+" CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// countRows reports how many rows a table holds — the primary assertion for idempotency.
func countRows(t *testing.T, s *Store, ctx context.Context, table string) int {
	t.Helper()
	var n int
	q := "SELECT count(*) FROM " + pgx.Identifier{table}.Sanitize()
	if err := s.Pool().QueryRow(ctx, q).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
