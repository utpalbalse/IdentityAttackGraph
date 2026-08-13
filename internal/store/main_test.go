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
// own database (default `nhiid_test`) and never touches the dev/demo database. Shared setup lives
// in internal/dbtest.
package store

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/utpalbalse/IdentityAttackGraph/internal/dbtest"
)

// testStore is opened once for the package; tests reset state between runs.
var testStore *Store

func TestMain(m *testing.M) {
	ctx := context.Background()
	dsn := dbtest.DSNFor("store")

	if err := dbtest.Prepare(ctx, dsn); err != nil {
		fmt.Fprint(os.Stderr, dbtest.Unavailable(err))
		os.Exit(1)
	}

	s, err := New(ctx, dsn, 8, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open test store: %v\n", err)
		os.Exit(1)
	}
	testStore = s

	code := m.Run()
	s.Close()
	os.Exit(code)
}

// ---- per-test helpers -------------------------------------------------------

// newTestStore returns the shared store with all data cleared, so each test starts from a known
// empty schema and tests can run in any order.
func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	if err := dbtest.TruncateAll(ctx, testStore.Pool()); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return testStore, ctx
}

// countRows reports how many rows a table holds — the primary assertion for idempotency.
func countRows(t *testing.T, s *Store, ctx context.Context, table string) int {
	t.Helper()
	n, err := dbtest.CountRows(ctx, s.Pool(), table)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// migrationFiles is re-exported for the schema test's "everything was applied" assertion.
func migrationFiles() []string { return dbtest.MigrationFiles() }
