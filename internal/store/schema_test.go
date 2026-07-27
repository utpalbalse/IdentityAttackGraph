//go:build integration

package store

import (
	"context"
	"testing"
)

// TestMigrationsApplyCleanly proves the shipped migrations bring an empty database to the current
// schema. TestMain already applied them; this asserts every file was recorded, so a migration that
// silently no-ops (or one added without being applied) is caught.
func TestMigrationsApplyCleanly(t *testing.T) {
	s, ctx := newTestStore(t)

	files := migrationFiles()
	if len(files) == 0 {
		t.Fatal("no embedded migrations found")
	}

	var applied int
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if applied != len(files) {
		t.Errorf("applied %d migrations, embedded %d — a migration did not run", applied, len(files))
	}
}

// TestNaturalKeyUniqueConstraintsExist is the regression guard for the bug class that cost us a
// wrong risk score: an `ON CONFLICT (cols) DO UPDATE` is only idempotent if a UNIQUE index on
// exactly those columns exists. When it does not, Postgres raises an error — or, with the bare
// `DO NOTHING` form, silently appends a duplicate row on every collection.
//
// Each entry mirrors a conflict target in this package. Adding an upsert without its constraint
// fails here rather than silently doubling rows in production.
func TestNaturalKeyUniqueConstraintsExist(t *testing.T) {
	s, ctx := newTestStore(t)

	want := []struct {
		table string
		cols  []string
	}{
		{"identities", []string{"provider", "external_id"}},
		{"credentials", []string{"cred_type", "external_id"}},
		{"secrets", []string{"store", "external_id"}},
		{"roles", []string{"provider", "external_id"}},
		{"workloads", []string{"kind", "external_id"}},
		{"repositories", []string{"provider", "external_id"}},
		{"findings", []string{"fingerprint"}},
		{"config_settings", []string{"key"}},
		{"remediation_actions", []string{"finding_id", "action"}},
		{"graph_nodes", []string{"node_type", "entity_id"}},
		{"graph_edges", []string{"src_node_id", "dst_node_id", "edge_type"}},
		{"collector_state", []string{"collector", "account_ref"}},
		// These two are the ones that regressed: half-nullable natural keys needing
		// UNIQUE NULLS NOT DISTINCT (migration 0008) to dedupe at all.
		{"trust_edges", []string{"src_identity_id", "src_role_id", "dst_identity_id", "dst_role_id", "edge_type"}},
		{"resource_bindings", []string{"identity_id", "role_id", "resource_urn", "effect"}},
		// Deduped via bare ON CONFLICT DO NOTHING, which needs *some* unique index to bite.
		{"exposures", []string{"fingerprint"}},
	}

	for _, w := range want {
		t.Run(w.table, func(t *testing.T) {
			got, err := uniqueIndexColumnSets(ctx, s, w.table)
			if err != nil {
				t.Fatalf("inspect %s: %v", w.table, err)
			}
			if !containsColumnSet(got, w.cols) {
				t.Errorf("%s has no UNIQUE index on %v — ON CONFLICT cannot dedupe, so re-collection "+
					"will error or silently duplicate rows.\n  unique indexes present: %v",
					w.table, w.cols, got)
			}
		})
	}
}

// TestTrustEdgeKeyTreatsNullsAsEqual pins the NULLS NOT DISTINCT behaviour that migration 0008
// added. A trust edge has a half-nullable natural key (an edge is identity→role or role→identity,
// never both), and under default SQL semantics NULL != NULL, so a plain UNIQUE index would let
// every re-collection insert a fresh duplicate.
func TestTrustEdgeKeyTreatsNullsAsEqual(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, table := range []string{"trust_edges", "resource_bindings"} {
		var nullsNotDistinct bool
		err := s.Pool().QueryRow(ctx, `
			SELECT COALESCE(bool_or(i.indnullsnotdistinct), false)
			FROM pg_index i
			JOIN pg_class c ON c.oid = i.indrelid
			WHERE c.relname = $1 AND i.indisunique`, table).Scan(&nullsNotDistinct)
		if err != nil {
			t.Fatalf("inspect %s: %v", table, err)
		}
		if !nullsNotDistinct {
			t.Errorf("%s: no UNIQUE ... NULLS NOT DISTINCT index; NULL columns in the natural key "+
				"would compare unequal and every re-run would insert a duplicate", table)
		}
	}
}

// ---- helpers ----------------------------------------------------------------

// uniqueIndexColumnSets returns the column list of every unique index on a table.
func uniqueIndexColumnSets(ctx context.Context, s *Store, table string) ([][]string, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT array_agg(a.attname ORDER BY k.ord)
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
		WHERE c.relname = $1 AND i.indisunique
		GROUP BY i.indexrelid`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out [][]string
	for rows.Next() {
		var cols []string
		if err := rows.Scan(&cols); err != nil {
			return nil, err
		}
		out = append(out, cols)
	}
	return out, rows.Err()
}

// containsColumnSet reports whether any index covers exactly the wanted columns (order-insensitive).
func containsColumnSet(got [][]string, want []string) bool {
	for _, g := range got {
		if len(g) != len(want) {
			continue
		}
		seen := make(map[string]bool, len(g))
		for _, c := range g {
			seen[c] = true
		}
		all := true
		for _, w := range want {
			if !seen[w] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
