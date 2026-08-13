//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/utpalbalse/IdentityAttackGraph/internal/models"
)

// Idempotent collection is a load-bearing property of this system, not an optimisation: collectors
// re-run on a schedule (--interval / CronJob), every entity is keyed by a deterministic UUID, and
// the README, the Helm docs, and the AWS collector docs all promise that a repeat run updates rows
// in place. These tests hold that promise to the database.
//
// The motivating incident: TrustEdgeRepo.Upsert and BindingRepo.Upsert once used a bare
// `ON CONFLICT DO NOTHING` with no unique constraint to conflict on, so every collection appended
// duplicate edges (4→8→12). That inflated one identity's trust factor until it clamped, publishing
// a risk score of 70 where the correct answer was 62. Every unit test passed throughout: the bug
// lived only in the gap between the SQL and the schema, and only appeared on the *second* run.

// ---- fixtures ---------------------------------------------------------------

func seedIdentity(t *testing.T, s *Store, ctx context.Context, externalID string) uuid.UUID {
	t.Helper()
	id, err := s.Identities.Upsert(ctx, models.Identity{
		Kind:       models.KindAWSIAMUser,
		Name:       "svc-billing-export",
		ARNOrEmail: externalID,
		Provider:   "aws",
		State:      "active",
		Prov:       models.Provenance{Source: "test", ExternalID: externalID, AccountRef: "aws:123456789012"},
	})
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return id
}

func seedRole(t *testing.T, s *Store, ctx context.Context, externalID string, owner *uuid.UUID) uuid.UUID {
	t.Helper()
	id, err := s.Roles.Upsert(ctx, models.Role{
		Provider: "aws", ExternalID: externalID, AccountRef: "aws:123456789012",
		Name: "billing-admin", PrivilegeLevel: "admin", IsAssumable: true,
		OwnerIdentityID: owner, Source: "test",
	})
	if err != nil {
		t.Fatalf("seed role: %v", err)
	}
	return id
}

// ---- per-repo idempotency ---------------------------------------------------

func TestIdentityUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	const arn = "arn:aws:iam::123456789012:user/svc-billing-export"

	first := seedIdentity(t, s, ctx, arn)
	second := seedIdentity(t, s, ctx, arn)

	if n := countRows(t, s, ctx, "identities"); n != 1 {
		t.Errorf("re-upserting one identity produced %d rows, want 1", n)
	}
	if first != second {
		t.Errorf("identity id changed across upserts: %s -> %s; downstream rows reference this id, "+
			"so it must be stable", first, second)
	}
}

// TestIdentityUpsertUpdatesMutableFields is the other half of idempotency: a repeat run must
// refresh changed attributes rather than ignore them (the DO UPDATE, not DO NOTHING).
func TestIdentityUpsertUpdatesMutableFields(t *testing.T) {
	s, ctx := newTestStore(t)
	const arn = "arn:aws:iam::123456789012:user/svc-billing-export"
	prov := models.Provenance{Source: "test", ExternalID: arn, AccountRef: "aws:123456789012"}

	id, err := s.Identities.Upsert(ctx, models.Identity{
		Kind: models.KindAWSIAMUser, Name: "old-name", ARNOrEmail: arn,
		Provider: "aws", State: "active", Prov: prov,
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if _, err := s.Identities.Upsert(ctx, models.Identity{
		Kind: models.KindAWSIAMUser, Name: "new-name", ARNOrEmail: arn,
		Provider: "aws", State: "disabled", Prov: prov,
	}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var name, state string
	if err := s.Pool().QueryRow(ctx, `SELECT name, state FROM identities WHERE id=$1`, id).Scan(&name, &state); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if name != "new-name" || state != "disabled" {
		t.Errorf("got name=%q state=%q, want new-name/disabled — re-collection must refresh mutable fields", name, state)
	}
}

func TestCredentialUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc")

	cred := models.Credential{
		IdentityID: identity, CredType: "aws_access_key", ExternalID: "AKIAIOSFODNN7EXAMPLE",
		Status: "active", AccountRef: "aws:123456789012", Source: "test",
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Credentials.Upsert(ctx, cred); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	if n := countRows(t, s, ctx, "credentials"); n != 1 {
		t.Errorf("3 upserts of one access key produced %d rows, want 1", n)
	}
}

func TestSecretUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	sec := models.Secret{
		Store: "aws_secretsmanager", ExternalID: "arn:aws:secretsmanager:us-east-1:1:secret:prod/app",
		AccountRef: "aws:123456789012", Name: "prod/app", RotationEnabled: true, VersionCount: 3,
		Source: "test",
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Secrets.Upsert(ctx, sec); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	if n := countRows(t, s, ctx, "secrets"); n != 1 {
		t.Errorf("3 upserts of one secret produced %d rows, want 1", n)
	}
}

func TestRoleUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	const arn = "arn:aws:iam::123456789012:role/billing-admin"

	first := seedRole(t, s, ctx, arn, nil)
	second := seedRole(t, s, ctx, arn, nil)

	if n := countRows(t, s, ctx, "roles"); n != 1 {
		t.Errorf("re-upserting one role produced %d rows, want 1", n)
	}
	if first != second {
		t.Errorf("role id changed across upserts: %s -> %s", first, second)
	}
}

// TestTrustEdgeUpsertIsIdempotent is the direct regression test for the incident. The natural key
// is half-nullable (identity→role here, so src_role_id and dst_identity_id are NULL), which is
// exactly the shape that defeated the original constraint-less upsert.
func TestTrustEdgeUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc-billing-export")
	role := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/billing-admin", nil)

	edge := models.TrustEdge{
		SrcIdentityID: &identity,
		DstRoleID:     &role,
		EdgeType:      "can_assume",
		Condition:     map[string]any{},
		Observed:      true,
		AccountRef:    "aws:123456789012",
		Source:        "test",
	}
	// Three passes mirrors three collector runs — the original bug produced 1, 2, then 3 rows.
	for i := 0; i < 3; i++ {
		if err := s.TrustEdges.Upsert(ctx, edge); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		if n := countRows(t, s, ctx, "trust_edges"); n != 1 {
			t.Fatalf("after %d collection(s) trust_edges has %d rows, want 1 — duplicate edges "+
				"inflate the trust factor and corrupt the risk score", i+1, n)
		}
	}
}

// TestTrustEdgeUpsertKeepsDistinctEdgesApart guards the opposite failure: a key so coarse that
// genuinely different edges collapse into one, silently losing graph structure.
func TestTrustEdgeUpsertKeepsDistinctEdgesApart(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc")
	roleA := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/a", nil)
	roleB := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/b", nil)

	base := models.TrustEdge{
		SrcIdentityID: &identity, EdgeType: "can_assume", Condition: map[string]any{},
		AccountRef: "aws:123456789012", Source: "test",
	}
	toA, toB := base, base
	toA.DstRoleID = &roleA
	toB.DstRoleID = &roleB
	differentType := toA
	differentType.EdgeType = "federated_from"

	for _, e := range []models.TrustEdge{toA, toB, differentType} {
		if err := s.TrustEdges.Upsert(ctx, e); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	if n := countRows(t, s, ctx, "trust_edges"); n != 3 {
		t.Errorf("3 distinct edges produced %d rows, want 3 — the natural key is collapsing "+
			"different edges", n)
	}
}

// TestBindingUpsertIsIdempotent is the second half of the incident: resource bindings doubled
// alongside trust edges (6→12), which is what drove blast radius up.
func TestBindingUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	role := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/billing-admin", nil)

	binding := models.ResourceBinding{
		RoleID:              &role,
		ResourceURN:         "arn:aws:s3:::prod-billing",
		ResourceKind:        "s3_bucket",
		ResourceCriticality: models.CritCrownJewel,
		Actions:             []string{"s3:*"},
		Effect:              "allow",
		AccountRef:          "aws:123456789012",
		Source:              "test",
	}
	for i := 0; i < 3; i++ {
		if err := s.Bindings.Upsert(ctx, binding); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		if n := countRows(t, s, ctx, "resource_bindings"); n != 1 {
			t.Fatalf("after %d collection(s) resource_bindings has %d rows, want 1", i+1, n)
		}
	}
}

func TestBindingUpsertKeepsDistinctResourcesApart(t *testing.T) {
	s, ctx := newTestStore(t)
	role := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/r", nil)

	base := models.ResourceBinding{
		RoleID: &role, ResourceKind: "s3_bucket", ResourceCriticality: models.CritHigh,
		Actions: []string{"s3:GetObject"}, Effect: "allow",
		AccountRef: "aws:123456789012", Source: "test",
	}
	billing, scratch := base, base
	billing.ResourceURN = "arn:aws:s3:::prod-billing"
	scratch.ResourceURN = "arn:aws:s3:::dev-scratch"

	for _, b := range []models.ResourceBinding{billing, scratch} {
		if err := s.Bindings.Upsert(ctx, b); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	if n := countRows(t, s, ctx, "resource_bindings"); n != 2 {
		t.Errorf("2 distinct resources produced %d rows, want 2", n)
	}
}

// TestBindingUpsertRefreshesCriticality covers the crown-jewel tagging path: tagging a bucket
// between runs must upgrade the existing binding, not leave a stale criticality behind.
func TestBindingUpsertRefreshesCriticality(t *testing.T) {
	s, ctx := newTestStore(t)
	role := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/r", nil)

	b := models.ResourceBinding{
		RoleID: &role, ResourceURN: "arn:aws:s3:::prod-billing", ResourceKind: "s3_bucket",
		ResourceCriticality: models.CritHigh, Actions: []string{"s3:*"}, Effect: "allow",
		AccountRef: "aws:123456789012", Source: "test",
	}
	if err := s.Bindings.Upsert(ctx, b); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	b.ResourceCriticality = models.CritCrownJewel // operator tagged the bucket
	if err := s.Bindings.Upsert(ctx, b); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var crit string
	if err := s.Pool().QueryRow(ctx,
		`SELECT resource_criticality FROM resource_bindings WHERE resource_urn=$1`, b.ResourceURN).Scan(&crit); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if crit != string(models.CritCrownJewel) {
		t.Errorf("criticality = %q, want crown_jewel — a newly tagged resource must upgrade in place", crit)
	}
}

func TestWorkloadUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc")

	w := models.Workload{
		Kind: "k8s_pod", ExternalID: "demo/prod/deploy-runner-abc12", AccountRef: "k8s:demo",
		Name: "deploy-runner", Environment: "prod", IdentityID: &identity, Source: "test",
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Workloads.Upsert(ctx, w); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	if n := countRows(t, s, ctx, "workloads"); n != 1 {
		t.Errorf("3 upserts of one workload produced %d rows, want 1", n)
	}
}

func TestRepositoryUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := models.Repository{
		Provider: "github", ExternalID: "acme/billing", Org: "acme", Name: "billing",
		Visibility: "private", DefaultBranch: "main", Source: "test",
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Repos.Upsert(ctx, repo); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	if n := countRows(t, s, ctx, "repositories"); n != 1 {
		t.Errorf("3 upserts of one repository produced %d rows, want 1", n)
	}
}

// TestExposureUpsertIsIdempotent matters for the leaked-credential story: re-scanning a repo must
// not multiply the same finding. This one dedupes on fingerprint via a bare ON CONFLICT DO NOTHING,
// so it depends entirely on uq_exposures_fingerprint existing (see schema_test.go).
func TestExposureUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc")
	repoID, err := s.Repos.Upsert(ctx, models.Repository{
		Provider: "github", ExternalID: "acme/billing", Org: "acme", Name: "billing",
		Visibility: "private", Source: "test",
	})
	if err != nil {
		t.Fatalf("seed repo: %v", err)
	}

	e := models.Exposure{
		RepositoryID: &repoID, IdentityID: &identity, Path: ".env", CommitSHA: "a1b2c3d",
		Line: 12, Pattern: "aws_akia", Fingerprint: "sha256:deadbeefcafef00d",
		Verified: true, Source: "test",
	}
	for i := 0; i < 3; i++ {
		if err := s.Exposures.Upsert(ctx, e); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	if n := countRows(t, s, ctx, "exposures"); n != 1 {
		t.Errorf("3 scans of the same leaked key produced %d rows, want 1", n)
	}
}

// TestFindingUpsertIsIdempotent covers detector dedupe: every detection pass re-raises the same
// findings, and they are keyed by fingerprint so the triage queue does not grow without bound.
func TestFindingUpsertIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc")

	f := models.Finding{
		Detector: "conditionless_assume_role", Category: "trust", Severity: models.SevHigh,
		Confidence: 90, IdentityID: &identity, Title: "Role assumable with no condition",
		Narrative: "test", Evidence: map[string]any{"role": "billing-admin"},
		Fingerprint: "fp-conditionless-1", Status: "open",
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Findings.Upsert(ctx, f); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	if n := countRows(t, s, ctx, "findings"); n != 1 {
		t.Errorf("3 detection passes produced %d findings, want 1", n)
	}
}

func TestGraphUpsertsAreIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc")
	role := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/billing-admin", nil)

	// The graph job rebuilds the projection on every worker cycle (every 60s), so non-idempotent
	// node/edge upserts would grow the graph unboundedly.
	var srcID, dstID uuid.UUID
	for i := 0; i < 3; i++ {
		var err error
		srcID, err = s.Graph.UpsertNode(ctx, models.GraphNode{
			NodeType: "identity", EntityID: &identity, AccountRef: "aws:123456789012",
			Label: "svc-billing-export", Criticality: models.CritLow,
		})
		if err != nil {
			t.Fatalf("upsert src node %d: %v", i, err)
		}
		dstID, err = s.Graph.UpsertNode(ctx, models.GraphNode{
			NodeType: "role", EntityID: &role, AccountRef: "aws:123456789012",
			Label: "billing-admin", Criticality: models.CritHigh,
		})
		if err != nil {
			t.Fatalf("upsert dst node %d: %v", i, err)
		}
		if err := s.Graph.UpsertEdge(ctx, models.GraphEdge{
			SrcNodeID: srcID, DstNodeID: dstID, EdgeType: "assumes", Weight: 1, Observed: true,
		}); err != nil {
			t.Fatalf("upsert edge %d: %v", i, err)
		}
	}

	if n := countRows(t, s, ctx, "graph_nodes"); n != 2 {
		t.Errorf("3 graph rebuilds produced %d nodes, want 2", n)
	}
	if n := countRows(t, s, ctx, "graph_edges"); n != 1 {
		t.Errorf("3 graph rebuilds produced %d edges, want 1", n)
	}
}

// TestRepeatedCollectionCycleIsStable is the end-to-end version of the incident: run a whole
// account's worth of entities three times, as the scheduled collector does, and assert every table
// is byte-stable. This is the test that would have caught the original bug — the per-repo tests
// above pin each cause, this one pins the symptom the user actually saw.
func TestRepeatedCollectionCycleIsStable(t *testing.T) {
	s, ctx := newTestStore(t)

	collect := func() {
		t.Helper()
		identity := seedIdentity(t, s, ctx, "arn:aws:iam::123456789012:user/svc-billing-export")
		role := seedRole(t, s, ctx, "arn:aws:iam::123456789012:role/billing-admin", nil)

		if _, err := s.Credentials.Upsert(ctx, models.Credential{
			IdentityID: identity, CredType: "aws_access_key", ExternalID: "AKIAIOSFODNN7EXAMPLE",
			Status: "active", AccountRef: "aws:123456789012", Source: "test",
		}); err != nil {
			t.Fatalf("credential: %v", err)
		}
		if err := s.TrustEdges.Upsert(ctx, models.TrustEdge{
			SrcIdentityID: &identity, DstRoleID: &role, EdgeType: "can_assume",
			Condition: map[string]any{}, Observed: true,
			AccountRef: "aws:123456789012", Source: "test",
		}); err != nil {
			t.Fatalf("trust edge: %v", err)
		}
		if err := s.Bindings.Upsert(ctx, models.ResourceBinding{
			RoleID: &role, ResourceURN: "arn:aws:s3:::prod-billing", ResourceKind: "s3_bucket",
			ResourceCriticality: models.CritCrownJewel, Actions: []string{"s3:*"}, Effect: "allow",
			AccountRef: "aws:123456789012", Source: "test",
		}); err != nil {
			t.Fatalf("binding: %v", err)
		}
	}

	tables := []string{"identities", "roles", "credentials", "trust_edges", "resource_bindings"}

	collect()
	want := map[string]int{}
	for _, tbl := range tables {
		want[tbl] = countRows(t, s, ctx, tbl)
	}

	for run := 2; run <= 4; run++ {
		collect()
		for _, tbl := range tables {
			if got := countRows(t, s, ctx, tbl); got != want[tbl] {
				t.Errorf("collection run %d: %s has %d rows, want %d (stable across runs)",
					run, tbl, got, want[tbl])
			}
		}
	}
}
