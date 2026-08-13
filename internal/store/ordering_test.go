//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/utpalbalse/IdentityAttackGraph/internal/models"
)

// Ordering is a correctness property here, not cosmetics. "Fix the top item first" is the product's
// core instruction, so the top item must not depend on which row Postgres happened to return first.
// Without an explicit tiebreak, rows that tie on the sort key come back in physical order, which
// changes as rows are updated — so the triage queue, the UI, and the committed screenshots would all
// drift between runs on the same data.

// seedScored inserts an identity with a fixed risk score and urgency.
func seedScored(t *testing.T, s *Store, ctx context.Context, name string, score, urgency int) uuid.UUID {
	t.Helper()
	arn := "arn:aws:iam::123456789012:user/" + name
	id, err := s.Identities.Upsert(ctx, models.Identity{
		Kind: models.KindAWSIAMUser, Name: name, ARNOrEmail: arn,
		Provider: "aws", State: "active",
		Prov: models.Provenance{Source: "test", ExternalID: arn, AccountRef: "aws:123456789012"},
	})
	if err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	if err := s.Identities.UpdateRiskScore(ctx, id, score, urgency, map[string]any{"privilege": map[string]any{"score": score}}); err != nil {
		t.Fatalf("score %s: %v", name, err)
	}
	return id
}

// seedTriageable is seedScored plus an open finding, which the triage queue requires — it lists
// only identities that have something actionable outstanding.
func seedTriageable(t *testing.T, s *Store, ctx context.Context, name string, score, urgency int) uuid.UUID {
	t.Helper()
	id := seedScored(t, s, ctx, name, score, urgency)
	if _, err := s.Findings.Upsert(ctx, models.Finding{
		Detector: "over_privileged_sa", Category: "privilege", Severity: models.SevHigh,
		Confidence: 80, IdentityID: &id, Title: "over-privileged", Narrative: "test",
		Evidence: map[string]any{}, Fingerprint: "fp-" + name, Status: "open",
	}); err != nil {
		t.Fatalf("seed finding for %s: %v", name, err)
	}
	return id
}

// names extracts the ordered names from a result set.
func names(ids []models.Identity) []string {
	out := make([]string, 0, len(ids))
	for _, i := range ids {
		out = append(out, i.Name)
	}
	return out
}

func equalOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestIdentityListOrderingIsDeterministic pins that identities tied on risk_score come back in a
// stable, name-ordered sequence rather than physical row order.
func TestIdentityListOrderingIsDeterministic(t *testing.T) {
	s, ctx := newTestStore(t)

	// Deliberately all-equal scores: this is the case an unqualified ORDER BY gets wrong.
	for _, n := range []string{"delta", "alpha", "charlie", "bravo"} {
		seedScored(t, s, ctx, n, 50, 0)
	}

	first, err := s.Identities.List(ctx, IdentityFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"alpha", "bravo", "charlie", "delta"}
	if got := names(first); !equalOrder(got, want) {
		t.Errorf("tied scores ordered %v, want %v (name ASC tiebreak)", got, want)
	}

	// Touching a row changes its physical position; the query must not care.
	if err := s.Identities.UpdateRiskScore(ctx, first[0].ID, 50, 0, map[string]any{}); err != nil {
		t.Fatalf("touch: %v", err)
	}
	second, err := s.Identities.List(ctx, IdentityFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list again: %v", err)
	}
	if got := names(second); !equalOrder(got, names(first)) {
		t.Errorf("ordering changed after an unrelated update: %v then %v", names(first), got)
	}
}

func TestIdentityListSortsByRiskDescending(t *testing.T) {
	s, ctx := newTestStore(t)
	seedScored(t, s, ctx, "low", 10, 0)
	seedScored(t, s, ctx, "critical", 90, 0)
	seedScored(t, s, ctx, "medium", 50, 0)

	got, err := s.Identities.List(ctx, IdentityFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"critical", "medium", "low"}
	if !equalOrder(names(got), want) {
		t.Errorf("ordered %v, want %v (highest risk first)", names(got), want)
	}
}

// TestTriageQueueRanksUrgencyOverRawScore pins the product rule that the queue is ordered by
// urgency first — a lower-scoring identity that is urgent outranks a higher-scoring one that isn't.
func TestTriageQueueRanksUrgencyOverRawScore(t *testing.T) {
	s, ctx := newTestStore(t)
	seedTriageable(t, s, ctx, "high-score-not-urgent", 80, 0)
	seedTriageable(t, s, ctx, "lower-score-urgent", 60, 5)

	got, err := s.Identities.TriageQueue(ctx, 50)
	if err != nil {
		t.Fatalf("triage queue: %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	if got[0].Name != "lower-score-urgent" {
		t.Errorf("queue led with %q, want lower-score-urgent — urgency must outrank raw score", got[0].Name)
	}
}

func TestTriageQueueOrderingIsDeterministic(t *testing.T) {
	s, ctx := newTestStore(t)
	// Fully tied on both sort keys: only the name/id tiebreak can decide.
	for _, n := range []string{"echo", "alpha", "delta", "bravo"} {
		seedTriageable(t, s, ctx, n, 70, 3)
	}

	first, err := s.Identities.TriageQueue(ctx, 50)
	if err != nil {
		t.Fatalf("triage queue: %v", err)
	}
	want := []string{"alpha", "bravo", "delta", "echo"}
	if got := names(first); !equalOrder(got, want) {
		t.Errorf("tied triage rows ordered %v, want %v", got, want)
	}

	second, err := s.Identities.TriageQueue(ctx, 50)
	if err != nil {
		t.Fatalf("triage queue again: %v", err)
	}
	if !equalOrder(names(first), names(second)) {
		t.Errorf("triage queue not repeatable: %v then %v", names(first), names(second))
	}
}

// TestFindingsListOrderingIsDeterministic covers the exported artifacts: docs/samples/findings.json
// and the SARIF export are committed to the repo, so an unstable order would produce a spurious diff
// on every regeneration.
func TestFindingsListOrderingIsDeterministic(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedScored(t, s, ctx, "svc", 60, 0)

	// Same severity and confidence: the detector/id tiebreak has to do the work.
	for _, det := range []string{"stale_access_key", "orphaned_identity", "high_blast_radius"} {
		if _, err := s.Findings.Upsert(ctx, models.Finding{
			Detector: det, Category: "hygiene", Severity: models.SevHigh, Confidence: 80,
			IdentityID: &identity, Title: det, Narrative: "test",
			Evidence: map[string]any{}, Fingerprint: "fp-" + det, Status: "open",
		}); err != nil {
			t.Fatalf("seed finding %s: %v", det, err)
		}
	}

	first, err := s.Findings.List(ctx, FindingFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	second, err := s.Findings.List(ctx, FindingFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list findings again: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("got %d findings, want 3", len(first))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("findings order not repeatable at %d: %s then %s",
				i, first[i].Detector, second[i].Detector)
		}
	}
}

// TestFindingsListSortsBySeverity pins that critical findings surface above high ones, which is what
// makes "the top of the triage queue is the thing to fix" true.
func TestFindingsListSortsBySeverity(t *testing.T) {
	s, ctx := newTestStore(t)
	identity := seedScored(t, s, ctx, "svc", 60, 0)

	seed := func(det string, sev models.Severity) {
		t.Helper()
		if _, err := s.Findings.Upsert(ctx, models.Finding{
			Detector: det, Category: "exposure", Severity: sev, Confidence: 80,
			IdentityID: &identity, Title: det, Narrative: "test",
			Evidence: map[string]any{}, Fingerprint: "fp-" + det, Status: "open",
		}); err != nil {
			t.Fatalf("seed %s: %v", det, err)
		}
	}
	seed("stale_access_key", models.SevMedium)
	seed("secret_exposed_in_repo", models.SevCritical)
	seed("high_blast_radius", models.SevHigh)

	got, err := s.Findings.List(ctx, FindingFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
	if got[0].Severity != models.SevCritical {
		t.Errorf("first finding is %s, want critical — severity must lead the triage order", got[0].Severity)
	}
}
