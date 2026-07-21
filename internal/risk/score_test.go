package risk

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// fixedNow anchors every age-dependent assertion so these tests never drift with the clock.
var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

func daysAgo(d int) *time.Time {
	t := fixedNow.AddDate(0, 0, -d)
	return &t
}

// shippedWeights loads configs/risk_weights.yaml so these tests pin the behaviour that actually
// ships, rather than a synthetic fixture that could silently drift from the real config.
func shippedWeights(t *testing.T) *Weights {
	t.Helper()
	w, err := LoadWeights(filepath.Join("..", "..", "configs", "risk_weights.yaml"))
	if err != nil {
		t.Fatalf("load shipped weights: %v", err)
	}
	return w
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	return NewEngine(shippedWeights(t))
}

// hasSignal reports whether a factor recorded the named signal.
func hasSignal(f Factor, name string) bool {
	for _, s := range f.Signals {
		if s == name {
			return true
		}
	}
	return false
}

func wantFactor(t *testing.T, f Factor, score int, signals ...string) {
	t.Helper()
	if f.Score != score {
		t.Errorf("score = %d, want %d (signals: %v)", f.Score, score, f.Signals)
	}
	for _, s := range signals {
		if !hasSignal(f, s) {
			t.Errorf("missing signal %q (got %v)", s, f.Signals)
		}
	}
	if len(f.Signals) != len(signals) {
		t.Errorf("signals = %v, want exactly %v", f.Signals, signals)
	}
}

// ----- privilege -----

func TestPrivilegeAdminDominates(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Roles: []models.Role{{PrivilegeLevel: "admin"}}}
	wantFactor(t, e.privilege(in), 60, "admin_or_star")
}

func TestPrivilegeWildcardsAreCapped(t *testing.T) {
	e := testEngine(t)
	// 5 wildcard actions * 8 = 40, capped at 24; 4 wildcard resources * 6 = 24, capped at 18.
	in := Input{Now: fixedNow, Roles: []models.Role{{WildcardActionCount: 5, WildcardResourceCount: 4}}}
	wantFactor(t, e.privilege(in), 42, "wildcard_action", "wildcard_resource")
}

func TestPrivilegeEscalationAndCrownJewelWrite(t *testing.T) {
	e := testEngine(t)
	in := Input{
		Now:   fixedNow,
		Roles: []models.Role{{PolicyDocument: map[string]any{"has_priv_escalation": true}}},
		Bindings: []models.ResourceBinding{{
			Effect: "allow", ResourceCriticality: models.CritCrownJewel, Actions: []string{"s3:*"},
		}},
	}
	wantFactor(t, e.privilege(in), 40, "priv_escalation_action", "write_crown_jewel")
}

func TestPrivilegeCrownJewelReadIsNotAWrite(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Bindings: []models.ResourceBinding{{
		Effect: "allow", ResourceCriticality: models.CritCrownJewel, Actions: []string{"s3:GetObject"},
	}}}
	wantFactor(t, e.privilege(in), 0)
}

func TestPrivilegeCreepNeedsAPeerBaseline(t *testing.T) {
	e := testEngine(t)
	roles := []models.Role{{PermissionCount: 300}}

	// No baseline yet (P90 == 0) -> the creep signal must stay silent rather than fire on everyone.
	wantFactor(t, e.privilege(Input{Now: fixedNow, Roles: roles}), 0)

	in := Input{Now: fixedNow, Roles: roles, PeerPermissionP90: 100}
	wantFactor(t, e.privilege(in), 15, "privilege_creep_p90")
}

func TestPrivilegeClampsAt100(t *testing.T) {
	e := testEngine(t)
	in := Input{
		Now: fixedNow,
		Roles: []models.Role{{
			PrivilegeLevel: "admin", WildcardActionCount: 9, WildcardResourceCount: 9,
			PermissionCount: 500, PolicyDocument: map[string]any{"has_priv_escalation": true},
		}},
		Bindings: []models.ResourceBinding{{
			Effect: "allow", ResourceCriticality: models.CritCrownJewel, Actions: []string{"*"},
		}},
		PeerPermissionP90: 10,
	}
	// 60+24+18+20+20+15 = 157, clamped.
	if got := e.privilege(in).Score; got != 100 {
		t.Errorf("privilege = %d, want 100 (clamped)", got)
	}
}

// ----- exposure -----

func TestExposurePrivateRepoPlusStaticKey(t *testing.T) {
	e := testEngine(t)
	in := Input{
		Now:       fixedNow,
		Exposures: []models.Exposure{{Path: ".env", Pattern: "aws_akia"}},
		Creds:     []models.Credential{{CredType: "aws_access_key"}}, // no ExpiresAt -> static
	}
	wantFactor(t, e.exposure(in), 65, "private_repo_or_ci", "static_key_no_expiry")
}

func TestExposureVerifiedLiveIsAdditive(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Exposures: []models.Exposure{{Path: ".env", Verified: true}}}
	wantFactor(t, e.exposure(in), 65, "private_repo_or_ci", "verified_live")
}

func TestExposurePublicOutranksPrivate(t *testing.T) {
	e := testEngine(t)
	// public and private are mutually exclusive: the public branch replaces, not stacks.
	in := Input{Now: fixedNow, Exposures: []models.Exposure{{Pattern: "public"}}}
	wantFactor(t, e.exposure(in), 80, "public_repo")
}

func TestExposureExpiringCredentialIsNotStatic(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Creds: []models.Credential{{CredType: "aws_access_key", ExpiresAt: daysAgo(-30)}}}
	wantFactor(t, e.exposure(in), 0)
}

func TestExposureStaticKeyCountsOnce(t *testing.T) {
	e := testEngine(t)
	// Three static keys are still one "this identity holds static credentials" signal.
	in := Input{Now: fixedNow, Creds: []models.Credential{
		{CredType: "aws_access_key"}, {CredType: "gcp_sa_key"}, {CredType: "api_key"},
	}}
	wantFactor(t, e.exposure(in), 20, "static_key_no_expiry")
}

// ----- freshness -----

func TestFreshnessStaleAndUnrotated(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Identity: models.Identity{LastSeenAt: daysAgo(200)}}
	wantFactor(t, e.freshness(in), 55, "unused_stale_window", "rotation_unmanaged")
}

func TestFreshnessNeverUsedButAged(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Identity: models.Identity{CreatedAtSource: daysAgo(60)}}
	wantFactor(t, e.freshness(in), 45, "never_used_aged", "rotation_unmanaged")
}

func TestFreshnessNeverUsedButNewIsNotPenalised(t *testing.T) {
	e := testEngine(t)
	// Created 5 days ago and not yet used: too early to call it stale.
	in := Input{Now: fixedNow, Identity: models.Identity{
		CreatedAtSource: daysAgo(5), LastRotatedAt: daysAgo(5),
	}}
	wantFactor(t, e.freshness(in), 0)
}

func TestFreshnessRotationOverdue(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Identity: models.Identity{
		LastSeenAt: daysAgo(1), LastRotatedAt: daysAgo(200),
	}}
	wantFactor(t, e.freshness(in), 25, "not_rotated")
}

// ----- usage -----

func TestUsageSignalsAreAdditiveAndClamped(t *testing.T) {
	e := testEngine(t)
	wantFactor(t, e.usage(Input{Now: fixedNow, Anomalies: AnomalySignals{ImpossibleTravel: true}}),
		35, "impossible_travel")

	all := AnomalySignals{
		ImpossibleTravel: true, NewRegion: true, NewASNOrRuntime: true,
		UsageSpike: true, FirstUseSensitive: true, OffHoursBurst: true,
	}
	// 35+20+15+20+25+10 = 125 -> clamped to 100.
	if got := e.usage(Input{Now: fixedNow, Anomalies: all}).Score; got != 100 {
		t.Errorf("usage = %d, want 100 (clamped)", got)
	}
}

func TestUsageQuietIdentityScoresZero(t *testing.T) {
	e := testEngine(t)
	wantFactor(t, e.usage(Input{Now: fixedNow}), 0)
}

// ----- trust -----

func TestTrustConditionlessAssume(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Trust: []models.TrustEdge{{EdgeType: "can_assume"}}}
	wantFactor(t, e.trust(in), 40, "conditionless_assume")
}

func TestTrustGuardSuppressesConditionlessSignal(t *testing.T) {
	e := testEngine(t)

	// Guards arrive as []string in-process...
	in := Input{Now: fixedNow, Trust: []models.TrustEdge{{
		EdgeType: "can_assume", Condition: map[string]any{"guards": []string{"ExternalId"}},
	}}}
	wantFactor(t, e.trust(in), 0)

	// ...and as []any once round-tripped through JSONB. Both must be honoured.
	in.Trust[0].Condition = map[string]any{"guards": []any{"MFA"}}
	wantFactor(t, e.trust(in), 0)

	// An empty guard list is not a guard.
	in.Trust[0].Condition = map[string]any{"guards": []string{}}
	wantFactor(t, e.trust(in), 40, "conditionless_assume")
}

func TestTrustCrossAccountAndWildcard(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Trust: []models.TrustEdge{{
		EdgeType:  "can_assume",
		Condition: map[string]any{"guards": []string{"ExternalId"}, "cross_account": true, "wildcard_principal": true},
	}}}
	wantFactor(t, e.trust(in), 50, "cross_account", "wildcard_external")
}

func TestTrustImpersonationAndTokenMinting(t *testing.T) {
	e := testEngine(t)
	for _, edge := range []string{"can_mint_token", "can_impersonate"} {
		in := Input{Now: fixedNow, Trust: []models.TrustEdge{{EdgeType: edge}}}
		wantFactor(t, e.trust(in), 20, "can_mint_or_impersonate")
	}
}

// ----- blast radius -----

func TestBlastCrownJewelDistanceMatters(t *testing.T) {
	e := testEngine(t)

	direct := Input{Now: fixedNow, Blast: graph.BlastRadius{CrownJewelCount: 1, NearestCrownJewel: 1}}
	wantFactor(t, e.blast(direct), 60, "crown_jewel_1hop")

	// Reachable only by chaining: still serious, but a rung down.
	chained := Input{Now: fixedNow, Blast: graph.BlastRadius{CrownJewelCount: 1, NearestCrownJewel: 3}}
	wantFactor(t, e.blast(chained), 40, "crown_jewel_chain")
}

func TestBlastHighCritIsCapped(t *testing.T) {
	e := testEngine(t)
	// 10 high-criticality resources * 5 = 50, capped at 30.
	in := Input{Now: fixedNow, Blast: graph.BlastRadius{HighCritCount: 10}}
	wantFactor(t, e.blast(in), 30, "high_crit_reachable")
}

func TestBlastReachableOverPeerP90(t *testing.T) {
	e := testEngine(t)
	br := graph.BlastRadius{ReachableResources: 50}

	// Without a baseline the signal stays silent.
	wantFactor(t, e.blast(Input{Now: fixedNow, Blast: br}), 0)

	wantFactor(t, e.blast(Input{Now: fixedNow, Blast: br, PeerReachableP90: 10}), 15, "reachable_over_p90")
}

func TestBlastReachesAdmin(t *testing.T) {
	e := testEngine(t)
	in := Input{Now: fixedNow, Blast: graph.BlastRadius{ReachesAdmin: true}}
	wantFactor(t, e.blast(in), 30, "escalate_to_admin")
}

func TestBlastEmptyRadiusScoresZero(t *testing.T) {
	e := testEngine(t)
	wantFactor(t, e.blast(Input{Now: fixedNow, Blast: graph.BlastRadius{NearestCrownJewel: -1}}), 0)
}

// ----- composite, severity, urgency -----

// leakedKeyInput models the demo's headline identity: a static key in a private repo, on an
// unrotated stale IAM user whose role reaches a crown-jewel bucket and admin.
func leakedKeyInput() Input {
	return Input{
		Now:       fixedNow,
		Identity:  models.Identity{Name: "svc-billing-export", LastSeenAt: daysAgo(200)},
		Roles:     []models.Role{{WildcardActionCount: 1}},
		Bindings:  []models.ResourceBinding{{Effect: "allow", ResourceCriticality: models.CritCrownJewel, Actions: []string{"s3:*"}}},
		Exposures: []models.Exposure{{Path: ".env", Pattern: "aws_akia"}},
		Creds:     []models.Credential{{CredType: "aws_access_key"}},
		Blast:     graph.BlastRadius{CrownJewelCount: 1, NearestCrownJewel: 1, ReachesAdmin: true},
	}
}

func TestScoreCompositeGoldenCase(t *testing.T) {
	b := testEngine(t).Score(leakedKeyInput())

	want := map[string]int{
		"privilege":    28, // wildcard_action 8 + write_crown_jewel 20
		"exposure":     65, // private_repo_or_ci 45 + static_key_no_expiry 20
		"freshness":    55, // unused_stale_window 40 + rotation_unmanaged 15
		"usage":        0,
		"trust":        0,
		"blast_radius": 90, // crown_jewel_1hop 60 + escalate_to_admin 30
	}
	for name, w := range want {
		if got := b.Factors[name].Score; got != w {
			t.Errorf("factor %s = %d, want %d (signals %v)", name, got, w, b.Factors[name].Signals)
		}
	}
	// 0.22*28 + 0.20*65 + 0.10*55 + 0.12*0 + 0.14*0 + 0.22*90 = 44.46 -> 44
	if b.Composite != 44 {
		t.Errorf("composite = %d, want 44", b.Composite)
	}
	if b.Severity != models.SevMedium {
		t.Errorf("severity = %s, want medium", b.Severity)
	}
}

// TestScoreCompositeMatchesWeightedSum is the invariant behind "explainable": the composite must
// always be reproducible by hand from the factors and weights the API returns alongside it.
func TestScoreCompositeMatchesWeightedSum(t *testing.T) {
	e := testEngine(t)
	inputs := []Input{
		leakedKeyInput(),
		{Now: fixedNow},
		{Now: fixedNow, Roles: []models.Role{{PrivilegeLevel: "admin"}}, Anomalies: AnomalySignals{UsageSpike: true}},
		{Now: fixedNow, Trust: []models.TrustEdge{{EdgeType: "can_assume"}}, Blast: graph.BlastRadius{HighCritCount: 3}},
	}
	for i, in := range inputs {
		b := e.Score(in)
		var sum float64
		for name, f := range b.Factors {
			sum += b.Weights[name] * float64(f.Score)
		}
		if want := int(math.Min(100, sum+0.5)); b.Composite != want {
			t.Errorf("input %d: composite = %d, want %d (sum %.4f)", i, b.Composite, want, sum)
		}
		if len(b.Factors) != 6 {
			t.Errorf("input %d: got %d factors, want the 6 documented ones", i, len(b.Factors))
		}
	}
}

// TestScoreIsDeterministic guards the composite against map-iteration order. The weighted sum
// accumulates over a Go map, and float addition is not associative, so an unstable order could
// flip a score that lands near a rounding boundary.
func TestScoreIsDeterministic(t *testing.T) {
	e := testEngine(t)
	in := leakedKeyInput()
	first := e.Score(in)
	for i := 0; i < 500; i++ {
		got := e.Score(in)
		if got.Composite != first.Composite || got.Severity != first.Severity || got.Urgency != first.Urgency {
			t.Fatalf("run %d diverged: %+v vs %+v", i, got, first)
		}
	}
}

func TestSeverityBandBoundaries(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		score int
		want  models.Severity
	}{
		{0, models.SevLow}, {24, models.SevLow},
		{25, models.SevMedium}, {49, models.SevMedium},
		{50, models.SevHigh}, {74, models.SevHigh},
		{75, models.SevCritical}, {100, models.SevCritical},
	}
	for _, c := range cases {
		if got := e.severity(c.score); got != c.want {
			t.Errorf("severity(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestUrgencyLiftsExploitableFindings(t *testing.T) {
	e := testEngine(t)

	// Same composite, but one is a verified-live public leak that reaches a crown jewel.
	quiet := Input{Now: fixedNow}
	if got := e.urgency(40, quiet); got != 40 {
		t.Errorf("urgency = %d, want 40 (no lift)", got)
	}

	hot := Input{
		Now:       fixedNow,
		Exposures: []models.Exposure{{Pattern: "public", Verified: true}},
		Blast:     graph.BlastRadius{CrownJewelCount: 1},
	}
	// +15 verified_live, +10 reachable_crown_jewel, +10 publicly_exposed
	if got := e.urgency(40, hot); got != 75 {
		t.Errorf("urgency = %d, want 75", got)
	}
	if got := e.urgency(95, hot); got != 100 {
		t.Errorf("urgency = %d, want 100 (clamped)", got)
	}
}

// ----- helpers -----

func TestClampAndCap(t *testing.T) {
	if clamp(-5) != 0 || clamp(101) != 100 || clamp(42) != 42 {
		t.Error("clamp must bound to [0,100]")
	}
	if capPts(50, 30) != 30 || capPts(10, 30) != 10 {
		t.Error("capPts must apply the cap")
	}
	if capPts(50, 0) != 50 {
		t.Error("a zero cap means uncapped, not zero")
	}
}
