package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// ruleNow anchors every age-based assertion so these tests do not drift with the wall clock.
var ruleNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

func ago(days int) *time.Time {
	t := ruleNow.AddDate(0, 0, -days)
	return &t
}

// activeSubject is the minimum viable subject: an active identity with nothing attached. Several
// hygiene detectors key off `State == "active"`, so this must not be omitted.
func activeSubject() Subject {
	return Subject{Identity: models.Identity{ID: uuid.New(), Name: "svc-billing-export", State: "active"}}
}

func ruleConfig() Config {
	return Config{
		StaleWindow:    90 * 24 * time.Hour,
		MaxCredAge:     365 * 24 * time.Hour,
		MaxRotationAge: 180 * 24 * time.Hour,
	}
}

func onlyFinding(t *testing.T, fs []models.Finding) models.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

// ---- orphaned_identity -------------------------------------------------------

func TestOrphanedIdentityFires(t *testing.T) {
	f := onlyFinding(t, orphanedIdentity{}.Detect(activeSubject(), ruleConfig(), ruleNow))
	if f.Detector != "orphaned_identity" || f.Severity != models.SevMedium {
		t.Errorf("got %s/%s, want orphaned_identity/medium", f.Detector, f.Severity)
	}
	if f.IdentityID == nil {
		t.Error("finding must be attributed to the identity")
	}
}

func TestOrphanedIdentitySuppressedByAnyAnchor(t *testing.T) {
	owner := models.Owner{ID: uuid.New(), Email: "team@acme"}
	ownerID := uuid.New()

	cases := map[string]func(*Subject){
		"resolved owner record": func(s *Subject) { s.Owner = &owner },
		"owner id on identity":  func(s *Subject) { s.Identity.OwnerID = &ownerID },
		"running workload":      func(s *Subject) { s.Workloads = []models.Workload{{Name: "api"}} },
		"repo reference":        func(s *Subject) { s.Exposures = []models.Exposure{{Path: ".env"}} },
	}
	for name, mutate := range cases {
		s := activeSubject()
		mutate(&s)
		if fs := (orphanedIdentity{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
			t.Errorf("%s should account for the identity, got %d findings", name, len(fs))
		}
	}
}

func TestOrphanedIdentitySkipsBreakGlassAndInactive(t *testing.T) {
	// Break-glass identities are deliberately unowned and unused — a documented FP control.
	s := activeSubject()
	s.Identity.Attributes = map[string]any{"break_glass": true}
	if fs := (orphanedIdentity{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("break-glass identity should be exempt, got %d findings", len(fs))
	}

	s2 := activeSubject()
	s2.Identity.State = "disabled"
	if fs := (orphanedIdentity{}).Detect(s2, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("a disabled identity is not a live risk, got %d findings", len(fs))
	}
}

// ---- stale_identity ----------------------------------------------------------

func TestStaleIdentitySeverityEscalatesWithAge(t *testing.T) {
	s := activeSubject()
	s.Identity.LastSeenAt = ago(100)
	if f := onlyFinding(t, staleIdentity{}.Detect(s, ruleConfig(), ruleNow)); f.Severity != models.SevLow {
		t.Errorf("100 days idle = %s, want low", f.Severity)
	}

	s.Identity.LastSeenAt = ago(200)
	if f := onlyFinding(t, staleIdentity{}.Detect(s, ruleConfig(), ruleNow)); f.Severity != models.SevMedium {
		t.Errorf("200 days idle = %s, want medium", f.Severity)
	}
}

func TestStaleIdentityNeverUsedButAged(t *testing.T) {
	s := activeSubject()
	s.Identity.CreatedAtSource = ago(60) // created, never used
	f := onlyFinding(t, staleIdentity{}.Detect(s, ruleConfig(), ruleNow))
	if f.Severity != models.SevMedium {
		t.Errorf("never-used identity = %s, want medium", f.Severity)
	}
}

func TestStaleIdentityQuietForFreshIdentities(t *testing.T) {
	s := activeSubject()
	s.Identity.LastSeenAt = ago(10)
	if fs := (staleIdentity{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("recently used identity should not fire, got %d", len(fs))
	}

	// Created 5 days ago and not yet used: inside the grace period.
	s2 := activeSubject()
	s2.Identity.CreatedAtSource = ago(5)
	if fs := (staleIdentity{}).Detect(s2, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("brand-new identity should not fire, got %d", len(fs))
	}
}

func TestStaleIdentitySkipsBreakGlass(t *testing.T) {
	s := activeSubject()
	s.Identity.LastSeenAt = ago(400)
	s.Identity.Attributes = map[string]any{"break_glass": true}
	if fs := (staleIdentity{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("break-glass identities are dormant by design, got %d findings", len(fs))
	}
}

// ---- over_privileged_sa ------------------------------------------------------

func TestOverPrivilegedSAOnAdminRole(t *testing.T) {
	for _, lvl := range []string{"admin", "privileged"} {
		s := activeSubject()
		s.Roles = []models.Role{{Name: "billing-admin", PrivilegeLevel: lvl}}
		f := onlyFinding(t, overPrivilegedSA{}.Detect(s, ruleConfig(), ruleNow))
		if f.Severity != models.SevHigh {
			t.Errorf("privilege_level=%s -> %s, want high", lvl, f.Severity)
		}
		if v, _ := f.Evidence["admin"].(bool); !v {
			t.Errorf("evidence should flag admin, got %v", f.Evidence)
		}
	}
}

func TestOverPrivilegedSAOnEscalationPrimitive(t *testing.T) {
	s := activeSubject()
	s.Roles = []models.Role{{Name: "ci", PolicyDocument: map[string]any{"has_priv_escalation": true}}}
	f := onlyFinding(t, overPrivilegedSA{}.Detect(s, ruleConfig(), ruleNow))
	if v, _ := f.Evidence["priv_escalation"].(bool); !v {
		t.Errorf("evidence should flag the escalation primitive, got %v", f.Evidence)
	}
}

func TestOverPrivilegedSAOnCrownJewelWrite(t *testing.T) {
	s := activeSubject()
	s.Bindings = []models.ResourceBinding{{
		Effect: "allow", ResourceCriticality: models.CritCrownJewel,
		Actions: []string{"s3:PutObject"}, ResourceURN: "arn:aws:s3:::prod-billing",
	}}
	f := onlyFinding(t, overPrivilegedSA{}.Detect(s, ruleConfig(), ruleNow))
	if v, _ := f.Evidence["write_crown_jewel"].(bool); !v {
		t.Errorf("evidence should flag the crown-jewel write, got %v", f.Evidence)
	}
}

func TestOverPrivilegedSAQuietForLeastPrivilege(t *testing.T) {
	s := activeSubject()
	s.Roles = []models.Role{{Name: "reader", PrivilegeLevel: "read"}}
	// Read access to a crown jewel is not a write primitive.
	s.Bindings = []models.ResourceBinding{{
		Effect: "allow", ResourceCriticality: models.CritCrownJewel, Actions: []string{"s3:GetObject"},
	}}
	if fs := (overPrivilegedSA{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("least-privilege identity should not fire, got %d: %+v", len(fs), fs)
	}
}

func TestOverPrivilegedSAIgnoresDenyBindings(t *testing.T) {
	s := activeSubject()
	s.Bindings = []models.ResourceBinding{{
		Effect: "deny", ResourceCriticality: models.CritCrownJewel, Actions: []string{"*"},
	}}
	if fs := (overPrivilegedSA{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("a deny binding grants nothing, got %d findings", len(fs))
	}
}

// ---- conditionless_assume_role ----------------------------------------------

func TestConditionlessAssumeRoleFires(t *testing.T) {
	s := activeSubject()
	s.Trust = []models.TrustEdge{{ID: uuid.New(), EdgeType: "can_assume"}}
	f := onlyFinding(t, conditionlessTrust{}.Detect(s, ruleConfig(), ruleNow))
	if f.Severity != models.SevHigh || f.Detector != "conditionless_assume_role" {
		t.Errorf("got %s/%s", f.Detector, f.Severity)
	}
}

func TestConditionlessAssumeRoleRespectsGuards(t *testing.T) {
	s := activeSubject()

	// Guards are []string in-process and []any once round-tripped through JSONB.
	for name, guards := range map[string]any{
		"in-process": []string{"ExternalId"},
		"from jsonb": []any{"MFA"},
	} {
		s.Trust = []models.TrustEdge{{ID: uuid.New(), EdgeType: "can_assume",
			Condition: map[string]any{"guards": guards}}}
		if fs := (conditionlessTrust{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
			t.Errorf("%s guards should suppress the finding, got %d", name, len(fs))
		}
	}

	// Cross-account metadata sits alongside guards in the same map and is not itself a guard.
	s.Trust = []models.TrustEdge{{ID: uuid.New(), EdgeType: "can_assume",
		Condition: map[string]any{"cross_account": true}}}
	if fs := (conditionlessTrust{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 1 {
		t.Errorf("a condition map without guards is still conditionless, got %d", len(fs))
	}
}

func TestConditionlessAssumeRoleOnlyAppliesToAssumption(t *testing.T) {
	s := activeSubject()
	s.Trust = []models.TrustEdge{{ID: uuid.New(), EdgeType: "federated_from"}}
	if fs := (conditionlessTrust{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("non-assume edges are out of scope for this detector, got %d", len(fs))
	}
}

func TestConditionlessAssumeRoleOnePerEdge(t *testing.T) {
	s := activeSubject()
	s.Trust = []models.TrustEdge{
		{ID: uuid.New(), EdgeType: "can_assume"},
		{ID: uuid.New(), EdgeType: "can_assume"},
	}
	fs := conditionlessTrust{}.Detect(s, ruleConfig(), ruleNow)
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want one per trust edge", len(fs))
	}
	if fs[0].Fingerprint == fs[1].Fingerprint {
		t.Error("per-edge findings need distinct fingerprints or dedupe collapses them")
	}
}

// ---- wildcard_trust ----------------------------------------------------------

func TestWildcardTrust(t *testing.T) {
	s := activeSubject()
	s.Trust = []models.TrustEdge{{ID: uuid.New(), EdgeType: "can_assume",
		Condition: map[string]any{"wildcard_principal": true}}}
	f := onlyFinding(t, wildcardTrust{}.Detect(s, ruleConfig(), ruleNow))
	if f.Severity != models.SevHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}

	s.Trust[0].Condition = map[string]any{"wildcard_principal": false}
	if fs := (wildcardTrust{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("a scoped principal should not fire, got %d", len(fs))
	}
}

// ---- secret_exposed_in_repo --------------------------------------------------

func TestSecretExposedInRepoSeverity(t *testing.T) {
	s := activeSubject()
	s.Exposures = []models.Exposure{{Path: ".env", Line: 12, Pattern: "aws_akia", Fingerprint: "abc123"}}
	if f := onlyFinding(t, secretExposedInRepo{}.Detect(s, ruleConfig(), ruleNow)); f.Severity != models.SevHigh {
		t.Errorf("unverified exposure = %s, want high", f.Severity)
	}

	// Verified-live, or public, escalates to critical.
	s.Exposures[0].Verified = true
	if f := onlyFinding(t, secretExposedInRepo{}.Detect(s, ruleConfig(), ruleNow)); f.Severity != models.SevCritical {
		t.Errorf("verified exposure = %s, want critical", f.Severity)
	}
	s.Exposures[0] = models.Exposure{Path: ".env", Pattern: "public"}
	if f := onlyFinding(t, secretExposedInRepo{}.Detect(s, ruleConfig(), ruleNow)); f.Severity != models.SevCritical {
		t.Errorf("public exposure = %s, want critical", f.Severity)
	}
}

// TestSecretExposedInRepoEvidenceCarriesNoMaterial pins the threat-model rule: findings record
// where a credential was found, never the credential.
func TestSecretExposedInRepoEvidenceCarriesNoMaterial(t *testing.T) {
	s := activeSubject()
	s.Exposures = []models.Exposure{{Path: ".env", Line: 12, CommitSHA: "a1b2",
		Pattern: "aws_akia", Fingerprint: "abc123"}}
	f := onlyFinding(t, secretExposedInRepo{}.Detect(s, ruleConfig(), ruleNow))

	allowed := map[string]bool{"path": true, "commit": true, "line": true,
		"pattern": true, "verified": true, "fingerprint": true}
	for k := range f.Evidence {
		if !allowed[k] {
			t.Errorf("unexpected evidence key %q — evidence must stay location-only", k)
		}
	}
	for _, k := range []string{"value", "secret", "material", "credential"} {
		if _, present := f.Evidence[k]; present {
			t.Errorf("evidence must never carry %q", k)
		}
	}
}

func TestSecretExposedInRepoNarrativeEscalatesOnReach(t *testing.T) {
	s := activeSubject()
	s.Exposures = []models.Exposure{{Path: ".env", Pattern: "aws_akia"}}
	plain := onlyFinding(t, secretExposedInRepo{}.Detect(s, ruleConfig(), ruleNow))

	s.Blast = graph.BlastRadius{CrownJewelCount: 1}
	reaching := onlyFinding(t, secretExposedInRepo{}.Detect(s, ruleConfig(), ruleNow))

	if !strings.Contains(reaching.Narrative, "crown-jewel") {
		t.Errorf("narrative should call out crown-jewel reach, got: %q", reaching.Narrative)
	}
	if strings.Contains(plain.Narrative, "crown-jewel") {
		t.Error("an exposure that reaches nothing should not claim crown-jewel reach")
	}
}

// ---- high_blast_radius -------------------------------------------------------

func TestHighBlastRadiusTriggers(t *testing.T) {
	s := activeSubject()
	s.Blast = graph.BlastRadius{CrownJewelCount: 1, NearestCrownJewel: 2}
	s.Paths = []graph.Path{{Hops: 2, Impact: models.CritCrownJewel}}
	f := onlyFinding(t, highBlastRadius{}.Detect(s, ruleConfig(), ruleNow))
	if f.Severity != models.SevHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if f.Evidence["crown_jewels_reachable"] != 1 || f.Evidence["nearest_crown_jewel_hops"] != 2 {
		t.Errorf("evidence should quantify the reach, got %v", f.Evidence)
	}

	// Admin escalation alone is enough, even with no crown jewel.
	s2 := activeSubject()
	s2.Blast = graph.BlastRadius{ReachesAdmin: true, NearestCrownJewel: -1}
	if fs := (highBlastRadius{}).Detect(s2, ruleConfig(), ruleNow); len(fs) != 1 {
		t.Errorf("admin escalation should fire, got %d", len(fs))
	}
}

func TestHighBlastRadiusQuietWhenContained(t *testing.T) {
	s := activeSubject()
	s.Blast = graph.BlastRadius{ReachableResources: 3, NearestCrownJewel: -1}
	if fs := (highBlastRadius{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("reaching only low-value resources should not fire, got %d", len(fs))
	}
}

// ---- ai_agent_overscoped -----------------------------------------------------

func TestAIAgentOverscopedRequiresAnAgent(t *testing.T) {
	s := activeSubject()
	s.Identity.AIAgentMeta = map[string]any{"broad_api_scope": true}
	if fs := (aiAgentOverscoped{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("detector must not fire on non-agent identities, got %d", len(fs))
	}
}

func TestAIAgentOverscopedTriggers(t *testing.T) {
	cases := map[string]map[string]any{
		"broad api scope":    {"broad_api_scope": true},
		"uncontrolled tools": {"uncontrolled_tools": true},
		"long ttl as int":    {"ttl_hours": 720},
		"long ttl as float":  {"ttl_hours": float64(720)}, // the shape that survives JSON decoding
	}
	for name, meta := range cases {
		s := activeSubject()
		s.Identity.IsAIAgent = true
		s.Identity.AIAgentMeta = meta
		f := onlyFinding(t, aiAgentOverscoped{}.Detect(s, ruleConfig(), ruleNow))
		if f.Severity != models.SevHigh || f.Category != "ai_agent" {
			t.Errorf("%s: got %s/%s, want high/ai_agent", name, f.Severity, f.Category)
		}
	}
}

func TestAIAgentWellScopedIsQuiet(t *testing.T) {
	s := activeSubject()
	s.Identity.IsAIAgent = true
	s.Identity.AIAgentMeta = map[string]any{
		"ttl_hours": 12, "broad_api_scope": false, "uncontrolled_tools": false,
	}
	if fs := (aiAgentOverscoped{}).Detect(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("a short-lived, tightly-scoped agent should not fire, got %d", len(fs))
	}
}

// ---- shared helpers ----------------------------------------------------------

func TestHasWriteAction(t *testing.T) {
	for _, a := range []string{"*", "*:*", "s3:*", "s3:PutObject", "s3:DeleteObject", "write", "iam:*"} {
		if !hasWriteAction([]string{a}) {
			t.Errorf("%q should count as a write primitive", a)
		}
	}
	for _, a := range []string{"s3:GetObject", "s3:ListBucket", "iam:GetRole", ""} {
		if hasWriteAction([]string{a}) {
			t.Errorf("%q is read-only and must not count as a write", a)
		}
	}
}

func TestToFloat(t *testing.T) {
	for _, v := range []any{720, int64(720), float64(720)} {
		if got, ok := toFloat(v); !ok || got != 720 {
			t.Errorf("toFloat(%T) = %v/%v, want 720/true", v, got, ok)
		}
	}
	if _, ok := toFloat("720"); ok {
		t.Error("a string TTL must not be silently coerced")
	}
	if _, ok := toFloat(nil); ok {
		t.Error("a missing TTL must not be coerced")
	}
}
