package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

// TestEngineRegistersDocumentedDetectors pins the detector inventory that README.md and
// docs/DETECTIONS.md advertise. Adding or renaming a detector without updating the docs breaks here.
//
// The engine registers 16; the 17th documented detector, unused_secret, is secret-scoped rather
// than identity-scoped, so the worker emits it directly via UnusedSecretFinding.
func TestEngineRegistersDocumentedDetectors(t *testing.T) {
	rules := []string{
		"orphaned_identity", "stale_identity", "stale_access_key", "over_privileged_sa",
		"conditionless_assume_role", "wildcard_trust", "secret_exposed_in_repo",
		"high_blast_radius", "ai_agent_overscoped",
	}
	anomalies := []string{
		"impossible_travel", "unusual_geo", "new_asn_or_runtime", "usage_spike",
		"first_use_sensitive_action", "privilege_creep", "suspicious_role_chain",
	}

	registered := map[string]bool{}
	for _, d := range NewEngine().detectors {
		if registered[d.ID()] {
			t.Errorf("detector %q registered twice", d.ID())
		}
		registered[d.ID()] = true
	}

	for _, id := range append(append([]string{}, rules...), anomalies...) {
		if !registered[id] {
			t.Errorf("documented detector %q is not registered", id)
		}
		delete(registered, id)
	}
	for id := range registered {
		t.Errorf("detector %q is registered but not documented", id)
	}

	if len(anomalies) != 7 {
		t.Errorf("docs claim 7 anomaly detectors, list has %d", len(anomalies))
	}
	if len(rules)+1 != 10 { // +1 for unused_secret
		t.Errorf("docs claim 10 rule detectors, list has %d", len(rules)+1)
	}
}

// noisySubject trips three detectors at three different severities.
func noisySubject() Subject {
	lastUsed := ruleNow.AddDate(0, 0, -200)
	return Subject{
		Identity: models.Identity{
			ID: uuid.New(), Name: "svc-billing-export", State: "active",
			LastSeenAt: ago(1), // recent, so stale_identity stays quiet
		},
		Roles:     []models.Role{{Name: "billing-admin", PrivilegeLevel: "admin"}}, // high
		Exposures: []models.Exposure{{Path: ".env", Pattern: "aws_akia", Fingerprint: "fp1", Verified: true}},
		Creds: []models.Credential{{
			ExternalID: "AKIA1", CredType: "aws_access_key", Status: "active", LastUsedAt: &lastUsed,
		}}, // medium
	}
}

func TestEngineRunRanksBySeverity(t *testing.T) {
	fs := NewEngine().Run(noisySubject(), ruleConfig(), ruleNow)
	if len(fs) < 3 {
		t.Fatalf("expected at least 3 findings, got %d: %+v", len(fs), fs)
	}
	for i := 1; i < len(fs); i++ {
		if sevRank(fs[i-1].Severity) < sevRank(fs[i].Severity) {
			t.Errorf("findings out of order at %d: %s before %s", i, fs[i-1].Severity, fs[i].Severity)
		}
	}
	if fs[0].Severity != models.SevCritical {
		t.Errorf("highest-severity finding = %s, want critical (the verified exposure)", fs[0].Severity)
	}
}

func TestEngineRunDedupesByFingerprint(t *testing.T) {
	s := noisySubject()
	// The same leaked credential discovered twice (e.g. two scanner passes over one repo).
	s.Exposures = append(s.Exposures, models.Exposure{
		Path: ".env", Pattern: "aws_akia", Fingerprint: "fp1", Verified: true,
	})

	fs := NewEngine().Run(s, ruleConfig(), ruleNow)
	seen := 0
	for _, f := range fs {
		if f.Detector == "secret_exposed_in_repo" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("identical exposures produced %d findings, want 1 after dedupe", seen)
	}
}

func TestEngineRunStampsTimestamps(t *testing.T) {
	fs := NewEngine().Run(noisySubject(), ruleConfig(), ruleNow)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range fs {
		if !f.FirstSeenAt.Equal(ruleNow) {
			t.Errorf("%s FirstSeenAt = %v, want %v", f.Detector, f.FirstSeenAt, ruleNow)
		}
		if !f.LastSeenAt.Equal(ruleNow) {
			t.Errorf("%s LastSeenAt = %v, want %v", f.Detector, f.LastSeenAt, ruleNow)
		}
		if f.Status != "open" {
			t.Errorf("%s status = %q, want open", f.Detector, f.Status)
		}
		if f.Narrative == "" {
			t.Errorf("%s has no attacker-framed narrative", f.Detector)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s has no fingerprint — dedupe would break", f.Detector)
		}
	}
}

func TestEngineRunOnQuietIdentity(t *testing.T) {
	s := Subject{Identity: models.Identity{
		ID: uuid.New(), Name: "svc-quiet", State: "active",
		LastSeenAt: ago(1), OwnerID: func() *uuid.UUID { u := uuid.New(); return &u }(),
	}}
	if fs := NewEngine().Run(s, ruleConfig(), ruleNow); len(fs) != 0 {
		t.Errorf("a well-managed identity should produce no findings, got %+v", fs)
	}
}

// ---- fingerprints ------------------------------------------------------------

func TestFingerprintIsStableAndDiscriminating(t *testing.T) {
	id := uuid.New()

	a := Fingerprint("over_privileged_sa", &id, []string{"role:admin"})
	if a != Fingerprint("over_privileged_sa", &id, []string{"role:admin"}) {
		t.Error("the same inputs must always produce the same fingerprint")
	}
	if len(a) != 32 {
		t.Errorf("fingerprint length = %d, want 32", len(a))
	}

	if a == Fingerprint("over_privileged_sa", &id, []string{"role:other"}) {
		t.Error("different salient evidence must not collide")
	}
	if a == Fingerprint("high_blast_radius", &id, []string{"role:admin"}) {
		t.Error("different detectors must not collide")
	}
	other := uuid.New()
	if a == Fingerprint("over_privileged_sa", &other, []string{"role:admin"}) {
		t.Error("different identities must not collide")
	}
}

func TestFingerprintHandlesIdentityAgnosticFindings(t *testing.T) {
	// Repo and vault findings have no owning identity; they must still fingerprint stably.
	a := Fingerprint("secret_exposed_in_repo", nil, []string{"fp1"})
	if a == "" || a != Fingerprint("secret_exposed_in_repo", nil, []string{"fp1"}) {
		t.Error("nil-identity fingerprints must be stable")
	}
	id := uuid.New()
	if a == Fingerprint("secret_exposed_in_repo", &id, []string{"fp1"}) {
		t.Error("an identity-linked finding must not collide with an identity-agnostic one")
	}
}

func TestSevRankOrdering(t *testing.T) {
	if !(sevRank(models.SevCritical) > sevRank(models.SevHigh) &&
		sevRank(models.SevHigh) > sevRank(models.SevMedium) &&
		sevRank(models.SevMedium) > sevRank(models.SevLow) &&
		sevRank(models.SevLow) > sevRank(models.SevInfo)) {
		t.Error("severity ranking must be strictly ordered")
	}
}

// ---- ExposureFinding (repo-scoped, identity-agnostic) ------------------------

func TestExposureFindingIsIdentityAgnostic(t *testing.T) {
	ex := models.Exposure{Path: "config/.env", Line: 12, CommitSHA: "a1b2",
		Pattern: "generic_token", Fingerprint: "fp9"}

	f := ExposureFinding(ex, nil, "acme/billing")
	if f.IdentityID != nil {
		t.Error("a secret with no resolved owner must still produce a finding, unattributed")
	}
	if f.Detector != "secret_exposed_in_repo" || f.Confidence != 85 {
		t.Errorf("got %s/%d", f.Detector, f.Confidence)
	}
	if !strings.Contains(f.Narrative, "acme/billing") {
		t.Errorf("narrative should locate the repo, got %q", f.Narrative)
	}
	if f.Evidence["repository"] != "acme/billing" {
		t.Errorf("evidence repository = %v", f.Evidence["repository"])
	}
}

func TestExposureFindingSeverityEscalation(t *testing.T) {
	base := models.Exposure{Path: ".env", Fingerprint: "fp1"}

	// The high-value list is matched as a substring, so "generic_token" escalates via "token".
	weak := base
	weak.Pattern = "generic_token"
	if f := ExposureFinding(weak, nil, ""); f.Severity != models.SevCritical {
		t.Errorf("generic_token = %s, want critical (substring match on \"token\")", f.Severity)
	}

	plain := base
	plain.Pattern = "hex_blob"
	if f := ExposureFinding(plain, nil, ""); f.Severity != models.SevHigh {
		t.Errorf("low-signal pattern = %s, want high", f.Severity)
	}

	// Verified-live always escalates, whatever the pattern.
	verified := plain
	verified.Verified = true
	if f := ExposureFinding(verified, nil, ""); f.Severity != models.SevCritical {
		t.Errorf("verified exposure = %s, want critical", f.Severity)
	}

	// So does a high-value credential class.
	awsKey := base
	awsKey.Pattern = "aws_akia"
	if f := ExposureFinding(awsKey, nil, ""); f.Severity != models.SevCritical {
		t.Errorf("aws key pattern = %s, want critical", f.Severity)
	}
}

func TestExposureFindingCarriesNoSecretMaterial(t *testing.T) {
	f := ExposureFinding(models.Exposure{Path: ".env", Line: 3, Pattern: "aws_akia",
		Fingerprint: "fp1", CommitSHA: "deadbeef"}, nil, "acme/api")

	allowed := map[string]bool{"path": true, "line": true, "commit": true,
		"pattern": true, "verified": true, "fingerprint": true, "repository": true}
	for k := range f.Evidence {
		if !allowed[k] {
			t.Errorf("unexpected evidence key %q — exposures record location only", k)
		}
	}
}

func TestIsHighValuePattern(t *testing.T) {
	for _, p := range []string{"aws_akia", "GCP_SA", "private_key", "service_account",
		"secret_key", "ssh_rsa", "github_token", "rsa"} {
		if !isHighValuePattern(p) {
			t.Errorf("%q should be treated as high value", p)
		}
	}
	for _, p := range []string{"hex_blob", "entropy_high", ""} {
		if isHighValuePattern(p) {
			t.Errorf("%q should not be treated as high value", p)
		}
	}
}

func TestUnusedSecretFindingRespectsWindow(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	win := 90 * 24 * time.Hour

	// Never accessed and unreferenced: fires, with no owning identity.
	f, ok := UnusedSecretFinding(models.Secret{Store: "sm", ExternalID: "s1", Name: "prod/db"}, win, now)
	if !ok || f.IdentityID != nil || f.Detector != "unused_secret" {
		t.Fatalf("ok=%v finding=%+v", ok, f)
	}

	// Just inside the window: still in use.
	inside := now.Add(-89 * 24 * time.Hour)
	if _, ok := UnusedSecretFinding(models.Secret{LastAccessedAt: &inside}, win, now); ok {
		t.Error("a secret accessed inside the window must not fire")
	}
}
