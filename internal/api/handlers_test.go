//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/auth"
	"github.com/nhiid/nhiid/internal/models"
)

// ---- status codes and error paths -------------------------------------------

// TestGetIdentityStatusCodes pins the three outcomes a client has to distinguish. A malformed id is
// the caller's fault (400) and a missing one is not (404); collapsing either into 500 makes the API
// impossible to program against.
func TestGetIdentityStatusCodes(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	existing := seedIdentity(t, s, ctx, "svc-billing-export", "aws", 62)

	cases := []struct {
		name, path string
		want       int
	}{
		{"existing identity", "/api/v1/identities/" + existing.String(), http.StatusOK},
		{"well-formed but absent", "/api/v1/identities/" + uuid.NewString(), http.StatusNotFound},
		{"malformed uuid", "/api/v1/identities/not-a-uuid", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, c.path, "")
			if rec.Code != c.want {
				t.Errorf("GET %s = %d, want %d (body: %s)", c.path, rec.Code, c.want, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// TestGetIdentityReturnsFullEnvelope guards the detail payload the UI drawer depends on: every
// related collection must be present, so the client never has to distinguish "absent" from "empty".
func TestGetIdentityReturnsFullEnvelope(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	id := seedIdentity(t, s, ctx, "svc-billing-export", "aws", 62)
	seedFinding(t, s, ctx, id, "conditionless_assume_role", models.SevHigh)

	rec := do(t, h, http.MethodGet, "/api/v1/identities/"+id.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	body := decode(t, rec)
	for _, key := range []string{
		"identity", "credentials", "roles", "resource_bindings", "trust_edges",
		"workloads", "exposures", "findings", "remediations", "usage_sample",
	} {
		if _, ok := body[key]; !ok {
			t.Errorf("response is missing %q", key)
		}
	}

	findings, ok := body["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Errorf("findings = %v, want exactly 1", body["findings"])
	}
}

// TestEmptyCollectionsSerializeAsArrays is a real client-breaking contract: `null` and `[]` are not
// interchangeable to a JS consumer that calls .map() on the result.
func TestEmptyCollectionsSerializeAsArrays(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	id := seedIdentity(t, s, ctx, "lonely", "aws", 10) // no findings, creds, or edges

	rec := do(t, h, http.MethodGet, "/api/v1/identities/"+id.String(), "")
	body := decode(t, rec)

	for _, key := range []string{"credentials", "roles", "trust_edges", "findings", "exposures"} {
		v, present := body[key]
		if !present {
			t.Errorf("%s missing entirely", key)
			continue
		}
		if v == nil {
			t.Errorf("%s serialized as null; must be [] so clients can iterate unconditionally", key)
			continue
		}
		if _, ok := v.([]any); !ok {
			t.Errorf("%s = %T, want an array", key, v)
		}
	}
}

func TestListIdentitiesEnvelopeAndEmptyState(t *testing.T) {
	h, _, _ := newAPI(t, "off", nil)

	rec := do(t, h, http.MethodGet, "/api/v1/identities", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	body := decode(t, rec)
	v, ok := body["identities"]
	if !ok {
		t.Fatal(`response has no "identities" key`)
	}
	if v == nil {
		t.Error("identities serialized as null on an empty inventory; want []")
	}
}

// TestListIdentitiesFiltersByProvider covers the query parameter the UI's provider chips use.
func TestListIdentitiesFiltersByProvider(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	seedIdentity(t, s, ctx, "aws-one", "aws", 50)
	seedIdentity(t, s, ctx, "aws-two", "aws", 40)
	seedIdentity(t, s, ctx, "gcp-one", "gcp", 30)

	rec := do(t, h, http.MethodGet, "/api/v1/identities?provider=gcp", "")
	body := decode(t, rec)
	ids, _ := body["identities"].([]any)
	if len(ids) != 1 {
		t.Fatalf("provider=gcp returned %d identities, want 1", len(ids))
	}
	first, _ := ids[0].(map[string]any)
	if first["provider"] != "gcp" {
		t.Errorf("returned a %v identity under provider=gcp", first["provider"])
	}
}

// TestListIdentitiesSortsByRiskDescending pins the ordering the console relies on to put the worst
// identity at the top.
func TestListIdentitiesSortsByRiskDescending(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	seedIdentity(t, s, ctx, "low-risk", "aws", 10)
	seedIdentity(t, s, ctx, "high-risk", "aws", 90)
	seedIdentity(t, s, ctx, "mid-risk", "aws", 50)

	rec := do(t, h, http.MethodGet, "/api/v1/identities", "")
	ids, _ := decode(t, rec)["identities"].([]any)
	if len(ids) != 3 {
		t.Fatalf("got %d identities, want 3", len(ids))
	}
	first, _ := ids[0].(map[string]any)
	if first["name"] != "high-risk" {
		t.Errorf("first identity is %v, want high-risk", first["name"])
	}
}

// TestTriageOmitsIdentitiesWithoutOpenFindings pins the queue's contract: it is a work list, so an
// identity with nothing outstanding must not appear regardless of its score.
func TestTriageOmitsIdentitiesWithoutOpenFindings(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	withFinding := seedIdentity(t, s, ctx, "needs-work", "aws", 40)
	seedFinding(t, s, ctx, withFinding, "over_privileged_sa", models.SevHigh)
	seedIdentity(t, s, ctx, "all-clear", "aws", 95) // higher score, nothing open

	rec := do(t, h, http.MethodGet, "/api/v1/triage", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "needs-work") {
		t.Error("triage queue omitted an identity with an open finding")
	}
	if strings.Contains(body, "all-clear") {
		t.Error("triage queue included an identity with no open findings")
	}
}

func TestVersionEndpoint(t *testing.T) {
	h, _, _ := newAPI(t, "off", nil)
	rec := do(t, h, http.MethodGet, "/api/v1/version", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if v := decode(t, rec)["version"]; v == nil || v == "" {
		t.Error("version endpoint returned no version")
	}
}

func TestRiskReductionOnEmptyDatabase(t *testing.T) {
	h, _, _ := newAPI(t, "off", nil)
	rec := do(t, h, http.MethodGet, "/api/v1/metrics/risk-reduction", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (an empty estate is not an error)", rec.Code)
	}
	if _, ok := decode(t, rec)["risk_reduced"]; !ok {
		t.Error(`response has no "risk_reduced" key`)
	}
}

// TestAttackPathsForIsolatedIdentity checks the graph endpoint degrades cleanly: an identity that
// reaches nothing should return an empty result, not a 500.
func TestAttackPathsForIsolatedIdentity(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	id := seedIdentity(t, s, ctx, "isolated", "aws", 20)

	rec := do(t, h, http.MethodGet, "/api/v1/identities/"+id.String()+"/attack-paths", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (no reachable paths is a valid answer)", rec.Code)
	}
}

// ---- exports ----------------------------------------------------------------

// TestExportFindingsFormats covers the artifacts a security team actually consumes. SARIF in
// particular has a schema other tools parse, so a malformed document is a broken integration.
func TestExportFindingsFormats(t *testing.T) {
	h, s, ctx := newAPI(t, "off", nil)
	id := seedIdentity(t, s, ctx, "svc", "aws", 62)
	seedFinding(t, s, ctx, id, "secret_exposed_in_repo", models.SevCritical)

	t.Run("sarif", func(t *testing.T) {
		rec := do(t, h, http.MethodGet, "/api/v1/export/findings?format=sarif", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", rec.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("SARIF is not valid JSON: %v", err)
		}
		if doc["version"] == nil || doc["runs"] == nil {
			t.Errorf("SARIF missing required version/runs keys: %v", doc)
		}
	})

	t.Run("csv", func(t *testing.T) {
		rec := do(t, h, http.MethodGet, "/api/v1/export/findings?format=csv", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "secret_exposed_in_repo") {
			t.Error("CSV export omitted the seeded finding")
		}
	})

	t.Run("json", func(t *testing.T) {
		rec := do(t, h, http.MethodGet, "/api/v1/export/findings?format=json", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", rec.Code)
		}
		if !json.Valid(rec.Body.Bytes()) {
			t.Error("JSON export is not valid JSON")
		}
	})
}

// ---- auth / RBAC ------------------------------------------------------------

const (
	viewerTok  = "tok-viewer"
	analystTok = "tok-analyst"
	adminTok   = "tok-admin"
)

func testTokens() []auth.TokenEntry {
	return []auth.TokenEntry{
		{Token: viewerTok, Subject: "viewer@test", Role: "viewer"},
		{Token: analystTok, Subject: "analyst@test", Role: "analyst"},
		{Token: adminTok, Subject: "admin@test", Role: "admin"},
	}
}

// TestAuthOffAllowsUnauthenticatedAccess documents the demo default explicitly, so that if it ever
// changes it is a deliberate decision with a failing test attached rather than a silent drift.
func TestAuthOffAllowsUnauthenticatedAccess(t *testing.T) {
	h, _, _ := newAPI(t, "off", nil)
	if rec := do(t, h, http.MethodGet, "/api/v1/identities", ""); rec.Code != http.StatusOK {
		t.Errorf("auth=off returned %d for an unauthenticated read, want 200", rec.Code)
	}
}

// TestTokenAuthRejectsMissingAndBadTokens is the check that matters most: enforcement has to happen
// in the middleware chain, which is only observable through a real request.
func TestTokenAuthRejectsMissingAndBadTokens(t *testing.T) {
	h, _, _ := newAPI(t, "token", testTokens())

	cases := []struct {
		name, token string
	}{
		{"no token", ""},
		{"unknown token", "not-a-real-token"},
		{"empty bearer", " "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, "/api/v1/identities", c.token)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("got %d, want 401 — unauthenticated requests must not reach a handler", rec.Code)
			}
		})
	}
}

func TestTokenAuthAcceptsValidToken(t *testing.T) {
	h, _, _ := newAPI(t, "token", testTokens())
	if rec := do(t, h, http.MethodGet, "/api/v1/identities", viewerTok); rec.Code != http.StatusOK {
		t.Errorf("valid viewer token got %d, want 200", rec.Code)
	}
}

// TestRoleEscalationIsBlocked walks the whole role lattice. A viewer must not reach analyst routes,
// and neither may reach admin config — the endpoint that can rewrite the risk weights every score
// depends on.
func TestRoleEscalationIsBlocked(t *testing.T) {
	h, _, _ := newAPI(t, "token", testTokens())

	cases := []struct {
		name, method, path, token string
		want                      int
	}{
		{"viewer reads inventory", http.MethodGet, "/api/v1/identities", viewerTok, http.StatusOK},
		{"viewer cannot export", http.MethodGet, "/api/v1/export/findings?format=json", viewerTok, http.StatusForbidden},
		{"analyst can export", http.MethodGet, "/api/v1/export/findings?format=json", analystTok, http.StatusOK},
		{"viewer cannot read config", http.MethodGet, "/api/v1/config/risk-weights", viewerTok, http.StatusForbidden},
		{"analyst cannot read config", http.MethodGet, "/api/v1/config/risk-weights", analystTok, http.StatusForbidden},
		{"admin can read config", http.MethodGet, "/api/v1/config/risk-weights", adminTok, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, h, c.method, c.path, c.token)
			if rec.Code != c.want {
				t.Errorf("%s %s as %s = %d, want %d", c.method, c.path, c.token, rec.Code, c.want)
			}
		})
	}
}

// TestAuthAppliesBeforeHandlerWork ensures rejection happens in middleware, not after the handler
// has already queried the database — an unauthenticated caller should not be able to make the API
// do work on its behalf.
func TestAuthAppliesBeforeHandlerWork(t *testing.T) {
	h, s, ctx := newAPI(t, "token", testTokens())
	id := seedIdentity(t, s, ctx, "secret-identity", "aws", 99)

	rec := do(t, h, http.MethodGet, "/api/v1/identities/"+id.String(), "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret-identity") {
		t.Error("unauthenticated response leaked identity data")
	}
}
