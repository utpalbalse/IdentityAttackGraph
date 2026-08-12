//go:build integration

// HTTP-level tests for the API. They run the real chi router with the real auth middleware against
// a real database, so what is asserted is the contract a client actually sees: status codes, the
// JSON envelope, and whether RBAC genuinely blocks a request — none of which is observable from a
// handler function called in isolation with a mocked store.
//
// Run:
//
//	go test -tags=integration ./internal/api/...
//
// Shared database setup lives in internal/dbtest; the suite uses its own `nhiid_test` database and
// never touches the dev/demo one.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/auth"
	"github.com/nhiid/nhiid/internal/dbtest"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/risk"
	"github.com/nhiid/nhiid/internal/store"
)

const weightsPath = "../../configs/risk_weights.yaml"

var (
	testStore   *store.Store
	testWeights *risk.Weights
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	dsn := dbtest.DSNFor("api")

	if err := dbtest.Prepare(ctx, dsn); err != nil {
		fmt.Fprint(os.Stderr, dbtest.Unavailable(err))
		os.Exit(1)
	}
	s, err := store.New(ctx, dsn, 8, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open test store: %v\n", err)
		os.Exit(1)
	}
	testStore = s

	// Load the shipped weights so the risk endpoints behave as they do in production.
	w, err := risk.LoadWeights(weightsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load risk weights from %s: %v\n", weightsPath, err)
		os.Exit(1)
	}
	testWeights = w

	code := m.Run()
	s.Close()
	os.Exit(code)
}

// ---- harness ----------------------------------------------------------------

// newAPI clears the database and returns a router wired exactly as cmd/api/main.go wires it —
// same middleware order, same role groups. Tests therefore exercise the real chain rather than a
// simplified stand-in. authMode is "off", "token", or "jwt".
func newAPI(t *testing.T, authMode string, tokens []auth.TokenEntry) (http.Handler, *store.Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	if err := dbtest.TruncateAll(ctx, testStore.Pool()); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	authn, err := auth.New(authMode, tokens, nil)
	if err != nil {
		t.Fatalf("configure auth: %v", err)
	}

	h := &Handler{
		Store:       testStore,
		RiskEngine:  risk.NewEngine(testWeights),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		WeightsFile: weightsPath,
	}

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authn.Authenticate)

		r.Group(func(r chi.Router) { // viewer — read
			r.Use(authn.Require(auth.RoleViewer))
			r.Get("/version", h.GetVersion)
			r.Get("/identities", h.ListIdentities)
			r.Get("/identities/{id}", h.GetIdentity)
			r.Get("/identities/{id}/attack-paths", h.GetAttackPaths)
			r.Get("/findings", h.ListFindings)
			r.Get("/triage", h.GetTriage)
			r.Get("/metrics/risk-reduction", h.GetRiskReduction)
		})

		r.Group(func(r chi.Router) { // analyst — triage + exports
			r.Use(authn.Require(auth.RoleAnalyst))
			r.Patch("/findings/{id}", h.UpdateFinding)
			r.Get("/export/findings", h.ExportFindings)
		})

		r.Group(func(r chi.Router) { // admin — config
			r.Use(authn.Require(auth.RoleAdmin))
			r.Get("/config/risk-weights", h.GetRiskWeights)
		})
	})
	return r, testStore, ctx
}

// do issues a request against the router and returns the recorder.
func do(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decode parses a JSON response body, failing the test on malformed JSON — which is itself a
// contract violation worth catching.
func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not valid JSON (%v): %s", err, rec.Body.String())
	}
	return out
}

// seedIdentity inserts a scored identity and returns its id.
func seedIdentity(t *testing.T, s *store.Store, ctx context.Context, name, provider string, score int) uuid.UUID {
	t.Helper()
	arn := "arn:aws:iam::123456789012:user/" + name
	kind := models.KindAWSIAMUser
	if provider == "gcp" {
		kind = models.KindGCPServiceAcct
		arn = name + "@proj.iam.gserviceaccount.com"
	}
	id, err := s.Identities.Upsert(ctx, models.Identity{
		Kind: kind, Name: name, ARNOrEmail: arn, Provider: provider, State: "active",
		Prov: models.Provenance{Source: "test", ExternalID: arn, AccountRef: provider + ":123456789012"},
	})
	if err != nil {
		t.Fatalf("seed identity %s: %v", name, err)
	}
	if err := s.Identities.UpdateRiskScore(ctx, id, score, 0, map[string]any{
		"privilege": map[string]any{"score": score, "signals": []string{"admin_or_star"}},
	}); err != nil {
		t.Fatalf("score identity %s: %v", name, err)
	}
	return id
}

func seedFinding(t *testing.T, s *store.Store, ctx context.Context, identityID uuid.UUID, detector string, sev models.Severity) uuid.UUID {
	t.Helper()
	id, err := s.Findings.Upsert(ctx, models.Finding{
		Detector: detector, Category: "hygiene", Severity: sev, Confidence: 80,
		IdentityID: &identityID, Title: detector, Narrative: "test finding",
		Evidence: map[string]any{"k": "v"}, Fingerprint: "fp-" + detector, Status: "open",
	})
	if err != nil {
		t.Fatalf("seed finding %s: %v", detector, err)
	}
	return id
}
