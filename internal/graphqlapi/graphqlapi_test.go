package graphqlapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/store"
)

type fakeSource struct {
	idents []models.Identity
	finds  []models.Finding
	g      *graph.Graph
}

func (f *fakeSource) ListIdentities(_ context.Context, fl store.IdentityFilter) ([]models.Identity, error) {
	var out []models.Identity
	for _, i := range f.idents {
		if fl.Provider != "" && i.Provider != fl.Provider {
			continue
		}
		if fl.MinRisk > 0 && i.RiskScore < fl.MinRisk {
			continue
		}
		out = append(out, i)
	}
	return out, nil
}

func (f *fakeSource) GetIdentity(_ context.Context, id uuid.UUID) (*models.Identity, error) {
	for i := range f.idents {
		if f.idents[i].ID == id {
			return &f.idents[i], nil
		}
	}
	return nil, fmt.Errorf("identity not found")
}

func (f *fakeSource) ListFindings(_ context.Context, fl store.FindingFilter) ([]models.Finding, error) {
	var out []models.Finding
	for _, fd := range f.finds {
		if fl.IdentityID != nil && (fd.IdentityID == nil || *fd.IdentityID != *fl.IdentityID) {
			continue
		}
		if fl.Severity != "" && string(fd.Severity) != fl.Severity {
			continue
		}
		out = append(out, fd)
	}
	return out, nil
}

func (f *fakeSource) TriageQueue(_ context.Context, _ int) ([]models.Identity, error) {
	return f.idents, nil
}

func (f *fakeSource) LoadGraph(_ context.Context) (*graph.Graph, error) { return f.g, nil }

// fixtureSource wires: svc-billing --assumes--> billing-admin --binds_to--> prod (crown jewel).
func fixtureSource() *fakeSource {
	svcID := uuid.New()
	svc := models.Identity{ID: svcID, Name: "svc-billing", Kind: models.KindAWSIAMUser, Provider: "aws", State: "active", RiskScore: 78}
	svc.Prov.AccountRef = "aws:123"
	find := models.Finding{IdentityID: &svcID, Detector: "high_blast_radius", Severity: models.SevHigh, Title: "High blast radius", Status: "open"}

	g := graph.New()
	nSvc, nRole, nRes := uuid.New(), uuid.New(), uuid.New()
	g.AddNode(&graph.Node{ID: nSvc, EntityID: svcID, Type: "identity", Label: "svc-billing"})
	g.AddNode(&graph.Node{ID: nRole, Type: "role", Label: "billing-admin", Criticality: models.CritHigh, Attributes: map[string]any{"privilege_level": "admin"}})
	g.AddNode(&graph.Node{ID: nRes, Type: "resource", Label: "arn:aws:s3:::prod", Criticality: models.CritCrownJewel})
	g.AddEdge(graph.Edge{Src: nSvc, Dst: nRole, Type: "assumes"})
	g.AddEdge(graph.Edge{Src: nRole, Dst: nRes, Type: "binds_to"})

	return &fakeSource{idents: []models.Identity{svc}, finds: []models.Finding{find}, g: g}
}

func TestGraphQLNestedQuery(t *testing.T) {
	ds := fixtureSource()
	schema, err := NewSchema(ds)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	q := `{ identities(provider:"aws", minRisk:50) {
		name riskScore
		findings { detector severity }
		blastRadius { crownJewelCount reachesAdmin }
		attackPaths { impact hops }
	} }`
	res := graphql.Do(graphql.Params{Schema: schema, RequestString: q, Context: withGraphCache(context.Background(), ds)})
	if len(res.Errors) > 0 {
		t.Fatalf("graphql errors: %v", res.Errors)
	}
	b, _ := json.Marshal(res.Data)
	got := string(b)
	for _, want := range []string{`"name":"svc-billing"`, `"detector":"high_blast_radius"`, `"crownJewelCount":1`, `"reachesAdmin":true`, `"hops":2`} {
		if !strings.Contains(got, want) {
			t.Errorf("response missing %q\n%s", want, got)
		}
	}
}

func TestGraphQLHandlerPOST(t *testing.T) {
	ds := fixtureSource()
	schema, _ := NewSchema(ds)
	h := Handler(schema, ds)

	req := httptest.NewRequest("POST", "/graphql", strings.NewReader(`{"query":"{ triage { name kind } }"}`))
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "svc-billing") {
		t.Errorf("handler body missing identity: %s", w.Body.String())
	}
}
