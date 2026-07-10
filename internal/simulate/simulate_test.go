package simulate

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// buildGraph wires: svc-billing-export --assumes--> billing-admin --binds_to--> prod-billing.
func buildGraph() (*graph.Graph, uuid.UUID, uuid.UUID, uuid.UUID) {
	g := graph.New()
	svc := uuid.New()
	role := uuid.New()
	res := uuid.New()
	g.AddNode(&graph.Node{ID: svc, Type: "identity", Label: "svc-billing-export", Criticality: models.CritLow})
	g.AddNode(&graph.Node{ID: role, Type: "role", Label: "billing-admin", Criticality: models.CritHigh,
		Attributes: map[string]any{"privilege_level": "admin"}})
	g.AddNode(&graph.Node{ID: res, Type: "resource", Label: "arn:aws:s3:::prod-billing", Criticality: models.CritCrownJewel})
	g.AddEdge(graph.Edge{Src: svc, Dst: role, Type: "assumes"})
	g.AddEdge(graph.Edge{Src: role, Dst: res, Type: "binds_to"})
	return g, svc, role, res
}

func TestNarratePath(t *testing.T) {
	g, svc, role, res := buildGraph()
	p := graph.Path{
		Nodes:  []uuid.UUID{svc, role, res},
		Edges:  []graph.Edge{{Src: svc, Dst: role, Type: "assumes"}, {Src: role, Dst: res, Type: "binds_to"}},
		Impact: models.CritCrownJewel,
		Hops:   2,
	}
	sc := NarratePath(g, p)

	if len(sc.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(sc.Steps))
	}
	if sc.Steps[0].Verb != "foothold" || sc.Steps[0].Actor != "svc-billing-export" {
		t.Errorf("step0 = %+v", sc.Steps[0])
	}
	if sc.Steps[1].Verb != "assumes role" || sc.Steps[1].Via != "assumes" {
		t.Errorf("step1 = %+v, want assumes role", sc.Steps[1])
	}
	if sc.Steps[2].Verb != "gains access to" || sc.Steps[2].Criticality != models.CritCrownJewel {
		t.Errorf("step2 = %+v, want crown-jewel resource access", sc.Steps[2])
	}
	if sc.CrossCloud {
		t.Error("path has no federation edge; CrossCloud should be false")
	}
	if !strings.Contains(sc.Summary, "svc-billing-export → arn:aws:s3:::prod-billing") {
		t.Errorf("summary = %q", sc.Summary)
	}
}

func TestNarrateCrossCloud(t *testing.T) {
	g := graph.New()
	ksa := uuid.New()
	awsRole := uuid.New()
	g.AddNode(&graph.Node{ID: ksa, Type: "identity", Label: "prod/deployer", Criticality: models.CritLow})
	g.AddNode(&graph.Node{ID: awsRole, Type: "role", Label: "prod-deployer", Criticality: models.CritHigh,
		Attributes: map[string]any{"privilege_level": "admin"}})
	g.AddEdge(graph.Edge{Src: ksa, Dst: awsRole, Type: "federated_from"})

	sc := NarratePath(g, graph.Path{
		Nodes:  []uuid.UUID{ksa, awsRole},
		Edges:  []graph.Edge{{Src: ksa, Dst: awsRole, Type: "federated_from"}},
		Impact: models.CritCrownJewel, Hops: 1,
	})
	if !sc.CrossCloud {
		t.Error("federated_from edge should mark the scenario cross-cloud")
	}
	if sc.Steps[1].Verb != "federates into" {
		t.Errorf("federation verb = %q", sc.Steps[1].Verb)
	}
}

func TestBestPath(t *testing.T) {
	if _, ok := BestPath(nil); ok {
		t.Error("BestPath(nil) should be (_, false)")
	}
	p := graph.Path{Hops: 3}
	if got, ok := BestPath([]graph.Path{p}); !ok || got.Hops != 3 {
		t.Errorf("BestPath = %+v, %v", got, ok)
	}
}

// MostIllustrative should walk all the way to the resource crown jewel, not stop at the admin role
// (which graph.AttackPaths also counts as a target at a shorter hop count).
func TestMostIllustrative(t *testing.T) {
	g, svc, _, res := buildGraph()
	paths := g.AttackPaths(svc, 5, 12)
	p, ok := MostIllustrative(g, paths)
	if !ok {
		t.Fatal("expected a path")
	}
	if last := p.Nodes[len(p.Nodes)-1]; last != res {
		t.Errorf("should land on the resource crown jewel, landed on %v", last)
	}
	if p.Hops != 2 {
		t.Errorf("expected the full 2-hop path, got %d hops", p.Hops)
	}
}

// Integration: the traversal actually finds the crown-jewel path from the foothold.
func TestAttackPathsIntegration(t *testing.T) {
	g, svc, _, _ := buildGraph()
	paths := g.AttackPaths(svc, 5, 5)
	if len(paths) == 0 {
		t.Fatal("expected at least one attack path from the foothold")
	}
	sc := NarratePath(g, paths[0])
	if sc.Impact != models.CritCrownJewel {
		t.Errorf("top path impact = %s, want crown_jewel", sc.Impact)
	}
}
