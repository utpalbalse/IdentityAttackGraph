package graph

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

func TestFromModelsBuildsAdjacencyAndEntityIndex(t *testing.T) {
	identityEntity := uuid.New()
	idNode, roleNode, resNode := uuid.New(), uuid.New(), uuid.New()

	nodes := []models.GraphNode{
		{ID: idNode, NodeType: "identity", EntityID: &identityEntity, Label: "svc", Criticality: models.CritLow},
		{ID: roleNode, NodeType: "role", Label: "admin", Attributes: map[string]any{"privilege_level": "admin"}},
		{ID: resNode, NodeType: "resource", Label: "s3:prod", Criticality: models.CritCrownJewel},
	}
	edges := []models.GraphEdge{
		{SrcNodeID: idNode, DstNodeID: roleNode, EdgeType: "assumes", Weight: 1, Observed: true},
		{SrcNodeID: roleNode, DstNodeID: resNode, EdgeType: "binds_to"},
	}

	g := FromModels(nodes, edges)

	if g.NodeCount() != 3 {
		t.Fatalf("NodeCount = %d, want 3", g.NodeCount())
	}
	got, ok := g.NodeIDForEntity(identityEntity)
	if !ok || got != idNode {
		t.Errorf("entity index = %v/%v, want %v/true", got, ok, idNode)
	}
	// Nodes with a nil EntityID must not land in the index under uuid.Nil.
	if _, ok := g.NodeIDForEntity(uuid.Nil); ok {
		t.Error("nil entity ids must not be indexed")
	}

	n, _ := g.Node(resNode)
	if n.Criticality != models.CritCrownJewel || n.Label != "s3:prod" {
		t.Errorf("resource node = %+v, want the crown-jewel projection", n)
	}
	r, _ := g.Node(roleNode)
	if lvl, _ := r.Attributes["privilege_level"].(string); lvl != "admin" {
		t.Errorf("attributes lost in projection: %v", r.Attributes)
	}

	// Edges must be walkable end to end.
	br := g.ComputeBlastRadius(idNode, 5)
	if br.CrownJewelCount != 1 || !br.ReachesAdmin {
		t.Errorf("blast radius over the loaded graph = %+v", br)
	}
}

func TestFromModelsEmpty(t *testing.T) {
	g := FromModels(nil, nil)
	if g.NodeCount() != 0 {
		t.Errorf("NodeCount = %d, want 0", g.NodeCount())
	}
	if got := g.Reachable(uuid.New(), 3); len(got) != 0 {
		t.Errorf("empty graph reached %v", got)
	}
}

func TestExplainLabelsEveryHop(t *testing.T) {
	e := newEstate()
	views := e.g.Explain(e.g.AttackPaths(e.user, 5, 10))

	if len(views) != 3 {
		t.Fatalf("got %d views, want 3", len(views))
	}
	for i, v := range views {
		if v.Rank != i+1 {
			t.Errorf("view %d rank = %d, want %d", i, v.Rank, i+1)
		}
		if len(v.Steps) != v.Hops+1 {
			t.Errorf("view %d: %d steps for %d hops", i, len(v.Steps), v.Hops)
		}
		if v.Steps[0].Via != "" {
			t.Errorf("view %d: the origin step has no inbound edge, got via=%q", i, v.Steps[0].Via)
		}
		for j, s := range v.Steps[1:] {
			if s.Via == "" {
				t.Errorf("view %d step %d: missing the capability that produced the hop", i, j+1)
			}
		}
	}

	// The 2-hop crown-jewel route is the one the README narrates.
	cj := views[1]
	if cj.Steps[0].Node != "svc-billing-export" || cj.Steps[0].Type != "identity" {
		t.Errorf("first step = %+v", cj.Steps[0])
	}
	if cj.Steps[1].Via != "assumes" || cj.Steps[1].Node != "billing-admin" {
		t.Errorf("second step = %+v, want assumes -> billing-admin", cj.Steps[1])
	}
	if cj.Steps[2].Via != "binds_to" || cj.Steps[2].Criticality != string(models.CritCrownJewel) {
		t.Errorf("third step = %+v, want binds_to -> crown_jewel", cj.Steps[2])
	}
	if !strings.Contains(cj.Narrative, "svc-billing-export") ||
		!strings.Contains(cj.Narrative, "s3:prod-billing") ||
		!strings.Contains(cj.Narrative, "2 hop(s)") {
		t.Errorf("narrative should name both ends and the distance, got: %q", cj.Narrative)
	}
}

func TestExplainFallsBackForUnknownNodes(t *testing.T) {
	g := New()
	a, b := uuid.New(), uuid.New()
	// Neither node was loaded, e.g. the working set was scoped to one account mid-traversal.
	p := Path{Nodes: []uuid.UUID{a, b}, Edges: []Edge{{Src: a, Dst: b, Type: "assumes"}},
		Impact: models.CritHigh, Hops: 1}

	views := g.Explain([]Path{p})
	if len(views) != 1 {
		t.Fatalf("got %d views, want 1", len(views))
	}
	if views[0].Steps[0].Node != a.String() {
		t.Errorf("unknown node should fall back to its id, got %q", views[0].Steps[0].Node)
	}
	if views[0].Steps[1].Via != "assumes" {
		t.Error("the edge label is known even when the node is not")
	}
}

func TestExplainEmpty(t *testing.T) {
	if views := New().Explain(nil); len(views) != 0 {
		t.Errorf("got %d views for no paths", len(views))
	}
}

func TestNarrateSkipsDegeneratePaths(t *testing.T) {
	g := New()
	if got := narrate(g, Path{Nodes: []uuid.UUID{uuid.New()}}); got != "" {
		t.Errorf("a single-node path has nothing to narrate, got %q", got)
	}
}

func TestReachableCountP90(t *testing.T) {
	// Ten identities reaching 0..9 resources each; the P90 baseline should land on 8.
	g := New()
	resources := make([]uuid.UUID, 9)
	for i := range resources {
		resources[i] = uuid.New()
		g.AddNode(&Node{ID: resources[i], Type: "resource", Criticality: models.CritLow})
	}
	for i := 0; i < 10; i++ {
		id := uuid.New()
		g.AddNode(&Node{ID: id, EntityID: uuid.New(), Type: "identity"})
		for j := 0; j < i && j < len(resources); j++ {
			g.AddEdge(Edge{Src: id, Dst: resources[j], Type: "binds_to"})
		}
	}

	if got := g.ReachableCountP90(5); got != 8 {
		t.Errorf("ReachableCountP90 = %d, want 8", got)
	}
}

func TestReachableCountP90IgnoresNonIdentities(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: uuid.New(), Type: "resource"})
	g.AddNode(&Node{ID: uuid.New(), Type: "role"})
	if got := g.ReachableCountP90(5); got != 0 {
		t.Errorf("ReachableCountP90 = %d, want 0 when there are no identities", got)
	}
}

func TestPercentile(t *testing.T) {
	cases := []struct {
		name string
		vals []int
		p    float64
		want int
	}{
		{"empty", nil, 0.9, 0},
		{"single", []int{7}, 0.9, 7},
		{"p90 of 0..9", []int{9, 3, 0, 7, 1, 8, 2, 6, 4, 5}, 0.9, 8},
		{"median", []int{1, 2, 3, 4, 5}, 0.5, 3},
		{"max", []int{1, 2, 3}, 1.0, 3},
		{"all equal", []int{4, 4, 4}, 0.9, 4},
	}
	for _, c := range cases {
		if got := percentile(c.vals, c.p); got != c.want {
			t.Errorf("%s: percentile = %d, want %d", c.name, got, c.want)
		}
	}
}
