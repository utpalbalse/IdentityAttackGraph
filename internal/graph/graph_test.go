package graph

import (
	"testing"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

// estate is a miniature version of the demo environment:
//
//	user --assumes--> adminRole --binds_to--> bucket   (crown jewel)
//	user --uses-----> lowRole   --binds_to--> logs     (high)
//	user --exposed_in--> repo                          (not a capability edge)
//	orphan                                             (no edges at all)
type estate struct {
	g                                                    *Graph
	user, adminRole, lowRole, bucket, logs, repo, orphan uuid.UUID
	userEntity                                           uuid.UUID
}

func newEstate() estate {
	e := estate{
		g: New(), user: uuid.New(), adminRole: uuid.New(), lowRole: uuid.New(),
		bucket: uuid.New(), logs: uuid.New(), repo: uuid.New(), orphan: uuid.New(),
		userEntity: uuid.New(),
	}
	e.g.AddNode(&Node{ID: e.user, EntityID: e.userEntity, Type: "identity", Label: "svc-billing-export"})
	e.g.AddNode(&Node{ID: e.adminRole, EntityID: uuid.New(), Type: "role", Label: "billing-admin",
		Attributes: map[string]any{"privilege_level": "admin"}})
	e.g.AddNode(&Node{ID: e.lowRole, EntityID: uuid.New(), Type: "role", Label: "reader",
		Attributes: map[string]any{"privilege_level": "read"}})
	e.g.AddNode(&Node{ID: e.bucket, Type: "resource", Label: "s3:prod-billing", Criticality: models.CritCrownJewel})
	e.g.AddNode(&Node{ID: e.logs, Type: "resource", Label: "s3:app-logs", Criticality: models.CritHigh})
	e.g.AddNode(&Node{ID: e.repo, Type: "repo", Label: "acme/billing"})
	e.g.AddNode(&Node{ID: e.orphan, EntityID: uuid.New(), Type: "identity", Label: "svc-orphaned"})

	e.g.AddEdge(Edge{Src: e.user, Dst: e.adminRole, Type: "assumes"})
	e.g.AddEdge(Edge{Src: e.user, Dst: e.lowRole, Type: "uses"})
	e.g.AddEdge(Edge{Src: e.adminRole, Dst: e.bucket, Type: "binds_to"})
	e.g.AddEdge(Edge{Src: e.lowRole, Dst: e.logs, Type: "binds_to"})
	e.g.AddEdge(Edge{Src: e.user, Dst: e.repo, Type: "exposed_in"})
	return e
}

// ----- construction & lookup -----

func TestAddNodeIndexesByEntity(t *testing.T) {
	e := newEstate()
	if e.g.NodeCount() != 7 {
		t.Errorf("NodeCount = %d, want 7", e.g.NodeCount())
	}
	got, ok := e.g.NodeIDForEntity(e.userEntity)
	if !ok || got != e.user {
		t.Errorf("NodeIDForEntity = %v/%v, want %v/true", got, ok, e.user)
	}
	if _, ok := e.g.NodeIDForEntity(uuid.New()); ok {
		t.Error("unknown entity id must not resolve")
	}
	if n, ok := e.g.Node(e.bucket); !ok || n.Label != "s3:prod-billing" {
		t.Errorf("Node(bucket) = %v/%v", n, ok)
	}
	if _, ok := e.g.Node(uuid.New()); ok {
		t.Error("unknown node id must not resolve")
	}
}

func TestAddNodeSkipsNilEntityIndex(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: uuid.New(), Type: "resource"}) // no EntityID
	if _, ok := g.NodeIDForEntity(uuid.Nil); ok {
		t.Error("a nil entity id must never be indexed — it would alias every entity-less node")
	}
}

// ----- Reachable -----

func TestReachableFollowsOnlyCapabilityEdges(t *testing.T) {
	e := newEstate()
	got := e.g.Reachable(e.user, 5)

	want := map[uuid.UUID]int{e.adminRole: 1, e.lowRole: 1, e.bucket: 2, e.logs: 2}
	if len(got) != len(want) {
		t.Fatalf("reached %d nodes, want %d (%v)", len(got), len(want), got)
	}
	for id, hops := range want {
		if got[id] != hops {
			t.Errorf("hops to %v = %d, want %d", id, got[id], hops)
		}
	}
	// "exposed_in" says where a credential leaked, not what the identity can do with it.
	if _, ok := got[e.repo]; ok {
		t.Error("exposure edges are not capability transfers and must not be traversed")
	}
}

func TestReachableRespectsHopLimit(t *testing.T) {
	e := newEstate()
	got := e.g.Reachable(e.user, 1)
	if len(got) != 2 {
		t.Fatalf("1-hop reach = %d nodes, want 2 (%v)", len(got), got)
	}
	if _, ok := got[e.bucket]; ok {
		t.Error("bucket is 2 hops away and must be excluded at maxHops=1")
	}
}

func TestReachableFromIsolatedNode(t *testing.T) {
	e := newEstate()
	if got := e.g.Reachable(e.orphan, 5); len(got) != 0 {
		t.Errorf("orphan reaches %v, want nothing", got)
	}
}

func TestReachableTerminatesOnCycle(t *testing.T) {
	g := New()
	a, b := uuid.New(), uuid.New()
	g.AddNode(&Node{ID: a, Type: "role"})
	g.AddNode(&Node{ID: b, Type: "role"})
	g.AddEdge(Edge{Src: a, Dst: b, Type: "assumes"})
	g.AddEdge(Edge{Src: b, Dst: a, Type: "assumes"}) // role-assumption loops do occur in the wild

	got := g.Reachable(a, 10)
	if len(got) != 1 || got[b] != 1 {
		t.Errorf("cyclic reach = %v, want just b at 1 hop", got)
	}
}

// ----- BlastRadius -----

func TestComputeBlastRadiusRollsUpCriticality(t *testing.T) {
	e := newEstate()
	br := e.g.ComputeBlastRadius(e.user, 5)

	if br.ReachableResources != 2 {
		t.Errorf("ReachableResources = %d, want 2", br.ReachableResources)
	}
	if br.CrownJewelCount != 1 {
		t.Errorf("CrownJewelCount = %d, want 1", br.CrownJewelCount)
	}
	if br.NearestCrownJewel != 2 {
		t.Errorf("NearestCrownJewel = %d, want 2", br.NearestCrownJewel)
	}
	if br.HighCritCount != 1 {
		t.Errorf("HighCritCount = %d, want 1", br.HighCritCount)
	}
	if !br.ReachesAdmin {
		t.Error("ReachesAdmin = false, want true (billing-admin is privilege_level=admin)")
	}
}

func TestComputeBlastRadiusNoCrownJewel(t *testing.T) {
	e := newEstate()
	// Start at lowRole: reaches only the high-criticality log bucket.
	br := e.g.ComputeBlastRadius(e.lowRole, 5)
	if br.CrownJewelCount != 0 {
		t.Errorf("CrownJewelCount = %d, want 0", br.CrownJewelCount)
	}
	if br.NearestCrownJewel != -1 {
		t.Errorf("NearestCrownJewel = %d, want -1 when none is reachable", br.NearestCrownJewel)
	}
	if br.ReachesAdmin {
		t.Error("a read-only role must not report ReachesAdmin")
	}
}

func TestComputeBlastRadiusTakesNearestCrownJewel(t *testing.T) {
	// Two routes to crown jewels at different depths; the nearest one wins.
	g := New()
	start, near, far, mid := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	g.AddNode(&Node{ID: start, Type: "identity"})
	g.AddNode(&Node{ID: near, Type: "resource", Criticality: models.CritCrownJewel})
	g.AddNode(&Node{ID: mid, Type: "role"})
	g.AddNode(&Node{ID: far, Type: "resource", Criticality: models.CritCrownJewel})
	g.AddEdge(Edge{Src: start, Dst: near, Type: "binds_to"})
	g.AddEdge(Edge{Src: start, Dst: mid, Type: "assumes"})
	g.AddEdge(Edge{Src: mid, Dst: far, Type: "binds_to"})

	br := g.ComputeBlastRadius(start, 5)
	if br.CrownJewelCount != 2 {
		t.Errorf("CrownJewelCount = %d, want 2", br.CrownJewelCount)
	}
	if br.NearestCrownJewel != 1 {
		t.Errorf("NearestCrownJewel = %d, want 1", br.NearestCrownJewel)
	}
}

// ----- AttackPaths -----

func TestAttackPathsRankByImpactThenLength(t *testing.T) {
	e := newEstate()
	paths := e.g.AttackPaths(e.user, 5, 10)

	if len(paths) != 3 {
		t.Fatalf("got %d paths, want 3 (admin role, crown-jewel bucket, high-crit logs)", len(paths))
	}
	// Highest impact first, shortest first within an impact tier.
	if paths[0].Impact != models.CritCrownJewel || paths[0].Hops != 1 {
		t.Errorf("path[0] = %s/%d hops, want crown_jewel/1 (the admin role)", paths[0].Impact, paths[0].Hops)
	}
	if paths[1].Impact != models.CritCrownJewel || paths[1].Hops != 2 {
		t.Errorf("path[1] = %s/%d hops, want crown_jewel/2 (the bucket)", paths[1].Impact, paths[1].Hops)
	}
	if paths[2].Impact != models.CritHigh {
		t.Errorf("path[2] impact = %s, want high (ranked below crown jewels)", paths[2].Impact)
	}

	// A path must be a coherent walk: n nodes joined by n-1 edges, starting at the origin.
	p := paths[1]
	if len(p.Nodes) != p.Hops+1 || len(p.Edges) != p.Hops {
		t.Errorf("path shape = %d nodes / %d edges for %d hops", len(p.Nodes), len(p.Edges), p.Hops)
	}
	if p.Nodes[0] != e.user {
		t.Error("every path must start at the identity it was computed for")
	}
	if p.Nodes[len(p.Nodes)-1] != e.bucket {
		t.Error("the crown-jewel path must terminate at the bucket")
	}
}

func TestAttackPathsRespectHopLimit(t *testing.T) {
	e := newEstate()
	paths := e.g.AttackPaths(e.user, 1, 10)
	if len(paths) != 1 {
		t.Fatalf("got %d paths at maxHops=1, want 1", len(paths))
	}
	if paths[0].Nodes[len(paths[0].Nodes)-1] != e.adminRole {
		t.Error("the only 1-hop target is the admin role")
	}
}

func TestAttackPathsRespectLimit(t *testing.T) {
	e := newEstate()
	if paths := e.g.AttackPaths(e.user, 5, 1); len(paths) != 1 {
		t.Fatalf("got %d paths, want 1", len(paths))
	}
}

func TestAttackPathsNoneForIsolatedIdentity(t *testing.T) {
	e := newEstate()
	if paths := e.g.AttackPaths(e.orphan, 5, 10); len(paths) != 0 {
		t.Errorf("got %d paths for an identity with no edges, want 0", len(paths))
	}
}

func TestAttackPathsIgnoreNonCapabilityEdges(t *testing.T) {
	g := New()
	id, secret := uuid.New(), uuid.New()
	g.AddNode(&Node{ID: id, Type: "identity"})
	g.AddNode(&Node{ID: secret, Type: "resource", Criticality: models.CritCrownJewel})
	g.AddEdge(Edge{Src: id, Dst: secret, Type: "exposed_in"}) // not a capability

	if paths := g.AttackPaths(id, 5, 10); len(paths) != 0 {
		t.Errorf("got %d paths across a non-capability edge, want 0", len(paths))
	}
}

// TestAttackPathsAreDeterministic pins the ordering guarantee the UI relies on: the same graph must
// always yield the same ranked paths, or the attack-graph view reshuffles between loads.
func TestAttackPathsAreDeterministic(t *testing.T) {
	e := newEstate()
	first := e.g.AttackPaths(e.user, 5, 10)
	for i := 0; i < 100; i++ {
		got := e.g.AttackPaths(e.user, 5, 10)
		if len(got) != len(first) {
			t.Fatalf("run %d: got %d paths, want %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].Hops != first[j].Hops || got[j].Impact != first[j].Impact {
				t.Fatalf("run %d path %d diverged: %+v vs %+v", i, j, got[j], first[j])
			}
			if got[j].Nodes[len(got[j].Nodes)-1] != first[j].Nodes[len(first[j].Nodes)-1] {
				t.Fatalf("run %d path %d reached a different target", i, j)
			}
		}
	}
}

func TestTargetImpactTreatsPrivilegedRoleAsCrownJewel(t *testing.T) {
	for _, lvl := range []string{"admin", "privileged"} {
		n := &Node{Type: "role", Attributes: map[string]any{"privilege_level": lvl}}
		impact, ok := targetImpact(n)
		if !ok || impact != models.CritCrownJewel {
			t.Errorf("privilege_level=%s -> %s/%v, want crown_jewel/true", lvl, impact, ok)
		}
	}
	if _, ok := targetImpact(&Node{Type: "role", Attributes: map[string]any{"privilege_level": "read"}}); ok {
		t.Error("a read-only role is not an attack-path target")
	}
	if _, ok := targetImpact(&Node{Type: "resource", Criticality: models.CritLow}); ok {
		t.Error("a low-criticality resource is not an attack-path target")
	}
}

// ----- Neighborhood -----

func TestNeighborhoodIsUndirectedAndDepthBounded(t *testing.T) {
	e := newEstate()

	nodes, edges := e.g.Neighborhood(e.user, 1)
	// The UI view shows context, so it walks every edge type in both directions.
	if len(nodes) != 4 {
		t.Errorf("depth-1 nodes = %d, want 4 (user, adminRole, lowRole, repo)", len(nodes))
	}
	if len(edges) != 3 {
		t.Errorf("depth-1 edges = %d, want 3", len(edges))
	}

	nodes2, edges2 := e.g.Neighborhood(e.user, 2)
	if len(nodes2) != 6 {
		t.Errorf("depth-2 nodes = %d, want 6", len(nodes2))
	}
	if len(edges2) != 5 {
		t.Errorf("depth-2 edges = %d, want 5", len(edges2))
	}
}

func TestNeighborhoodWalksInboundEdges(t *testing.T) {
	e := newEstate()
	// The bucket has no outbound edges; it is only reachable by walking backwards.
	nodes, edges := e.g.Neighborhood(e.bucket, 1)
	if len(nodes) != 2 || len(edges) != 1 {
		t.Fatalf("got %d nodes / %d edges, want 2/1 (bucket + adminRole)", len(nodes), len(edges))
	}
}

func TestNeighborhoodOfUnknownNode(t *testing.T) {
	e := newEstate()
	nodes, edges := e.g.Neighborhood(uuid.New(), 2)
	if len(nodes) != 0 || len(edges) != 0 {
		t.Errorf("unknown start = %d nodes / %d edges, want 0/0", len(nodes), len(edges))
	}
}

// ----- TrustChainDepth -----

func TestTrustChainDepthCountsOnlyPivots(t *testing.T) {
	e := newEstate()
	// user --assumes--> adminRole --binds_to--> bucket: one pivot, then a resource grant.
	if got := e.g.TrustChainDepth(e.user, 5); got != 1 {
		t.Errorf("TrustChainDepth = %d, want 1 (binds_to is a grant, not a pivot)", got)
	}
	if got := e.g.TrustChainDepth(e.orphan, 5); got != 0 {
		t.Errorf("isolated identity depth = %d, want 0", got)
	}
}

func TestTrustChainDepthFollowsMultiHopPivots(t *testing.T) {
	// The cross-cloud case: a pod federates into a role, which assumes another, which impersonates.
	g := New()
	pod, roleA, roleB, sa := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{pod, roleA, roleB, sa} {
		g.AddNode(&Node{ID: id, Type: "role"})
	}
	g.AddEdge(Edge{Src: pod, Dst: roleA, Type: "federated_from"})
	g.AddEdge(Edge{Src: roleA, Dst: roleB, Type: "assumes"})
	g.AddEdge(Edge{Src: roleB, Dst: sa, Type: "impersonates"})

	if got := g.TrustChainDepth(pod, 5); got != 3 {
		t.Errorf("TrustChainDepth = %d, want 3", got)
	}
	// The hop limit bounds the walk.
	if got := g.TrustChainDepth(pod, 2); got != 2 {
		t.Errorf("TrustChainDepth at maxHops=2 = %d, want 2", got)
	}
}

func TestTrustChainDepthTerminatesOnCycle(t *testing.T) {
	g := New()
	a, b := uuid.New(), uuid.New()
	g.AddNode(&Node{ID: a, Type: "role"})
	g.AddNode(&Node{ID: b, Type: "role"})
	g.AddEdge(Edge{Src: a, Dst: b, Type: "assumes"})
	g.AddEdge(Edge{Src: b, Dst: a, Type: "assumes"})

	if got := g.TrustChainDepth(a, 10); got != 1 {
		t.Errorf("cyclic chain depth = %d, want 1", got)
	}
}

func TestIsTrustEdge(t *testing.T) {
	for _, tp := range []string{"assumes", "impersonates", "federated_from", "can_mint_token"} {
		if !IsTrustEdge(tp) {
			t.Errorf("%q is an identity pivot", tp)
		}
	}
	// Holding permissions or binding a resource is a grant, not a pivot to another principal.
	for _, tp := range []string{"has_permissions", "binds_to", "uses", "references", "exposed_in", ""} {
		if IsTrustEdge(tp) {
			t.Errorf("%q must not count as a trust pivot", tp)
		}
	}
}

func TestIsCapabilityEdge(t *testing.T) {
	// The capability set is what makes blast radius mean "can actually do", so pin it explicitly.
	for _, tp := range []string{"uses", "assumes", "impersonates", "can_mint_token",
		"binds_to", "references", "federated_from", "has_permissions"} {
		if !isCapabilityEdge(tp) {
			t.Errorf("%q should be a capability edge", tp)
		}
	}
	for _, tp := range []string{"exposed_in", "owns", "runs_as", ""} {
		if isCapabilityEdge(tp) {
			t.Errorf("%q must not be a capability edge", tp)
		}
	}
}
