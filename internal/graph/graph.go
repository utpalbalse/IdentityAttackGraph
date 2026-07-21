// Package graph implements NHIID's in-memory directed property graph and the traversal logic
// used for blast-radius and attack-path reasoning. It is loaded from the persisted
// graph_nodes/graph_edges projection (see internal/store) for a bounded working set (by account
// or scope), keeping memory bounded at scale.
//
// This is implemented from scratch — no external graph library — because the traversal semantics
// (privilege-aware paths to crown jewels, condition-aware trust edges) are domain-specific.
package graph

import (
	"sort"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

// Node is a lightweight in-memory projection of models.GraphNode.
type Node struct {
	ID          uuid.UUID // graph_node id
	EntityID    uuid.UUID // source entity id (identity/role/resource), for start-node lookup
	Type        string
	Label       string
	Criticality models.Criticality
	Attributes  map[string]any
}

// Edge is a directed, typed, weighted relationship.
type Edge struct {
	Src        uuid.UUID
	Dst        uuid.UUID
	Type       string
	Weight     float64
	Observed   bool
	Attributes map[string]any
}

// Graph is an adjacency-list directed property graph.
type Graph struct {
	nodes    map[uuid.UUID]*Node
	out      map[uuid.UUID][]Edge
	in       map[uuid.UUID][]Edge
	byEntity map[uuid.UUID]uuid.UUID // source entity id -> graph node id
}

func New() *Graph {
	return &Graph{
		nodes:    make(map[uuid.UUID]*Node),
		out:      make(map[uuid.UUID][]Edge),
		in:       make(map[uuid.UUID][]Edge),
		byEntity: make(map[uuid.UUID]uuid.UUID),
	}
}

func (g *Graph) AddNode(n *Node) {
	g.nodes[n.ID] = n
	if n.EntityID != uuid.Nil {
		g.byEntity[n.EntityID] = n.ID
	}
}

// NodeIDForEntity maps a source entity id (e.g. an identity's id) to its graph node id.
func (g *Graph) NodeIDForEntity(entityID uuid.UUID) (uuid.UUID, bool) {
	id, ok := g.byEntity[entityID]
	return id, ok
}

func (g *Graph) AddEdge(e Edge) {
	g.out[e.Src] = append(g.out[e.Src], e)
	g.in[e.Dst] = append(g.in[e.Dst], e)
}

func (g *Graph) Node(id uuid.UUID) (*Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

func (g *Graph) NodeCount() int { return len(g.nodes) }

// Neighborhood returns the sub-graph within `depth` hops of `start` (both directions),
// useful for the UI graph view.
func (g *Graph) Neighborhood(start uuid.UUID, depth int) ([]*Node, []Edge) {
	seenN := map[uuid.UUID]bool{start: true}
	seenE := map[string]bool{}
	var nodes []*Node
	var edges []Edge
	if n, ok := g.nodes[start]; ok {
		nodes = append(nodes, n)
	}
	frontier := []uuid.UUID{start}
	for d := 0; d < depth; d++ {
		var next []uuid.UUID
		for _, cur := range frontier {
			for _, dir := range [][]Edge{g.out[cur], g.in[cur]} {
				for _, e := range dir {
					key := e.Src.String() + e.Type + e.Dst.String()
					if !seenE[key] {
						seenE[key] = true
						edges = append(edges, e)
					}
					for _, other := range []uuid.UUID{e.Src, e.Dst} {
						if !seenN[other] {
							seenN[other] = true
							if n, ok := g.nodes[other]; ok {
								nodes = append(nodes, n)
								next = append(next, other)
							}
						}
					}
				}
			}
		}
		frontier = next
	}
	return nodes, edges
}

// Reachable performs a forward BFS over "capability" edges and returns the set of reachable
// resource nodes with their criticality. This is the basis for blast-radius scoring.
//
// We only traverse edges that represent a capability transfer: uses, assumes, impersonates,
// can_mint_token, binds_to, references. Ownership/exposure edges are not capability transfers.
func (g *Graph) Reachable(start uuid.UUID, maxHops int) map[uuid.UUID]int {
	out := map[uuid.UUID]int{} // node -> hop distance
	visited := map[uuid.UUID]bool{start: true}
	type qi struct {
		id   uuid.UUID
		hops int
	}
	q := []qi{{start, 0}}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.hops >= maxHops {
			continue
		}
		for _, e := range g.out[cur.id] {
			if !isCapabilityEdge(e.Type) {
				continue
			}
			if !visited[e.Dst] {
				visited[e.Dst] = true
				out[e.Dst] = cur.hops + 1
				q = append(q, qi{e.Dst, cur.hops + 1})
			}
		}
	}
	return out
}

func isCapabilityEdge(t string) bool {
	switch t {
	case "uses", "assumes", "impersonates", "can_mint_token", "binds_to", "references", "federated_from", "has_permissions":
		return true
	}
	return false
}

// IsTrustEdge reports whether an edge type is an identity *pivot* — assuming, impersonating, or
// federating into another principal — as opposed to holding a permission set or binding a resource.
// A sequence of these is lateral movement, which both the risk engine and suspicious_role_chain
// weigh differently from a single direct grant.
func IsTrustEdge(t string) bool {
	switch t {
	case "assumes", "impersonates", "federated_from", "can_mint_token":
		return true
	}
	return false
}

// TrustChainDepth returns how many consecutive trust pivots are reachable from `start`. A depth of 1
// is a single assume-role; 2 or more means the identity can chain through intermediate principals.
func (g *Graph) TrustChainDepth(start uuid.UUID, maxHops int) int {
	depth := 0
	visited := map[uuid.UUID]bool{start: true}
	type qi struct {
		id   uuid.UUID
		hops int
	}
	q := []qi{{start, 0}}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.hops > depth {
			depth = cur.hops
		}
		if cur.hops >= maxHops {
			continue
		}
		for _, e := range g.out[cur.id] {
			if !IsTrustEdge(e.Type) || visited[e.Dst] {
				continue
			}
			visited[e.Dst] = true
			q = append(q, qi{e.Dst, cur.hops + 1})
		}
	}
	return depth
}

// BlastRadius summarizes what `start` can reach.
type BlastRadius struct {
	ReachableResources int
	HighCritCount      int
	CrownJewelCount    int
	NearestCrownJewel  int // hops; -1 if none
	ReachesAdmin       bool
}

// ComputeBlastRadius walks reachable resources and rolls up criticality.
func (g *Graph) ComputeBlastRadius(start uuid.UUID, maxHops int) BlastRadius {
	br := BlastRadius{NearestCrownJewel: -1}
	for id, hops := range g.Reachable(start, maxHops) {
		n, ok := g.nodes[id]
		if !ok {
			continue
		}
		switch n.Type {
		case "resource":
			br.ReachableResources++
			switch n.Criticality {
			case models.CritCrownJewel:
				br.CrownJewelCount++
				if br.NearestCrownJewel == -1 || hops < br.NearestCrownJewel {
					br.NearestCrownJewel = hops
				}
			case models.CritHigh:
				br.HighCritCount++
			}
		case "role":
			if lvl, _ := n.Attributes["privilege_level"].(string); lvl == "admin" || lvl == "privileged" {
				br.ReachesAdmin = true
			}
		}
	}
	return br
}

// Path is a single attack path expressed node-by-node.
type Path struct {
	Nodes  []uuid.UUID
	Edges  []Edge
	Impact models.Criticality
	Hops   int
}

// AttackPaths finds capability paths from `start` to high-impact targets (crown_jewel resources
// or admin/privileged roles), ranked by impact then shortest. Uses BFS with path reconstruction;
// returns up to `limit` distinct target paths.
func (g *Graph) AttackPaths(start uuid.UUID, maxHops, limit int) []Path {
	type state struct {
		id    uuid.UUID
		path  []uuid.UUID
		edges []Edge
		hops  int
	}
	var results []Path
	visitedTarget := map[uuid.UUID]bool{}
	visited := map[uuid.UUID]bool{start: true}
	q := []state{{start, []uuid.UUID{start}, nil, 0}}

	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if n, ok := g.nodes[cur.id]; ok && cur.id != start {
			if impact, isTarget := targetImpact(n); isTarget && !visitedTarget[cur.id] {
				visitedTarget[cur.id] = true
				results = append(results, Path{
					Nodes: cur.path, Edges: cur.edges, Impact: impact, Hops: cur.hops,
				})
				if len(results) >= limit*3 { // gather a few extra, we trim after ranking
					break
				}
			}
		}
		if cur.hops >= maxHops {
			continue
		}
		for _, e := range g.out[cur.id] {
			if !isCapabilityEdge(e.Type) {
				continue
			}
			if visited[e.Dst] {
				continue
			}
			visited[e.Dst] = true
			np := append(append([]uuid.UUID{}, cur.path...), e.Dst)
			ne := append(append([]Edge{}, cur.edges...), e)
			q = append(q, state{e.Dst, np, ne, cur.hops + 1})
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := models.CriticalityRank(results[i].Impact), models.CriticalityRank(results[j].Impact)
		if ri != rj {
			return ri > rj // higher impact first
		}
		return results[i].Hops < results[j].Hops // then shorter
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results
}

func targetImpact(n *Node) (models.Criticality, bool) {
	if n.Type == "resource" && (n.Criticality == models.CritCrownJewel || n.Criticality == models.CritHigh) {
		return n.Criticality, true
	}
	if n.Type == "role" {
		if lvl, _ := n.Attributes["privilege_level"].(string); lvl == "admin" || lvl == "privileged" {
			return models.CritCrownJewel, true
		}
	}
	return models.CritLow, false
}
