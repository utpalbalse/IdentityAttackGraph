package graph

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

// FromModels builds an in-memory graph from persisted graph_nodes/graph_edges. Nodes are keyed by
// their graph_node id; the entity→node index lets callers start a traversal from an identity.
func FromModels(nodes []models.GraphNode, edges []models.GraphEdge) *Graph {
	g := New()
	for _, n := range nodes {
		var ent uuid.UUID
		if n.EntityID != nil {
			ent = *n.EntityID
		}
		g.AddNode(&Node{
			ID:          n.ID,
			EntityID:    ent,
			Type:        n.NodeType,
			Label:       n.Label,
			Criticality: n.Criticality,
			Attributes:  n.Attributes,
		})
	}
	for _, e := range edges {
		g.AddEdge(Edge{
			Src:        e.SrcNodeID,
			Dst:        e.DstNodeID,
			Type:       e.EdgeType,
			Weight:     e.Weight,
			Observed:   e.Observed,
			Attributes: e.Attributes,
		})
	}
	return g
}

// PathStep is one labeled hop in an attack path, suitable for API/UI rendering.
type PathStep struct {
	Node        string `json:"node"`
	Type        string `json:"type"`
	Criticality string `json:"criticality,omitempty"`
	Via         string `json:"via,omitempty"`
}

// PathView is an explainable attack path with a narrative and node-by-node steps.
type PathView struct {
	Rank      int        `json:"rank"`
	Impact    string     `json:"impact"`
	Hops      int        `json:"hops"`
	Narrative string     `json:"narrative"`
	Steps     []PathStep `json:"path"`
}

// Explain converts raw Paths into labeled, narrated PathViews.
func (g *Graph) Explain(paths []Path) []PathView {
	out := make([]PathView, 0, len(paths))
	for i, p := range paths {
		steps := make([]PathStep, 0, len(p.Nodes))
		for j, nid := range p.Nodes {
			n, ok := g.Node(nid)
			label, typ, crit := nid.String(), "", ""
			if ok {
				label, typ, crit = n.Label, n.Type, string(n.Criticality)
			}
			step := PathStep{Node: label, Type: typ, Criticality: crit}
			if j > 0 && j-1 < len(p.Edges) {
				step.Via = p.Edges[j-1].Type
			}
			steps = append(steps, step)
		}
		out = append(out, PathView{
			Rank:      i + 1,
			Impact:    string(p.Impact),
			Hops:      p.Hops,
			Narrative: narrate(g, p),
			Steps:     steps,
		})
	}
	return out
}

func narrate(g *Graph, p Path) string {
	if len(p.Nodes) < 2 {
		return ""
	}
	start, _ := g.Node(p.Nodes[0])
	end, _ := g.Node(p.Nodes[len(p.Nodes)-1])
	startLabel, endLabel := p.Nodes[0].String(), p.Nodes[len(p.Nodes)-1].String()
	if start != nil {
		startLabel = start.Label
	}
	if end != nil {
		endLabel = end.Label
	}
	via := ""
	for i, e := range p.Edges {
		if i > 0 {
			via += " → "
		}
		via += e.Type
	}
	return fmt.Sprintf("%s can reach %s (%s) in %d hop(s) via %s.", startLabel, endLabel, p.Impact, p.Hops, via)
}

// ReachableCountP90 returns the 90th-percentile reachable-resource count across all identity nodes,
// used as a peer baseline for the blast-radius factor. Cheap enough to compute per scoring run.
func (g *Graph) ReachableCountP90(maxHops int) int {
	var counts []int
	for id, n := range g.nodes {
		if n.Type != "identity" {
			continue
		}
		br := g.ComputeBlastRadius(id, maxHops)
		counts = append(counts, br.ReachableResources)
	}
	return percentile(counts, 0.9)
}

func percentile(vals []int, p float64) int {
	if len(vals) == 0 {
		return 0
	}
	// simple nearest-rank
	for i := 0; i < len(vals); i++ {
		for j := i + 1; j < len(vals); j++ {
			if vals[j] < vals[i] {
				vals[i], vals[j] = vals[j], vals[i]
			}
		}
	}
	idx := int(p*float64(len(vals)-1) + 0.5)
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	return vals[idx]
}
