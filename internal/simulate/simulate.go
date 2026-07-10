// Package simulate turns the persisted attack graph into a narrated, attacker's-eye walkthrough:
// "start from this foothold, take these capability edges, land on this crown jewel". The narration
// is pure (a function of the graph + a path), so it is unit-testable without a database; the
// orchestration that selects which paths to tell lives in cmd/simulate.
package simulate

import (
	"fmt"

	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// Step is one narrated hop: the node the attacker now controls and the action that got them there.
type Step struct {
	Index       int                `json:"index"`
	Actor       string             `json:"actor"`
	NodeType    string             `json:"node_type"`
	Verb        string             `json:"verb"`          // humanized attacker action
	Via         string             `json:"via,omitempty"` // raw capability edge type
	Criticality models.Criticality `json:"criticality,omitempty"`
}

// Scenario is a narrated attack path from a foothold to an impact.
type Scenario struct {
	StartLabel string             `json:"start"`
	EndLabel   string             `json:"end"`
	Impact     models.Criticality `json:"impact"`
	Hops       int                `json:"hops"`
	CrossCloud bool               `json:"cross_cloud"` // path crosses a workload→cloud federation edge
	Steps      []Step             `json:"steps"`
	Summary    string             `json:"summary"`
}

// verbFor maps a capability edge type to a plain-language attacker action.
func verbFor(edgeType string) string {
	switch edgeType {
	case "assumes", "can_assume":
		return "assumes role"
	case "impersonates", "can_impersonate":
		return "impersonates"
	case "federated_from":
		return "federates into"
	case "binds_to":
		return "gains access to"
	case "has_permissions":
		return "wields the permissions of"
	case "uses":
		return "runs as"
	case "can_mint_token":
		return "mints a token for"
	default:
		return edgeType
	}
}

// NarratePath converts a raw attack path into narrated steps. Pure: no I/O.
func NarratePath(g *graph.Graph, p graph.Path) Scenario {
	sc := Scenario{Impact: p.Impact, Hops: p.Hops}
	for j, nid := range p.Nodes {
		label, typ, crit := nid.String(), "", models.Criticality("")
		if n, ok := g.Node(nid); ok {
			label, typ, crit = n.Label, n.Type, n.Criticality
		}
		step := Step{Index: j, Actor: label, NodeType: typ, Criticality: crit}
		if j == 0 {
			sc.StartLabel = label
			step.Verb = "foothold"
		} else if j-1 < len(p.Edges) {
			step.Via = p.Edges[j-1].Type
			step.Verb = verbFor(p.Edges[j-1].Type)
			if p.Edges[j-1].Type == "federated_from" {
				sc.CrossCloud = true
			}
		}
		sc.Steps = append(sc.Steps, step)
	}
	if n := len(sc.Steps); n > 0 {
		sc.EndLabel = sc.Steps[n-1].Actor
	}
	if len(sc.Steps) >= 2 {
		sc.Summary = fmt.Sprintf("%s → %s (%s) in %d hop(s)", sc.StartLabel, sc.EndLabel, p.Impact, p.Hops)
	}
	return sc
}

// BestPath returns the highest-impact, then shortest, path from the supplied set (already ranked by
// graph.AttackPaths), or (zero, false) when there are none.
func BestPath(paths []graph.Path) (graph.Path, bool) {
	if len(paths) == 0 {
		return graph.Path{}, false
	}
	return paths[0], true
}

// MostIllustrative picks the path that best tells the story: one that lands on an actual resource
// crown jewel (the asset the attacker is really after) rather than stopping at an intermediate
// admin role that graph.AttackPaths also counts as a target. Ties break toward more hops (the
// fuller chain). Falls back to the top-ranked path when no resource-terminal path exists.
func MostIllustrative(g *graph.Graph, paths []graph.Path) (graph.Path, bool) {
	if len(paths) == 0 {
		return graph.Path{}, false
	}
	best := -1
	for i, p := range paths {
		if len(p.Nodes) == 0 {
			continue
		}
		last, ok := g.Node(p.Nodes[len(p.Nodes)-1])
		if ok && last.Type == "resource" && last.Criticality == models.CritCrownJewel {
			if best < 0 || p.Hops > paths[best].Hops {
				best = i
			}
		}
	}
	if best >= 0 {
		return paths[best], true
	}
	return paths[0], true
}
