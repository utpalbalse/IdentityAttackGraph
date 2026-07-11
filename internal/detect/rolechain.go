package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// trustEdgeTypes are the capability edges that represent identity pivots (as opposed to owning a
// permission set or binding a resource). A chain of these is lateral movement.
var trustEdgeTypes = map[string]bool{
	"assumes":        true,
	"impersonates":   true,
	"federated_from": true,
	"can_mint_token": true,
}

// suspicious_role_chain — an anomalous assume/impersonate/federate *sequence* that escalates
// privilege beyond any single direct grant. Candidate chains come from the graph engine's
// attack-path traversal; observed assume/impersonate usage corroborates and raises confidence.
type suspiciousRoleChain struct{}

func (suspiciousRoleChain) ID() string { return "suspicious_role_chain" }

func (suspiciousRoleChain) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	best, ok := deepestTrustChain(s.Paths)
	if !ok {
		return nil
	}
	trustHops := countTrustEdges(best.Edges)
	observed := observedPivotCount(s.Usage)
	conf := 66
	corro := ""
	if observed > 0 {
		conf = 82
		corro = fmt.Sprintf(" Corroborated by %d observed assume/impersonate event(s).", observed)
	}
	ev := map[string]any{
		"total_hops":            best.Hops,
		"trust_hops":            trustHops,
		"edge_sequence":         edgeSequence(best.Edges),
		"impact":                string(best.Impact),
		"observed_pivot_events": observed,
	}
	narr := fmt.Sprintf("Identity %q can chain %d trust hop(s) (assume/impersonate/federate) to reach %s "+
		"in %d hop(s) — lateral movement that escalates beyond any single direct grant.%s",
		s.Identity.Name, trustHops, best.Impact, best.Hops, corro)
	return []models.Finding{finding(s, "suspicious_role_chain", "trust", models.SevHigh, conf,
		"Suspicious role/impersonation chain", narr, ev, string(best.Impact), fmt.Sprintf("%dh", best.Hops))}
}

// deepestTrustChain picks the highest-impact, then longest, attack path that includes at least one
// trust pivot and spans at least two hops (i.e. not a direct grant).
func deepestTrustChain(paths []graph.Path) (graph.Path, bool) {
	best := -1
	for i, p := range paths {
		if p.Hops < 2 || countTrustEdges(p.Edges) < 1 {
			continue
		}
		if best < 0 || betterChain(p, paths[best]) {
			best = i
		}
	}
	if best < 0 {
		return graph.Path{}, false
	}
	return paths[best], true
}

func betterChain(a, b graph.Path) bool {
	if ra, rb := models.CriticalityRank(a.Impact), models.CriticalityRank(b.Impact); ra != rb {
		return ra > rb
	}
	return a.Hops > b.Hops
}

func countTrustEdges(edges []graph.Edge) int {
	n := 0
	for _, e := range edges {
		if trustEdgeTypes[e.Type] {
			n++
		}
	}
	return n
}

func edgeSequence(edges []graph.Edge) []string {
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.Type)
	}
	return out
}

// observedPivotCount counts assume-role / impersonation events in the usage window (corroboration).
func observedPivotCount(usage []models.UsageEvent) int {
	n := 0
	for _, u := range usage {
		name := strings.ToLower(u.EventName)
		if strings.Contains(name, "assumerole") || strings.Contains(name, "impersonate") ||
			strings.Contains(name, "generateaccesstoken") {
			n++
		}
	}
	return n
}
