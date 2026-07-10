// Command simulate renders an attacker's-eye walkthrough of the current inventory: it reads the
// persisted attack graph, finds the highest-impact paths (leaked credential → crown jewel, an
// over-scoped AI agent, a cross-cloud pod → cloud role hop), and narrates each one step by step
// with the detections that caught it and the single remediation that severs it. Run after seeding.
//
//	simulate            # colorized terminal walkthrough
//	simulate --json     # machine-readable scenarios (used for docs/samples)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/config"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/simulate"
	"github.com/nhiid/nhiid/internal/store"
)

const maxHops = 6

func main() {
	asJSON := flag.Bool("json", false, "emit scenarios as JSON instead of a narrated walkthrough")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")
	limit := flag.Int("scenarios", 3, "maximum scenarios to narrate")
	flag.Parse()

	useColor = !*noColor && os.Getenv("NO_COLOR") == ""

	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()
	s, err := store.New(ctx, cfg.Database.DSN, cfg.Database.MaxConns, cfg.Database.MinConns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	nodes, edges, err := s.Graph.LoadAll(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load graph: %v\n", err)
		os.Exit(1)
	}
	g := graph.FromModels(nodes, edges)

	idents, err := s.Identities.List(ctx, store.IdentityFilter{Limit: 1000})
	if err != nil {
		fmt.Fprintf(os.Stderr, "list identities: %v\n", err)
		os.Exit(1)
	}

	reports := selectReports(ctx, s, g, idents, *limit)

	if *asJSON {
		emitJSON(nodes, idents, reports)
		return
	}
	render(nodes, edges, idents, reports)
}

// report bundles everything needed to narrate one identity's worst-case story.
type report struct {
	Identity    models.Identity           `json:"identity"`
	Scenario    *simulate.Scenario        `json:"scenario,omitempty"`
	Blast       graph.BlastRadius         `json:"blast_radius"`
	Exposures   []models.Exposure         `json:"exposures,omitempty"`
	Findings    []models.Finding          `json:"findings,omitempty"`
	Remediation *models.RemediationAction `json:"top_remediation,omitempty"`
	kind        string                    // "leak" | "ai_agent" | "cross_cloud" | "blast"
}

func buildReport(ctx context.Context, s *store.Store, g *graph.Graph, id models.Identity) report {
	r := report{Identity: id}
	if nid, ok := g.NodeIDForEntity(id.ID); ok {
		if best, ok := simulate.MostIllustrative(g, g.AttackPaths(nid, maxHops, 12)); ok {
			sc := simulate.NarratePath(g, best)
			r.Scenario = &sc
		}
		r.Blast = g.ComputeBlastRadius(nid, maxHops)
	}
	r.Exposures, _ = s.Exposures.ForIdentity(ctx, id.ID)
	r.Findings, _ = s.Findings.List(ctx, store.FindingFilter{IdentityID: &id.ID})
	if rems, _ := s.Remediation.ForIdentity(ctx, id.ID); len(rems) > 0 {
		best := rems[0]
		for _, rm := range rems[1:] {
			if rm.RiskDelta > best.RiskDelta {
				best = rm
			}
		}
		r.Remediation = &best
	}
	return r
}

// selectReports picks the most instructive stories: a leaked-credential path to a crown jewel, an
// over-scoped AI agent, and a cross-cloud federation hop — then fills with the next highest-risk
// crown-jewel paths, deduped by identity.
func selectReports(ctx context.Context, s *store.Store, g *graph.Graph, idents []models.Identity, limit int) []report {
	// idents already arrive risk-sorted (desc).
	var leak, aiAgent, crossCloud *report
	var rest []report
	seen := map[uuid.UUID]bool{}

	take := func(id models.Identity) report { return buildReport(ctx, s, g, id) }

	for _, id := range idents {
		r := take(id)
		reachesCrown := r.Scenario != nil && r.Scenario.Impact == models.CritCrownJewel
		switch {
		case leak == nil && len(r.Exposures) > 0 && reachesCrown:
			r.kind = "leak"
			leak = &r
			seen[id.ID] = true
		case aiAgent == nil && id.IsAIAgent:
			r.kind = "ai_agent"
			aiAgent = &r
			seen[id.ID] = true
		case crossCloud == nil && r.Scenario != nil && r.Scenario.CrossCloud:
			r.kind = "cross_cloud"
			crossCloud = &r
			seen[id.ID] = true
		}
	}

	// Fill remaining slots with the highest-risk crown-jewel paths not already featured.
	for _, id := range idents {
		if seen[id.ID] {
			continue
		}
		r := take(id)
		if r.Scenario != nil && r.Scenario.Impact == models.CritCrownJewel {
			r.kind = "blast"
			rest = append(rest, r)
		}
	}

	var out []report
	for _, r := range []*report{leak, aiAgent, crossCloud} {
		if r != nil {
			out = append(out, *r)
		}
	}
	out = append(out, rest...)
	// Stable order already (risk-sorted input); cap to limit.
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func emitJSON(nodes []models.GraphNode, idents []models.Identity, reports []report) {
	crown := 0
	for _, n := range nodes {
		if n.Criticality == models.CritCrownJewel {
			crown++
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"summary": map[string]any{
			"identities":   len(idents),
			"graph_nodes":  len(nodes),
			"crown_jewels": crown,
			"scenarios":    len(reports),
		},
		"scenarios": reports,
	})
}

// ----- terminal rendering -----

var useColor = true

func c(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string   { return c("1", s) }
func dim(s string) string    { return c("2", s) }
func red(s string) string    { return c("1;31", s) }
func green(s string) string  { return c("32", s) }
func cyan(s string) string   { return c("36", s) }
func yellow(s string) string { return c("33", s) }

func sevColor(sev models.Severity, s string) string {
	switch sev {
	case models.SevCritical:
		return c("1;31", s)
	case models.SevHigh:
		return c("35", s)
	case models.SevMedium:
		return c("33", s)
	default:
		return c("34", s)
	}
}

func critTag(crit models.Criticality) string {
	if crit == models.CritCrownJewel {
		return " " + red("◆ CROWN JEWEL")
	}
	if crit == models.CritHigh {
		return " " + yellow("▲ high")
	}
	return ""
}

func render(nodes []models.GraphNode, edges []models.GraphEdge, idents []models.Identity, reports []report) {
	crown := 0
	for _, n := range nodes {
		if n.Criticality == models.CritCrownJewel {
			crown++
		}
	}
	fmt.Println()
	fmt.Println(bold(cyan("  IdentityAttackGraph — Attack-Path Simulation")))
	fmt.Println(dim("  ─────────────────────────────────────────────"))
	fmt.Printf("  %d identities · %d graph nodes · %d edges · %s\n\n",
		len(idents), len(nodes), len(edges), red(fmt.Sprintf("%d crown jewels", crown)))

	if len(reports) == 0 {
		fmt.Println(yellow("  No attack paths found. Seed the demo first:  make demo\n"))
		return
	}

	for i, r := range reports {
		renderReport(i+1, r)
	}
	fmt.Println(dim("  Detections and remediations shown above are computed live from the graph.\n"))
}

func renderReport(n int, r report) {
	title := map[string]string{
		"leak":        "Leaked credential → crown jewel",
		"ai_agent":    "Over-scoped AI agent",
		"cross_cloud": "Cross-cloud: workload → cloud privileges",
		"blast":       "High blast radius",
	}[r.kind]

	fmt.Printf("%s %s\n", bold(cyan(fmt.Sprintf("━━━ Scenario %d ·", n))), bold(title))
	fmt.Printf("  %s  %s  (risk %s)\n", dim("target"), bold(r.Identity.Name),
		riskColor(r.Identity.RiskScore))

	// Recon: a leaked credential the attacker would find first.
	if len(r.Exposures) > 0 {
		ex := r.Exposures[0]
		fmt.Printf("  %s  attacker finds credential material at %s (pattern %s) — belongs to %s\n",
			yellow("RECON "), bold(ex.Path+lineSuffix(ex.Line)), ex.Pattern, r.Identity.Name)
	}

	// AI-agent posture callout.
	if r.Identity.IsAIAgent {
		m := r.Identity.AIAgentMeta
		fmt.Printf("  %s  framework=%v model=%v ttl=%vh broad_scope=%v uncontrolled_tools=%v\n",
			yellow("AGENT "), m["framework"], m["model"], m["ttl_hours"], m["broad_api_scope"], m["uncontrolled_tools"])
	}

	// The path, step by step.
	if r.Scenario != nil {
		for _, st := range r.Scenario.Steps {
			if st.Index == 0 {
				fmt.Printf("  %s  ▸ %s %s\n", dim("STEP 0"), bold(st.Actor), dim("["+st.NodeType+"]"))
				continue
			}
			fmt.Printf("  %s  → %s %s %s%s\n", dim(fmt.Sprintf("STEP %d", st.Index)),
				cyan(st.Verb), bold(st.Actor), dim("["+st.NodeType+"]"), critTag(st.Criticality))
		}
		if r.Scenario.CrossCloud {
			fmt.Printf("  %s  this path crosses a workload→cloud federation edge (IRSA/Workload Identity)\n", yellow("NOTE  "))
		}
	}

	// Impact.
	b := r.Blast
	fmt.Printf("  %s %s reachable · nearest crown jewel %s · reaches admin: %v\n",
		green("IMPACT"), red(fmt.Sprintf("%d crown jewel(s)", b.CrownJewelCount)),
		hopStr(b.NearestCrownJewel), b.ReachesAdmin)

	// Detections.
	if len(r.Findings) > 0 {
		var parts []string
		for _, f := range sortFindings(r.Findings) {
			parts = append(parts, sevColor(f.Severity, fmt.Sprintf("%s (%s)", f.Detector, f.Severity)))
		}
		fmt.Printf("  %s  %s\n", green("CAUGHT"), joinWrap(parts))
	}

	// The fix.
	if r.Remediation != nil {
		rm := r.Remediation
		fmt.Printf("  %s  %s  →  risk %d→%d (%s)\n", green("FIX   "), rm.Action,
			rm.RiskBefore, rm.RiskAfter, green(fmt.Sprintf("−%d", rm.RiskDelta)))
	}
	fmt.Println()
}

func riskColor(v int) string {
	s := fmt.Sprintf("%d", v)
	switch {
	case v >= 70:
		return red(s)
	case v >= 40:
		return yellow(s)
	default:
		return s
	}
}

func hopStr(h int) string {
	if h < 0 {
		return "—"
	}
	return fmt.Sprintf("%d hop(s)", h)
}

func lineSuffix(line int) string {
	if line > 0 {
		return fmt.Sprintf(":%d", line)
	}
	return ""
}

func sortFindings(fs []models.Finding) []models.Finding {
	out := append([]models.Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool {
		return models.SeverityRank(out[i].Severity) > models.SeverityRank(out[j].Severity)
	})
	return out
}

func joinWrap(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
			if i%3 == 0 {
				out += "\n          "
			}
		}
		out += p
	}
	return out
}
