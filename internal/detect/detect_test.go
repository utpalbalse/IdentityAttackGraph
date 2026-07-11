package detect

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// chainPath builds a synthetic attack path with the given capability edge sequence.
func chainPath(edgeTypes []string, impact models.Criticality) graph.Path {
	nodes := make([]uuid.UUID, len(edgeTypes)+1)
	for i := range nodes {
		nodes[i] = uuid.New()
	}
	edges := make([]graph.Edge, len(edgeTypes))
	for i, t := range edgeTypes {
		edges[i] = graph.Edge{Src: nodes[i], Dst: nodes[i+1], Type: t}
	}
	return graph.Path{Nodes: nodes, Edges: edges, Impact: impact, Hops: len(edgeTypes)}
}

func TestSuspiciousRoleChainFires(t *testing.T) {
	s := Subject{
		Identity: models.Identity{ID: uuid.New(), Name: "svc"},
		Paths:    []graph.Path{chainPath([]string{"assumes", "binds_to"}, models.CritCrownJewel)},
	}
	fs := suspiciousRoleChain{}.Detect(s, Config{}, time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != models.SevHigh {
		t.Errorf("severity = %s, want high", fs[0].Severity)
	}
	if fs[0].Confidence != 66 {
		t.Errorf("confidence = %d, want 66 (no observed pivots)", fs[0].Confidence)
	}
}

func TestSuspiciousRoleChainNeedsTrustEdge(t *testing.T) {
	// has_permissions → binds_to is a direct grant, not a pivot chain: must not fire.
	s := Subject{
		Identity: models.Identity{ID: uuid.New(), Name: "agent"},
		Paths:    []graph.Path{chainPath([]string{"has_permissions", "binds_to"}, models.CritCrownJewel)},
	}
	if fs := (suspiciousRoleChain{}).Detect(s, Config{}, time.Now()); len(fs) != 0 {
		t.Fatalf("no trust edge => no chain finding, got %d", len(fs))
	}
}

func TestSuspiciousRoleChainNeedsTwoHops(t *testing.T) {
	s := Subject{
		Identity: models.Identity{ID: uuid.New(), Name: "svc"},
		Paths:    []graph.Path{chainPath([]string{"assumes"}, models.CritCrownJewel)}, // 1 hop
	}
	if fs := (suspiciousRoleChain{}).Detect(s, Config{}, time.Now()); len(fs) != 0 {
		t.Fatalf("single-hop grant should not be a chain, got %d", len(fs))
	}
}

func TestSuspiciousRoleChainCorroborated(t *testing.T) {
	s := Subject{
		Identity: models.Identity{ID: uuid.New(), Name: "svc"},
		Paths:    []graph.Path{chainPath([]string{"impersonates", "has_permissions", "binds_to"}, models.CritCrownJewel)},
		Usage:    []models.UsageEvent{{EventName: "AssumeRole"}},
	}
	fs := suspiciousRoleChain{}.Detect(s, Config{}, time.Now())
	if len(fs) != 1 || fs[0].Confidence != 82 {
		t.Fatalf("observed pivot should raise confidence to 82, got %+v", fs)
	}
}

func TestEgressAllowlistSuppressesGeoAnomaly(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	usage := []models.UsageEvent{
		{EventTime: base, SrcCountry: "US", SrcIP: "203.0.113.5"},
		{EventTime: base.Add(2 * time.Minute), SrcCountry: "RU", SrcIP: "203.0.113.9"},
	}
	s := Subject{Identity: models.Identity{ID: uuid.New(), Name: "svc"}, Usage: usage}
	cfg := Config{ImpossibleTravelKMH: 900}

	if fs := (impossibleTravel{}).Detect(s, cfg, time.Now()); len(fs) == 0 {
		t.Fatal("impossible travel should fire without an allowlist")
	}
	cfg.EgressAllowlist = []string{"203.0.113.0/24"}
	if fs := (impossibleTravel{}).Detect(s, cfg, time.Now()); len(fs) != 0 {
		t.Fatalf("allowlisted egress IPs should suppress the anomaly, got %d", len(fs))
	}
}

func TestStaleAccessKeyAgeBased(t *testing.T) {
	now := time.Now()
	cfg := Config{StaleWindow: 90 * 24 * time.Hour, MaxCredAge: 365 * 24 * time.Hour, MaxRotationAge: 180 * 24 * time.Hour}
	used := now.Add(-1 * time.Hour) // actively used...

	// ...but 400 days old -> exceeds max age -> high severity.
	created := now.Add(-400 * 24 * time.Hour)
	s := Subject{Identity: models.Identity{ID: uuid.New(), Name: "svc"},
		Creds: []models.Credential{{ExternalID: "AKIA", CredType: "aws_access_key", Status: "active", LastUsedAt: &used, CreatedAtSource: &created}}}
	if fs := (staleAccessKey{}).Detect(s, cfg, now); len(fs) != 1 || fs[0].Severity != models.SevHigh {
		t.Fatalf("old actively-used key should fire high (exceeds_max_age), got %+v", fs)
	}

	// Fresh + recently used -> nothing.
	fresh := now.Add(-10 * 24 * time.Hour)
	s2 := Subject{Identity: models.Identity{ID: uuid.New(), Name: "svc"},
		Creds: []models.Credential{{ExternalID: "AKIA2", Status: "active", LastUsedAt: &used, CreatedAtSource: &fresh}}}
	if fs := (staleAccessKey{}).Detect(s2, cfg, now); len(fs) != 0 {
		t.Fatalf("fresh recently-used key should not fire, got %d", len(fs))
	}
}

func TestUnusedSecretFinding(t *testing.T) {
	now := time.Now()
	win := 90 * 24 * time.Hour

	f, ok := UnusedSecretFinding(models.Secret{Store: "sm", ExternalID: "a", Name: "a", ReferencedByCount: 0}, win, now)
	if !ok || f.Severity != models.SevLow || f.Detector != "unused_secret" || f.IdentityID != nil {
		t.Fatalf("unused, never-accessed secret should fire low + identity-agnostic: ok=%v f=%+v", ok, f)
	}

	if _, ok := UnusedSecretFinding(models.Secret{ReferencedByCount: 2}, win, now); ok {
		t.Error("referenced secret should not fire")
	}

	recent := now.Add(-24 * time.Hour)
	if _, ok := UnusedSecretFinding(models.Secret{ReferencedByCount: 0, LastAccessedAt: &recent}, win, now); ok {
		t.Error("recently accessed secret should not fire")
	}

	old := now.Add(-200 * 24 * time.Hour)
	if _, ok := UnusedSecretFinding(models.Secret{ReferencedByCount: 0, LastAccessedAt: &old}, win, now); !ok {
		t.Error("old unreferenced secret should fire")
	}
}
