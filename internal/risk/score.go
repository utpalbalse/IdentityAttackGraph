// Package risk implements NHIID's transparent, weighted risk score. The composite is a weighted
// sum of six explainable sub-scores; every sub-score lists the discrete signals that produced it.
// There is no opaque ML in the score — anomaly detections feed the usage factor as evidenced
// boolean signals. See docs/RISK_MODEL.md.
package risk

import (
	"time"

	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
)

// Input is the decoupled, store-agnostic view the scorer needs for one identity.
type Input struct {
	Identity models.Identity
	Creds    []models.Credential
	Roles    []models.Role
	Bindings []models.ResourceBinding
	Trust    []models.TrustEdge
	Exposures []models.Exposure

	// Live anomaly signals, supplied by the detection engine (each is evidence-backed).
	Anomalies AnomalySignals

	// Graph-derived blast radius for this identity.
	Blast graph.BlastRadius

	// Peer-group baselines for creep detection.
	PeerPermissionP90 int
	PeerReachableP90  int

	Now time.Time
}

// AnomalySignals are discrete usage anomalies fed into the usage factor.
type AnomalySignals struct {
	ImpossibleTravel  bool
	NewRegion         bool
	NewASNOrRuntime   bool
	UsageSpike        bool
	FirstUseSensitive bool
	OffHoursBurst     bool
}

// Factor is one explainable sub-score.
type Factor struct {
	Score   int      `json:"score"`
	Signals []string `json:"signals"`
}

// Breakdown is the full explainable result for an identity.
type Breakdown struct {
	Composite int                `json:"composite"`
	Severity  models.Severity    `json:"severity"`
	Urgency   int                `json:"urgency"`
	Factors   map[string]Factor  `json:"factors"`
	Weights   map[string]float64 `json:"weights"`
}

// Engine computes scores from a set of weights.
type Engine struct{ W *Weights }

func NewEngine(w *Weights) *Engine { return &Engine{W: w} }

// Score produces the full explainable breakdown for one identity.
func (e *Engine) Score(in Input) Breakdown {
	cfg := e.W
	priv := e.privilege(in)
	exp := e.exposure(in)
	fresh := e.freshness(in)
	use := e.usage(in)
	trust := e.trust(in)
	blast := e.blast(in)

	factors := map[string]Factor{
		"privilege":    priv,
		"exposure":     exp,
		"freshness":    fresh,
		"usage":        use,
		"trust":        trust,
		"blast_radius": blast,
	}
	var composite float64
	for name, f := range factors {
		composite += cfg.Weights[name] * float64(f.Score)
	}
	c := clamp(int(composite + 0.5))
	b := Breakdown{
		Composite: c,
		Severity:  e.severity(c),
		Factors:   factors,
		Weights:   cfg.Weights,
	}
	b.Urgency = e.urgency(c, in)
	return b
}

func (e *Engine) privilege(in Input) Factor {
	f := Factor{}
	add := func(pts int, sig string) { f.Score += pts; if pts > 0 { f.Signals = append(f.Signals, sig) } }
	wildAct, wildRes := 0, 0
	hasAdmin, escal, writeCrown := false, false, false
	for _, r := range in.Roles {
		if r.PrivilegeLevel == "admin" || r.PrivilegeLevel == "privileged" {
			hasAdmin = true
		}
		wildAct += r.WildcardActionCount
		wildRes += r.WildcardResourceCount
		if a, _ := r.PolicyDocument["has_priv_escalation"].(bool); a {
			escal = true
		}
	}
	for _, b := range in.Bindings {
		if b.Effect == "allow" && b.ResourceCriticality == models.CritCrownJewel && hasWrite(b.Actions) {
			writeCrown = true
		}
	}
	if hasAdmin {
		add(e.W.sig("privilege", "admin_or_star"), "admin_or_star")
	}
	if wildAct > 0 {
		add(capPts(wildAct*e.W.sig("privilege", "wildcard_action"), e.W.sig("privilege", "wildcard_action_cap")), "wildcard_action")
	}
	if wildRes > 0 {
		add(capPts(wildRes*e.W.sig("privilege", "wildcard_resource"), e.W.sig("privilege", "wildcard_resource_cap")), "wildcard_resource")
	}
	if escal {
		add(e.W.sig("privilege", "priv_escalation_action"), "priv_escalation_action")
	}
	if writeCrown {
		add(e.W.sig("privilege", "write_crown_jewel"), "write_crown_jewel")
	}
	if in.PeerPermissionP90 > 0 && totalPerms(in.Roles) > in.PeerPermissionP90 {
		add(e.W.sig("privilege", "privilege_creep_p90"), "privilege_creep_p90")
	}
	f.Score = clamp(f.Score)
	return f
}

func (e *Engine) exposure(in Input) Factor {
	f := Factor{}
	add := func(pts int, sig string) { f.Score += pts; if pts > 0 { f.Signals = append(f.Signals, sig) } }
	pub, priv, verified := false, false, false
	for _, ex := range in.Exposures {
		// public vs private is conveyed by pattern/attributes upstream; default to private.
		priv = true
		if ex.Verified {
			verified = true
		}
		if ex.Pattern == "public" || ex.Path == "public" { // upstream may tag visibility
			pub = true
		}
	}
	if pub {
		add(e.W.sig("exposure", "public_repo"), "public_repo")
	} else if priv {
		add(e.W.sig("exposure", "private_repo_or_ci"), "private_repo_or_ci")
	}
	if verified {
		add(e.W.sig("exposure", "verified_live"), "verified_live")
	}
	for _, c := range in.Creds {
		if c.ExpiresAt == nil && (c.CredType == "aws_access_key" || c.CredType == "gcp_sa_key" || c.CredType == "api_key") {
			add(e.W.sig("exposure", "static_key_no_expiry"), "static_key_no_expiry")
			break
		}
	}
	f.Score = clamp(f.Score)
	return f
}

func (e *Engine) freshness(in Input) Factor {
	f := Factor{}
	add := func(pts int, sig string) { f.Score += pts; if pts > 0 { f.Signals = append(f.Signals, sig) } }
	now := in.Now
	if in.Identity.LastSeenAt == nil {
		if in.Identity.CreatedAtSource != nil && now.Sub(*in.Identity.CreatedAtSource) > 30*24*time.Hour {
			add(e.W.sig("freshness", "never_used_aged"), "never_used_aged")
		}
	} else if now.Sub(*in.Identity.LastSeenAt) > 90*24*time.Hour {
		add(e.W.sig("freshness", "unused_stale_window"), "unused_stale_window")
	}
	if in.Identity.LastRotatedAt == nil {
		add(e.W.sig("freshness", "rotation_unmanaged"), "rotation_unmanaged")
	} else if now.Sub(*in.Identity.LastRotatedAt) > 180*24*time.Hour {
		add(e.W.sig("freshness", "not_rotated"), "not_rotated")
	}
	f.Score = clamp(f.Score)
	return f
}

func (e *Engine) usage(in Input) Factor {
	f := Factor{}
	add := func(on bool, name string) {
		if on {
			f.Score += e.W.sig("usage", name)
			f.Signals = append(f.Signals, name)
		}
	}
	a := in.Anomalies
	add(a.ImpossibleTravel, "impossible_travel")
	add(a.NewRegion, "new_region")
	add(a.NewASNOrRuntime, "new_asn_or_runtime")
	add(a.UsageSpike, "usage_spike")
	add(a.FirstUseSensitive, "first_use_sensitive")
	add(a.OffHoursBurst, "offhours_burst")
	f.Score = clamp(f.Score)
	return f
}

func (e *Engine) trust(in Input) Factor {
	f := Factor{}
	add := func(pts int, sig string) { f.Score += pts; if pts > 0 { f.Signals = append(f.Signals, sig) } }
	for _, t := range in.Trust {
		if len(t.Condition) == 0 && (t.EdgeType == "can_assume") {
			add(e.W.sig("trust", "conditionless_assume"), "conditionless_assume")
		}
		if x, _ := t.Condition["cross_account"].(bool); x {
			add(e.W.sig("trust", "cross_account"), "cross_account")
		}
		if x, _ := t.Condition["wildcard_principal"].(bool); x {
			add(e.W.sig("trust", "wildcard_external"), "wildcard_external")
		}
		if t.EdgeType == "can_mint_token" || t.EdgeType == "can_impersonate" {
			add(e.W.sig("trust", "can_mint_or_impersonate"), "can_mint_or_impersonate")
		}
	}
	f.Score = clamp(f.Score)
	return f
}

func (e *Engine) blast(in Input) Factor {
	f := Factor{}
	add := func(pts int, sig string) { f.Score += pts; if pts > 0 { f.Signals = append(f.Signals, sig) } }
	br := in.Blast
	if br.CrownJewelCount > 0 {
		if br.NearestCrownJewel <= 1 {
			add(e.W.sig("blast_radius", "crown_jewel_1hop"), "crown_jewel_1hop")
		} else {
			add(e.W.sig("blast_radius", "crown_jewel_chain"), "crown_jewel_chain")
		}
	}
	if br.HighCritCount > 0 {
		add(capPts(br.HighCritCount*e.W.sig("blast_radius", "high_crit_each"), e.W.sig("blast_radius", "high_crit_cap")), "high_crit_reachable")
	}
	if in.PeerReachableP90 > 0 && br.ReachableResources > in.PeerReachableP90 {
		add(e.W.sig("blast_radius", "reachable_over_p90"), "reachable_over_p90")
	}
	if br.ReachesAdmin {
		add(e.W.sig("blast_radius", "escalate_to_admin"), "escalate_to_admin")
	}
	f.Score = clamp(f.Score)
	return f
}

func (e *Engine) urgency(composite int, in Input) int {
	u := composite
	verified, pub := false, false
	for _, ex := range in.Exposures {
		if ex.Verified {
			verified = true
		}
		if ex.Pattern == "public" {
			pub = true
		}
	}
	if verified {
		u += e.W.Urgency["exposure_verified_live"]
	}
	if in.Blast.CrownJewelCount > 0 {
		u += e.W.Urgency["reachable_crown_jewel"]
	}
	if pub {
		u += e.W.Urgency["publicly_exposed"]
	}
	return clamp(u)
}

func (e *Engine) severity(score int) models.Severity {
	b := e.W.SeverityBands
	switch {
	case score >= b["critical"]:
		return models.SevCritical
	case score >= b["high"]:
		return models.SevHigh
	case score >= b["medium"]:
		return models.SevMedium
	default:
		return models.SevLow
	}
}

// ----- helpers -----

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func capPts(v, cap int) int {
	if cap > 0 && v > cap {
		return cap
	}
	return v
}

func hasWrite(actions []string) bool {
	for _, a := range actions {
		switch a {
		case "*", "s3:*", "s3:PutObject", "s3:DeleteObject", "write", "*:*":
			return true
		}
	}
	return false
}

func totalPerms(roles []models.Role) int {
	t := 0
	for _, r := range roles {
		t += r.PermissionCount
	}
	return t
}
