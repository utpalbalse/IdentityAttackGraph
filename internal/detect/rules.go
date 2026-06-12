package detect

import (
	"fmt"
	"time"

	"github.com/nhiid/nhiid/internal/models"
)

// ---- orphaned_identity -------------------------------------------------------

type orphanedIdentity struct{}

func (orphanedIdentity) ID() string { return "orphaned_identity" }
func (orphanedIdentity) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	if s.Identity.State != "active" {
		return nil
	}
	if breakGlass(s.Identity) {
		return nil
	}
	hasOwner := s.Owner != nil || s.Identity.OwnerID != nil
	hasWorkload := len(s.Workloads) > 0
	hasRepo := len(s.Exposures) > 0
	if hasOwner || hasWorkload || hasRepo {
		return nil
	}
	ev := map[string]any{
		"missing": []string{"owner", "workload", "repo_reference"},
		"created": s.Identity.CreatedAtSource,
		"last_seen": s.Identity.LastSeenAt,
		"account": s.Identity.Prov.AccountRef,
	}
	narr := fmt.Sprintf("Identity %q has no owner, no workload running as it, and no repository reference. "+
		"It is unaccounted for — an abandoned credential an attacker can use without anyone noticing.", s.Identity.Name)
	return []models.Finding{finding(s, "orphaned_identity", "hygiene", models.SevMedium, 70,
		"Orphaned non-human identity", narr, ev)}
}

// ---- stale_identity ----------------------------------------------------------

type staleIdentity struct{}

func (staleIdentity) ID() string { return "stale_identity" }
func (staleIdentity) Detect(s Subject, cfg Config, now time.Time) []models.Finding {
	if breakGlass(s.Identity) {
		return nil
	}
	last := s.Identity.LastSeenAt
	stale := false
	if last == nil {
		if s.Identity.CreatedAtSource != nil && now.Sub(*s.Identity.CreatedAtSource) > 30*24*time.Hour {
			stale = true
		}
	} else if now.Sub(*last) > cfg.StaleWindow {
		stale = true
	}
	if !stale {
		return nil
	}
	sev := models.SevLow
	if days := daysAgo(last, now); days > 180 || last == nil {
		sev = models.SevMedium
	}
	ev := map[string]any{"last_seen": last, "stale_window_days": int(cfg.StaleWindow.Hours() / 24)}
	narr := fmt.Sprintf("Identity %q has had no legitimate usage within the staleness window. "+
		"Dormant credentials are unmonitored attack surface and prime candidates for revocation.", s.Identity.Name)
	return []models.Finding{finding(s, "stale_identity", "hygiene", sev, 75,
		"Stale unused identity", narr, ev)}
}

// ---- stale_access_key --------------------------------------------------------

type staleAccessKey struct{}

func (staleAccessKey) ID() string { return "stale_access_key" }
func (staleAccessKey) Detect(s Subject, cfg Config, now time.Time) []models.Finding {
	var out []models.Finding
	for _, c := range s.Creds {
		if c.Status != "active" {
			continue
		}
		stale := c.LastUsedAt == nil || now.Sub(*c.LastUsedAt) > cfg.StaleWindow
		if !stale {
			continue
		}
		ev := map[string]any{"credential": c.ExternalID, "type": c.CredType, "last_used": c.LastUsedAt}
		narr := fmt.Sprintf("Credential %s (%s) on identity %q has not been used within the staleness window. "+
			"Unused long-lived keys should be disabled then deleted.", c.ExternalID, c.CredType, s.Identity.Name)
		out = append(out, finding(s, "stale_access_key", "hygiene", models.SevMedium, 80,
			"Stale unused credential", narr, ev, c.ExternalID))
	}
	return out
}

// ---- over_privileged_sa ------------------------------------------------------

type overPrivilegedSA struct{}

func (overPrivilegedSA) ID() string { return "over_privileged_sa" }
func (overPrivilegedSA) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	var matched []string
	admin, escalation, writeCrown := false, false, false
	for _, r := range s.Roles {
		if r.PrivilegeLevel == "admin" || r.PrivilegeLevel == "privileged" {
			admin = true
			matched = append(matched, "role:"+r.Name+":admin")
		}
		if v, _ := r.PolicyDocument["has_priv_escalation"].(bool); v {
			escalation = true
			matched = append(matched, "role:"+r.Name+":priv_escalation")
		}
	}
	for _, b := range s.Bindings {
		if b.Effect == "allow" && b.ResourceCriticality == models.CritCrownJewel && hasWriteAction(b.Actions) {
			writeCrown = true
			matched = append(matched, "write:"+b.ResourceURN)
		}
	}
	if !admin && !escalation && !writeCrown {
		return nil
	}
	ev := map[string]any{"matched": matched, "admin": admin, "priv_escalation": escalation, "write_crown_jewel": writeCrown}
	narr := fmt.Sprintf("Identity %q holds excessive privilege (%v). This grants a concrete escalation or "+
		"high-impact write primitive far beyond least privilege.", s.Identity.Name, matched)
	return []models.Finding{finding(s, "over_privileged_sa", "privilege", models.SevHigh, 78,
		"Over-privileged service identity", narr, ev)}
}

// ---- conditionless_assume_role ----------------------------------------------

type conditionlessTrust struct{}

func (conditionlessTrust) ID() string { return "conditionless_assume_role" }
func (conditionlessTrust) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	var out []models.Finding
	for _, t := range s.Trust {
		if t.EdgeType != "can_assume" || len(t.Condition) > 0 {
			continue
		}
		ev := map[string]any{"edge": t.EdgeType, "missing_conditions": []string{"ExternalId", "MFA", "SourceIp"}}
		narr := fmt.Sprintf("Identity %q can assume a role with no trust condition (no ExternalId/MFA/IP restriction). "+
			"This is lateral-movement fuel: anyone able to act as the principal inherits the target role.", s.Identity.Name)
		out = append(out, finding(s, "conditionless_assume_role", "trust", models.SevHigh, 72,
			"Conditionless assume-role trust", narr, ev, t.ID.String()))
	}
	return out
}

// ---- wildcard_trust ----------------------------------------------------------

type wildcardTrust struct{}

func (wildcardTrust) ID() string { return "wildcard_trust" }
func (wildcardTrust) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	var out []models.Finding
	for _, t := range s.Trust {
		wild, _ := t.Condition["wildcard_principal"].(bool)
		if !wild {
			continue
		}
		ev := map[string]any{"edge": t.EdgeType, "condition": t.Condition}
		narr := fmt.Sprintf("Identity/role linked to %q trusts a wildcard or external principal. "+
			"This dramatically widens who can obtain its privileges.", s.Identity.Name)
		out = append(out, finding(s, "wildcard_trust", "trust", models.SevHigh, 74,
			"Wildcard/external trust principal", narr, ev, t.ID.String()))
	}
	return out
}

// ---- secret_exposed_in_repo --------------------------------------------------

type secretExposedInRepo struct{}

func (secretExposedInRepo) ID() string { return "secret_exposed_in_repo" }
func (secretExposedInRepo) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	var out []models.Finding
	for _, ex := range s.Exposures {
		sev := models.SevHigh
		if ex.Verified || ex.Pattern == "public" {
			sev = models.SevCritical
		}
		// Evidence carries the LOCATION only — never the secret value (threat model rule).
		ev := map[string]any{
			"path": ex.Path, "commit": ex.CommitSHA, "line": ex.Line,
			"pattern": ex.Pattern, "verified": ex.Verified, "fingerprint": ex.Fingerprint,
		}
		reach := ""
		if s.Blast.CrownJewelCount > 0 {
			reach = " The exposed credential can reach a crown-jewel resource, making this an immediate priority."
		}
		narr := fmt.Sprintf("Credential material for identity %q was found in a repository at %s (pattern %s).%s",
			s.Identity.Name, ex.Path, ex.Pattern, reach)
		out = append(out, finding(s, "secret_exposed_in_repo", "exposure", sev, 85,
			"Credential material exposed in repository", narr, ev, ex.Fingerprint))
	}
	return out
}

// ---- high_blast_radius -------------------------------------------------------

type highBlastRadius struct{}

func (highBlastRadius) ID() string { return "high_blast_radius" }
func (highBlastRadius) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	if s.Blast.CrownJewelCount == 0 && !s.Blast.ReachesAdmin {
		return nil
	}
	pathDesc := make([]string, 0, len(s.Paths))
	for _, p := range s.Paths {
		pathDesc = append(pathDesc, fmt.Sprintf("%d hops -> %s", p.Hops, p.Impact))
	}
	ev := map[string]any{
		"crown_jewels_reachable": s.Blast.CrownJewelCount,
		"nearest_crown_jewel_hops": s.Blast.NearestCrownJewel,
		"reaches_admin": s.Blast.ReachesAdmin,
		"top_paths": pathDesc,
	}
	narr := fmt.Sprintf("Identity %q can reach high-impact resources (crown jewels: %d, admin: %v). "+
		"If compromised, blast radius extends to critical assets via the listed attack paths.",
		s.Identity.Name, s.Blast.CrownJewelCount, s.Blast.ReachesAdmin)
	return []models.Finding{finding(s, "high_blast_radius", "blast_radius", models.SevHigh, 76,
		"High blast radius identity", narr, ev)}
}

// ---- ai_agent_overscoped -----------------------------------------------------

type aiAgentOverscoped struct{}

func (aiAgentOverscoped) ID() string { return "ai_agent_overscoped" }
func (aiAgentOverscoped) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	if !s.Identity.IsAIAgent {
		return nil
	}
	meta := s.Identity.AIAgentMeta
	ttlHours, _ := toFloat(meta["ttl_hours"])
	broadScope, _ := meta["broad_api_scope"].(bool)
	uncontrolledTools, _ := meta["uncontrolled_tools"].(bool)
	if !broadScope && !uncontrolledTools && ttlHours <= 24 {
		return nil
	}
	ev := map[string]any{"ttl_hours": ttlHours, "broad_api_scope": broadScope, "uncontrolled_tools": uncontrolledTools, "tools": meta["tools"]}
	narr := fmt.Sprintf("AI-agent identity %q is over-scoped (broad API scope=%v, uncontrolled tools=%v, TTL=%.0fh). "+
		"Autonomous agents with broad, long-lived, weakly-scoped access are high-consequence targets.",
		s.Identity.Name, broadScope, uncontrolledTools, ttlHours)
	return []models.Finding{finding(s, "ai_agent_overscoped", "ai_agent", models.SevHigh, 70,
		"Over-scoped AI-agent identity", narr, ev)}
}

// ---- helpers -----------------------------------------------------------------

func breakGlass(id models.Identity) bool {
	if v, _ := id.Attributes["break_glass"].(bool); v {
		return true
	}
	return false
}

func hasWriteAction(actions []string) bool {
	for _, a := range actions {
		switch a {
		case "*", "*:*", "s3:*", "s3:PutObject", "s3:DeleteObject", "write", "iam:*":
			return true
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
