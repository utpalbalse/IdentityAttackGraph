// Package remediate turns a finding into ranked remediation recommendations, each with a
// *projected risk delta* computed by re-scoring the identity with the fix hypothetically applied.
// This reuses the risk engine, so the delta is consistent with the score the operator sees and
// gives measurable "risk reduction if you do this" guidance. See docs/RISK_MODEL.md.
package remediate

import (
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/risk"
)

// Plan is one recommended action with its rationale and projected effect.
type Plan struct {
	Action    string
	Rationale string
	RiskAfter int
	RiskDelta int
}

// recommendation pairs an action with a mutation that simulates having performed it.
type recommendation struct {
	action    string
	rationale string
	mutate    func(*risk.Input)
}

// catalog maps each detector to its remediation options (ordered by preference).
var catalog = map[string][]recommendation{
	"secret_exposed_in_repo": {
		{"rotate", "Rotate the exposed credential and purge it from history.", clearExposuresAndKeys},
		{"revoke", "Revoke the leaked credential immediately if rotation is delayed.", clearKeys},
	},
	"stale_access_key": {
		{"disable_key", "Disable the unused key, then delete after a grace period.", clearKeys},
		{"revoke", "Delete the unused credential.", clearKeys},
	},
	"stale_identity": {
		{"remove_identity", "Decommission the dormant identity.", decommission},
	},
	"orphaned_identity": {
		{"remove_identity", "Remove the unaccounted-for identity (or assign an owner).", decommission},
	},
	"over_privileged_sa": {
		{"reduce_scope", "Replace admin/wildcard grants with least-privilege permissions.", leastPrivilege},
	},
	"privilege_creep": {
		{"reduce_scope", "Trim permissions back toward the peer-group baseline.", leastPrivilege},
	},
	"conditionless_assume_role": {
		{"add_condition", "Require ExternalId/MFA on the assume-role trust.", guardTrust},
		{"break_trust", "Remove the trust relationship if it is unnecessary.", breakTrust},
	},
	"wildcard_trust": {
		{"break_trust", "Remove the wildcard/external trust principal.", breakTrust},
		{"add_condition", "Constrain the principal and add conditions.", guardTrust},
	},
	"high_blast_radius": {
		{"reduce_scope", "Cut the privileges that reach crown-jewel resources.", leastPrivilege},
		{"break_trust", "Break the assume-role chain into the high-impact target.", breakTrust},
	},
	"ai_agent_overscoped": {
		{"reduce_scope", "Scope the agent's API/tool access to least privilege.", leastPrivilege},
		{"shorten_ttl", "Shorten the agent credential TTL.", nil},
	},
	"impossible_travel":          {{"require_mfa", "Force re-auth with MFA and investigate the session.", nil}},
	"unusual_geo":                {{"require_mfa", "Require MFA from new locations; verify the access is expected.", nil}},
	"first_use_sensitive_action": {{"require_mfa", "Require MFA for sensitive actions; confirm the change was intended.", nil}},
	"usage_spike":                {{"require_mfa", "Throttle and require MFA while investigating the spike.", nil}},
}

// Recommend returns ranked plans for a finding, computing each plan's projected risk delta by
// re-scoring a mutated copy of the identity's risk input. `current` is the identity's present
// composite score (computed by the caller from the same engine + input for consistency).
func Recommend(detector string, in risk.Input, engine *risk.Engine, current int) []Plan {
	recs, ok := catalog[detector]
	if !ok {
		return nil
	}
	var plans []Plan
	for _, rec := range recs {
		after := current
		if rec.mutate != nil {
			cp := cloneInput(in)
			rec.mutate(&cp)
			after = engine.Score(cp).Composite
		}
		delta := current - after
		if delta < 0 {
			delta = 0
		}
		plans = append(plans, Plan{Action: rec.action, Rationale: rec.rationale, RiskAfter: after, RiskDelta: delta})
	}
	return plans
}

// ----- mutations (each simulates a remediation) -----

func clearExposuresAndKeys(in *risk.Input) { in.Exposures = nil; in.Creds = nil }
func clearKeys(in *risk.Input)             { in.Creds = nil }

func decommission(in *risk.Input) {
	in.Roles = nil
	in.Bindings = nil
	in.Creds = nil
	in.Exposures = nil
	in.Trust = nil
	in.Blast = graph.BlastRadius{}
}

func leastPrivilege(in *risk.Input) {
	var kept []models.Role
	for _, r := range in.Roles {
		if r.PrivilegeLevel == "admin" || r.PrivilegeLevel == "privileged" {
			continue // drop the dangerous grants
		}
		r.WildcardActionCount = 0
		r.WildcardResourceCount = 0
		kept = append(kept, r)
	}
	in.Roles = kept
	// drop write access to crown-jewel resources and assume the blast path is cut
	var binds []models.ResourceBinding
	for _, b := range in.Bindings {
		if b.ResourceCriticality == models.CritCrownJewel {
			continue
		}
		binds = append(binds, b)
	}
	in.Bindings = binds
	in.Blast = graph.BlastRadius{}
}

func guardTrust(in *risk.Input) {
	guarded := make([]models.TrustEdge, len(in.Trust))
	for i, t := range in.Trust {
		cond := map[string]any{"guards": []string{"mfa", "external_id"}}
		for k, v := range t.Condition {
			if k != "guards" {
				cond[k] = v
			}
		}
		t.Condition = cond
		guarded[i] = t
	}
	in.Trust = guarded
}

func breakTrust(in *risk.Input) {
	in.Trust = nil
	in.Blast = graph.BlastRadius{} // removing the assume path removes the reachable blast radius
}

// cloneInput makes a copy deep enough that mutations don't touch the caller's slices/maps.
func cloneInput(in risk.Input) risk.Input {
	cp := in
	cp.Creds = append([]models.Credential(nil), in.Creds...)
	cp.Roles = append([]models.Role(nil), in.Roles...)
	cp.Bindings = append([]models.ResourceBinding(nil), in.Bindings...)
	cp.Exposures = append([]models.Exposure(nil), in.Exposures...)
	cp.Trust = append([]models.TrustEdge(nil), in.Trust...)
	return cp
}
