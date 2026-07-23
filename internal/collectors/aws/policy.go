package aws

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/nhiid/nhiid/internal/models"
)

// policyDoc is the subset of an IAM policy document we analyze. Action/Resource/Principal can each
// be a single string or an array in IAM JSON, so we decode them through stringOrSlice.
type policyDoc struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

type statement struct {
	Sid       string          `json:"Sid"`
	Effect    string          `json:"Effect"`
	Action    stringOrSlice   `json:"Action"`
	NotAction stringOrSlice   `json:"NotAction"`
	Resource  stringOrSlice   `json:"Resource"`
	Principal json.RawMessage `json:"Principal"`
	Condition map[string]any  `json:"Condition"`
}

// stringOrSlice decodes a JSON value that may be a string or []string.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err != nil {
		return err
	}
	*s = []string{single}
	return nil
}

// privEscalationActions are IAM actions that, alone or combined, allow a principal to grant itself
// more privilege. Presence of any of these is a strong over-privilege signal. This list is curated
// from well-known AWS privilege-escalation paths (Rhino Security Labs taxonomy).
var privEscalationActions = map[string]bool{
	"iam:createaccesskey":         true,
	"iam:createloginprofile":      true,
	"iam:updateloginprofile":      true,
	"iam:attachuserpolicy":        true,
	"iam:attachgrouppolicy":       true,
	"iam:attachrolepolicy":        true,
	"iam:putuserpolicy":           true,
	"iam:putgrouppolicy":          true,
	"iam:putrolepolicy":           true,
	"iam:createpolicyversion":     true,
	"iam:setdefaultpolicyversion": true,
	"iam:passrole":                true,
	"iam:updateassumerolepolicy":  true,
	"sts:assumerole":              true,
	"lambda:createfunction":       true,
	"lambda:updatefunctioncode":   true,
	"lambda:invokefunction":       true,
	"glue:createdevendpoint":      true,
	"cloudformation:createstack":  true,
	"datapipeline:createpipeline": true,
	"ec2:runinstances":            true,
}

// dataServices are services whose wildcarded resources we treat as high-criticality, since they
// commonly hold sensitive data. Crown-jewel classification is not inferred from actions — it is
// declared per resource via the criticality tag and applied in analyzePolicies (see tags.go).
var dataServices = map[string]bool{
	"s3": true, "dynamodb": true, "rds": true, "kms": true,
	"secretsmanager": true, "ssm": true, "redshift": true, "es": true,
}

// policyAnalysis is the normalized result of analyzing one or more permission policies.
type policyAnalysis struct {
	PermissionCount       int
	WildcardActionCount   int
	WildcardResourceCount int
	HasPrivEscalation     bool
	PrivilegeLevel        string // read|write|admin|privileged
	Bindings              []binding
}

// binding is a pre-model resource binding (resolved to identity/role id by the caller).
type binding struct {
	ResourceURN string
	Actions     []string
	Effect      string
	Criticality models.Criticality
}

// analyzePolicies decodes and analyzes a set of (already URL-decoded) policy documents. The
// resolver (may be nil) elevates a binding's criticality when its resource carries a criticality
// tag and the statement's actions can act on that resource.
func analyzePolicies(docs []string, resolver *critResolver) policyAnalysis {
	a := policyAnalysis{PrivilegeLevel: "read"}
	hasWrite, hasAdmin := false, false

	for _, raw := range docs {
		doc, err := decodePolicy(raw)
		if err != nil {
			continue
		}
		for _, st := range doc.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			actions := st.Action
			a.PermissionCount += len(actions)

			for _, res := range nonEmpty(st.Resource) {
				if res == "*" {
					a.WildcardResourceCount++
				}
			}

			crit := models.CritLow
			for _, act := range actions {
				la := strings.ToLower(act)
				if act == "*" || strings.HasSuffix(act, ":*") {
					a.WildcardActionCount++
				}
				if act == "*" || act == "*:*" || la == "iam:*" {
					hasAdmin = true
				}
				if privEscalationActions[la] {
					a.HasPrivEscalation = true
				}
				if isWriteAction(la) {
					hasWrite = true
				}
				if c := actionCriticality(la, st.Resource); models.CriticalityRank(c) > models.CriticalityRank(crit) {
					crit = c
				}
			}

			for _, res := range nonEmpty(st.Resource) {
				// Start from the action-inferred criticality, then elevate if this specific resource
				// is tagged as more critical and the statement's actions can reach it.
				bindCrit := crit
				if tagCrit := resolver.criticalityFor(res, actions); models.CriticalityRank(tagCrit) > models.CriticalityRank(bindCrit) {
					bindCrit = tagCrit
				}
				a.Bindings = append(a.Bindings, binding{
					ResourceURN: res,
					Actions:     dedupeLower(actions),
					Effect:      "allow",
					Criticality: bindCrit,
				})
			}
		}
	}

	switch {
	case hasAdmin:
		a.PrivilegeLevel = "admin"
	case a.HasPrivEscalation:
		a.PrivilegeLevel = "privileged"
	case hasWrite:
		a.PrivilegeLevel = "write"
	default:
		a.PrivilegeLevel = "read"
	}
	return a
}

// decodePolicy URL-decodes (IAM returns documents URL-encoded) then JSON-parses a policy.
func decodePolicy(raw string) (*policyDoc, error) {
	s := raw
	if dec, err := url.QueryUnescape(raw); err == nil {
		s = dec
	}
	var doc policyDoc
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// actionCriticality infers criticality from an action and its resources. It caps at CritHigh by
// design: whether a resource is a crown jewel is a business fact AWS cannot infer, so crown-jewel
// classification is applied separately from the criticality tag (see analyzePolicies + tags.go).
func actionCriticality(action string, resources stringOrSlice) models.Criticality {
	svc := serviceOf(action)
	wildOnData := false
	for _, r := range nonEmpty(resources) {
		if r == "*" && dataServices[svc] {
			wildOnData = true
		}
	}
	if action == "*" || action == "*:*" || action == "iam:*" {
		return models.CritHigh
	}
	if wildOnData {
		return models.CritHigh
	}
	if dataServices[svc] && isWriteAction(action) {
		return models.CritMedium
	}
	return models.CritLow
}

func serviceOf(action string) string {
	if i := strings.Index(action, ":"); i > 0 {
		return strings.ToLower(action[:i])
	}
	return ""
}

func isWriteAction(la string) bool {
	if la == "*" || la == "*:*" || strings.HasSuffix(la, ":*") {
		return true
	}
	for _, verb := range []string{":put", ":create", ":delete", ":update", ":write", ":modify", ":attach", ":set", ":remove", ":terminate"} {
		if strings.Contains(la, verb) {
			return true
		}
	}
	return false
}

func nonEmpty(s stringOrSlice) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func dedupeLower(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
