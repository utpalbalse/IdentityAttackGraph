package aws

import (
	"encoding/json"
	"strings"
)

// trustGrant is one principal that may assume a role, with the security posture of that grant.
type trustGrant struct {
	PrincipalARN string
	Wildcard     bool     // principal is "*" or otherwise unbounded
	External     bool     // a Federated / SAML / OIDC principal
	Service      bool     // an AWS service principal (e.g. ec2.amazonaws.com) — not an attack edge
	Guards       []string // security conditions present: external_id, mfa, source_ip, org_id
}

// principalBlock models the Principal element, which can be "*" or an object of typed lists.
type principalBlock struct {
	AWS       stringOrSlice `json:"AWS"`
	Service   stringOrSlice `json:"Service"`
	Federated stringOrSlice `json:"Federated"`
}

// parseTrustPolicy decodes an AssumeRolePolicyDocument into the grants it expresses.
func parseTrustPolicy(raw string) []trustGrant {
	doc, err := decodePolicy(raw)
	if err != nil {
		return nil
	}
	var grants []trustGrant
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		guards := extractGuards(st.Condition)

		// Principal may be the literal string "*" or an object.
		if isWildcardPrincipal(st.Principal) {
			grants = append(grants, trustGrant{PrincipalARN: "*", Wildcard: true, Guards: guards})
			continue
		}
		var pb principalBlock
		if err := json.Unmarshal(st.Principal, &pb); err != nil {
			continue
		}
		for _, arn := range pb.AWS {
			if arn == "*" {
				grants = append(grants, trustGrant{PrincipalARN: "*", Wildcard: true, Guards: guards})
			} else {
				grants = append(grants, trustGrant{PrincipalARN: arn, Guards: guards})
			}
		}
		for _, f := range pb.Federated {
			grants = append(grants, trustGrant{PrincipalARN: f, External: true, Guards: guards})
		}
		for _, s := range pb.Service {
			grants = append(grants, trustGrant{PrincipalARN: s, Service: true, Guards: guards})
		}
	}
	return grants
}

func isWildcardPrincipal(raw json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == "*"
	}
	return false
}

// extractGuards inspects a trust condition block for meaningful security constraints.
func extractGuards(cond map[string]any) []string {
	var guards []string
	flat := strings.ToLower(flattenKeys(cond))
	if strings.Contains(flat, "externalid") {
		guards = append(guards, "external_id")
	}
	if strings.Contains(flat, "multifactorauthpresent") || strings.Contains(flat, "mfa") {
		guards = append(guards, "mfa")
	}
	if strings.Contains(flat, "sourceip") {
		guards = append(guards, "source_ip")
	}
	if strings.Contains(flat, "principalorgid") || strings.Contains(flat, "sourcearn") || strings.Contains(flat, "sourceaccount") {
		guards = append(guards, "org_scope")
	}
	return guards
}

// flattenKeys returns a string of all nested condition keys/values for substring matching.
func flattenKeys(m map[string]any) string {
	var b strings.Builder
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, vv := range t {
				b.WriteString(k)
				b.WriteByte(' ')
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		case string:
			b.WriteString(t)
			b.WriteByte(' ')
		}
	}
	walk(m)
	return b.String()
}

// accountFromARN extracts the 12-digit account id from an IAM ARN, or "" if not present.
func accountFromARN(arn string) string {
	// arn:aws:iam::123456789012:user/x  → field index 4 is the account.
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
