package gcp

import (
	"strings"

	"github.com/nhiid/nhiid/internal/models"
)

// GCP's privilege model is role-binding based: a member is granted a predefined or custom role on a
// resource. These maps classify the roles that matter for NHI risk and lateral movement.

// escalationRoles let a principal grant itself more privilege (set IAM policy, mint keys/tokens).
var escalationRoles = map[string]bool{
	"roles/owner":                             true,
	"roles/iam.securityAdmin":                 true,
	"roles/iam.serviceAccountTokenCreator":    true,
	"roles/iam.serviceAccountUser":            true,
	"roles/iam.serviceAccountKeyAdmin":        true,
	"roles/iam.roleAdmin":                     true,
	"roles/iam.organizationRoleAdmin":         true,
	"roles/resourcemanager.organizationAdmin": true,
	"roles/iam.workloadIdentityPoolAdmin":     true,
}

// impersonationRoles, when held *on a service account*, let the holder act as / mint tokens for it
// — the GCP equivalent of cross-account assume-role and a primary lateral-movement edge.
var impersonationRoles = map[string]bool{
	"roles/iam.serviceAccountTokenCreator": true, // generateAccessToken / signJwt
	"roles/iam.serviceAccountUser":         true, // actAs
	"roles/iam.serviceAccountKeyAdmin":     true, // create a key, then use it
	"roles/owner":                          true,
	"roles/editor":                         true,
}

// federationRoles bind external workload-identity principals to a service account (WIF).
var federationRoles = map[string]bool{
	"roles/iam.workloadIdentityUser": true,
}

// dataServices whose admin/write roles we treat as high-criticality reach.
var dataServices = []string{"storage", "bigquery", "secretmanager", "cloudkms", "spanner", "sql", "datastore", "pubsub", "redis"}

func isAdminRole(role string) bool {
	if role == "roles/owner" || role == "roles/editor" {
		return true
	}
	r := strings.ToLower(role)
	return strings.Contains(r, "admin")
}

func isWriteRole(role string) bool {
	r := strings.ToLower(role)
	for _, k := range []string{"admin", "writer", "editor", "owner", "dataowner", "create", "update", "delete", "write", "publish", "produce"} {
		if strings.Contains(r, k) {
			return true
		}
	}
	return false
}

// roleCriticality maps a role to the criticality of the access it confers on a resource.
func roleCriticality(role string) models.Criticality {
	if role == "roles/owner" {
		return models.CritCrownJewel // full control of the resource hierarchy
	}
	r := strings.ToLower(role)
	if isAdminRole(role) {
		for _, svc := range dataServices {
			if strings.Contains(r, svc) {
				return models.CritCrownJewel
			}
		}
		return models.CritHigh
	}
	if isWriteRole(role) {
		for _, svc := range dataServices {
			if strings.Contains(r, svc) {
				return models.CritHigh
			}
		}
		return models.CritMedium
	}
	return models.CritLow
}

// privilegeLevel derives an identity's overall level from the set of roles it holds.
func privilegeLevel(roles []string) string {
	admin, escal, write := false, false, false
	for _, role := range roles {
		if isAdminRole(role) {
			admin = true
		}
		if escalationRoles[role] {
			escal = true
		}
		if isWriteRole(role) {
			write = true
		}
	}
	switch {
	case admin:
		return "admin"
	case escal:
		return "privileged"
	case write:
		return "write"
	default:
		return "read"
	}
}

// broadRoleCount counts owner/editor/*admin grants — used as a wildcard-action proxy for scoring.
func broadRoleCount(roles []string) int {
	n := 0
	for _, role := range roles {
		if isAdminRole(role) {
			n++
		}
	}
	return n
}

func hasEscalation(roles []string) bool {
	for _, role := range roles {
		if escalationRoles[role] {
			return true
		}
	}
	return false
}

// member classification ----------------------------------------------------

// parseMember splits an IAM member binding ("serviceAccount:x@y", "allUsers", "principalSet://…")
// into its type prefix and identifier.
func parseMember(m string) (typ, id string) {
	if i := strings.Index(m, ":"); i > 0 {
		return m[:i], m[i+1:]
	}
	return m, "" // allUsers / allAuthenticatedUsers
}

func isPublicMember(m string) bool {
	return m == "allUsers" || m == "allAuthenticatedUsers"
}

func isServiceAccountMember(m string) bool {
	t, _ := parseMember(m)
	return t == "serviceAccount"
}

func isExternalMember(m string) bool {
	t, _ := parseMember(m)
	return t == "principalSet" || t == "principal"
}

// memberKind maps a member to a NHIID identity kind for stub creation.
func memberKind(m string) models.IdentityKind {
	switch {
	case isServiceAccountMember(m):
		return models.KindGCPServiceAcct
	case isExternalMember(m):
		return models.KindWorkloadIdentity
	default:
		return models.KindOther
	}
}
