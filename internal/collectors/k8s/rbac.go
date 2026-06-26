package k8s

import (
	"fmt"
	"strings"

	"github.com/nhiid/nhiid/internal/models"
)

// ruleScope is a set of RBAC rules together with the scope at which they are granted to a subject.
// Scope is determined by the BINDING, not the role: a ClusterRole bound via a (namespaced)
// RoleBinding only grants within that namespace.
type ruleScope struct {
	rules    []policyRule
	cluster  bool   // true => cluster-wide (ClusterRoleBinding)
	scopeURN string // "cluster" or "ns/<namespace>"
	roleName string
}

// rbacBinding is a synthesized resource binding for a sensitive capability, used for blast-radius.
type rbacBinding struct {
	URN     string
	Kind    string
	Crit    models.Criticality
	Actions []string
}

// rbacAnalysis is the normalized privilege picture for a ServiceAccount's effective RBAC.
type rbacAnalysis struct {
	PrivilegeLevel  string // read | write | privileged | admin
	WildcardVerbs   int
	HasEscalation   bool
	PermissionCount int
	Bindings        []rbacBinding
	RoleNames       []string
}

var escalationVerbs = map[string]bool{"bind": true, "escalate": true, "impersonate": true}
var rbacResources = map[string]bool{"roles": true, "clusterroles": true, "rolebindings": true, "clusterrolebindings": true}
var writeVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true}
var readVerbs = map[string]bool{"get": true, "list": true, "watch": true}

// analyzeEntries computes the effective privilege level and sensitive resource bindings for a
// ServiceAccount given every (rules, scope) it is bound to.
func analyzeEntries(clusterName string, entries []ruleScope) rbacAnalysis {
	a := rbacAnalysis{PrivilegeLevel: "read"}
	seenURN := map[string]bool{}
	addBinding := func(b rbacBinding) {
		if seenURN[b.URN] {
			return
		}
		seenURN[b.URN] = true
		a.Bindings = append(a.Bindings, b)
	}

	var hasWrite, hasRead, clusterAdmin, nsAdmin, secretsCluster, secretsNS, podExec bool
	roleSet := map[string]bool{}

	for _, e := range entries {
		if e.roleName != "" && !roleSet[e.roleName] {
			roleSet[e.roleName] = true
			a.RoleNames = append(a.RoleNames, e.roleName)
		}
		for _, r := range e.rules {
			a.PermissionCount++
			gWild := contains(r.APIGroups, "*")
			rWild := contains(r.Resources, "*")
			vWild := contains(r.Verbs, "*")
			if vWild {
				a.WildcardVerbs++
			}

			// cluster-admin equivalent: all groups, resources, and verbs wildcarded.
			if gWild && rWild && vWild {
				if e.cluster {
					clusterAdmin = true
				} else {
					nsAdmin = true
				}
			}

			// secret read = credential-theft / escalation primitive.
			if (rWild || contains(r.Resources, "secrets")) && (vWild || containsAny(r.Verbs, readVerbs)) {
				if e.cluster {
					secretsCluster = true
				} else {
					secretsNS = true
				}
				a.HasEscalation = true
			}

			// RBAC self-escalation: bind/escalate/impersonate, or write on rbac objects.
			if containsAnyMap(r.Verbs, escalationVerbs) {
				a.HasEscalation = true
			}
			if (gWild || contains(r.APIGroups, "rbac.authorization.k8s.io")) &&
				(rWild || containsAnyMap(r.Resources, rbacResources)) &&
				(vWild || containsAnyMap(r.Verbs, writeVerbs)) {
				a.HasEscalation = true
			}

			// pod exec/attach = code execution in a running workload.
			if contains(r.Resources, "pods/exec") || contains(r.Resources, "pods/attach") {
				podExec = true
			}

			if vWild || containsAnyMap(r.Verbs, writeVerbs) {
				hasWrite = true
			}
			if containsAnyMap(r.Verbs, readVerbs) {
				hasRead = true
			}
		}
	}

	// Synthesized resource bindings (drive blast-radius/attack-path to crown jewels).
	if clusterAdmin {
		addBinding(rbacBinding{URN: fmt.Sprintf("k8s:%s:*", clusterName), Kind: "k8s_cluster", Crit: models.CritCrownJewel, Actions: []string{"*"}})
	}
	if secretsCluster {
		addBinding(rbacBinding{URN: fmt.Sprintf("k8s:%s:cluster:secrets", clusterName), Kind: "k8s_secret", Crit: models.CritCrownJewel, Actions: []string{"get", "list"}})
	} else if secretsNS {
		addBinding(rbacBinding{URN: fmt.Sprintf("k8s:%s:namespace:secrets", clusterName), Kind: "k8s_secret", Crit: models.CritHigh, Actions: []string{"get", "list"}})
	}
	if podExec {
		addBinding(rbacBinding{URN: fmt.Sprintf("k8s:%s:pods:exec", clusterName), Kind: "k8s_pod", Crit: models.CritHigh, Actions: []string{"create"}})
	}

	switch {
	case clusterAdmin:
		a.PrivilegeLevel = "admin"
	case a.HasEscalation || podExec || nsAdmin:
		a.PrivilegeLevel = "privileged"
	case hasWrite:
		a.PrivilegeLevel = "write"
	case hasRead:
		a.PrivilegeLevel = "read"
	}
	return a
}

// privilegeFromName infers a privilege level for a referenced-but-unexported (Cluster)Role from
// well-known built-in names, so bindings to e.g. cluster-admin still connect in the graph.
func builtinRules(name string) ([]policyRule, bool) {
	switch strings.ToLower(name) {
	case "cluster-admin":
		return []policyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}, true
	case "admin", "edit":
		return []policyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"create", "update", "patch", "delete", "get", "list", "watch"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}}}, true
	case "view":
		return []policyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch"}}}, true
	}
	return nil, false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsAny(s []string, set map[string]bool) bool {
	for _, x := range s {
		if set[strings.ToLower(x)] {
			return true
		}
	}
	return false
}

func containsAnyMap(s []string, set map[string]bool) bool { return containsAny(s, set) }
