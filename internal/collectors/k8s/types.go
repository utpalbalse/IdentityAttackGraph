// Package k8s implements a Kubernetes collector. It ingests a cluster export produced by
//
//	kubectl get serviceaccounts,roles,clusterroles,rolebindings,clusterrolebindings,pods -A -o json
//
// and normalizes ServiceAccounts (non-human identities), their effective RBAC (privilege analysis),
// pod workloads, legacy token credentials, and — crucially — cloud federation edges (EKS IRSA /
// GKE Workload Identity) that link a pod's identity to cloud privileges. Reading an export keeps
// the collector dependency-free and unit-testable offline; the same normalization powers a live
// client-go source (see docs/K8S_COLLECTOR.md).
package k8s

import "time"

// metadata is the subset of ObjectMeta we read.
type metadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Annotations       map[string]string `json:"annotations"`
	Labels            map[string]string `json:"labels"`
	UID               string            `json:"uid"`
	CreationTimestamp string            `json:"creationTimestamp"`
}

type serviceAccount struct {
	Metadata                     metadata `json:"metadata"`
	AutomountServiceAccountToken *bool    `json:"automountServiceAccountToken"`
	Secrets                      []struct {
		Name string `json:"name"`
	} `json:"secrets"`
}

// policyRule mirrors rbac.authorization.k8s.io/v1 PolicyRule.
type policyRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

// role holds a Role or ClusterRole; cluster is set during parse from the object kind.
type role struct {
	Metadata metadata     `json:"metadata"`
	Rules    []policyRule `json:"rules"`
	cluster  bool
}

type roleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// roleBinding holds a RoleBinding or ClusterRoleBinding; cluster is set during parse.
type roleBinding struct {
	Metadata metadata  `json:"metadata"`
	RoleRef  roleRef   `json:"roleRef"`
	Subjects []subject `json:"subjects"`
	cluster  bool
}

type pod struct {
	Metadata metadata `json:"metadata"`
	Spec     struct {
		ServiceAccountName string `json:"serviceAccountName"`
	} `json:"spec"`
}

type secret struct {
	Metadata metadata `json:"metadata"`
	Type     string   `json:"type"`
}

// snapshot is the parsed cluster state the builder normalizes.
type snapshot struct {
	serviceAccounts []serviceAccount
	roles           []role
	roleBindings    []roleBinding
	pods            []pod
	secrets         []secret
}

// federation annotation keys that link a K8s ServiceAccount to a cloud principal.
const (
	annIRSA = "eks.amazonaws.com/role-arn"     // EKS IRSA -> AWS IAM role ARN
	annWIF  = "iam.gke.io/gcp-service-account" // GKE Workload Identity -> GCP SA email
)

func parseK8sTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		u := t.UTC()
		return &u
	}
	return nil
}
