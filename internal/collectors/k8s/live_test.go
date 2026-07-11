package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/nhiid/nhiid/internal/models"
)

// TestLiveSnapshotAndBuild drives the live source with the official fake clientset and asserts it
// yields the same normalized records as the export path (admin RBAC, IRSA federation, workload,
// token credential) — proving the live source feeds the identical builder.
func TestLiveSnapshotAndBuild(t *testing.T) {
	objs := []runtime.Object{
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "deployer", Namespace: "prod",
				Annotations: map[string]string{annIRSA: "arn:aws:iam::123456789012:role/prod-deployer"},
			},
			Secrets: []corev1.ObjectReference{{Name: "deployer-token-abc"}},
		},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "prod"}},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "deployer-admin"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deployer", Namespace: "prod"}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "prod"},
			Spec:       corev1.PodSpec{ServiceAccountName: "deployer"},
		},
	}
	cs := fake.NewSimpleClientset(objs...)

	snap, err := liveSnapshot(context.Background(), cs)
	if err != nil {
		t.Fatalf("liveSnapshot: %v", err)
	}
	b := newBuilder("live-cluster")
	b.load(snap)
	res := b.finalize(nil)

	roleByOwner := map[string]models.Role{}
	identByName := map[string]models.Identity{}
	for _, id := range res.Identities {
		identByName[id.Name] = id
	}
	for _, r := range res.Roles {
		if r.OwnerIdentityID != nil {
			roleByOwner[r.OwnerIdentityID.String()] = r
		}
	}

	dep, ok := identByName["prod/deployer"]
	if !ok {
		t.Fatal("missing prod/deployer identity from live source")
	}
	if got := roleByOwner[dep.ID.String()].PrivilegeLevel; got != "admin" {
		t.Errorf("deployer privilege = %q, want admin", got)
	}

	wantAWS := models.DeterministicID(string(models.KindAWSIAMRole), "arn:aws:iam::123456789012:role/prod-deployer")
	sawIRSA := false
	for _, e := range res.TrustEdges {
		if e.EdgeType == "federated_from" && e.SrcIdentityID != nil && *e.SrcIdentityID == dep.ID &&
			e.DstIdentityID != nil && *e.DstIdentityID == wantAWS {
			sawIRSA = true
		}
	}
	if !sawIRSA {
		t.Error("missing IRSA federation edge from live source")
	}

	tok := false
	for _, c := range res.Credentials {
		if c.IdentityID == dep.ID && c.CredType == "k8s_sa_token" {
			tok = true
		}
	}
	if !tok {
		t.Error("missing k8s_sa_token credential from live source")
	}

	wl := false
	for _, w := range res.Workloads {
		if w.Kind == "k8s_pod" && w.IdentityID != nil && *w.IdentityID == dep.ID {
			wl = true
		}
	}
	if !wl {
		t.Error("missing pod workload from live source")
	}
}
