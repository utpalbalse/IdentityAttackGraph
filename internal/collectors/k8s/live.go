package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// liveSnapshot lists ServiceAccounts, RBAC, pods, and token secrets from a live cluster into the
// same `snapshot` the export parser produces — so the normalization (builder) is byte-for-byte
// identical between the export and live sources. Takes a kubernetes.Interface so it can be driven by
// the fake clientset in tests.
func liveSnapshot(ctx context.Context, cs kubernetes.Interface) (snapshot, error) {
	var snap snapshot
	all := metav1.ListOptions{}

	sas, err := cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, all)
	if err != nil {
		return snap, fmt.Errorf("list serviceaccounts: %w", err)
	}
	for i := range sas.Items {
		snap.serviceAccounts = append(snap.serviceAccounts, convSA(&sas.Items[i]))
	}

	roles, err := cs.RbacV1().Roles(metav1.NamespaceAll).List(ctx, all)
	if err != nil {
		return snap, fmt.Errorf("list roles: %w", err)
	}
	for i := range roles.Items {
		snap.roles = append(snap.roles, convRole(roles.Items[i].ObjectMeta, roles.Items[i].Rules, false))
	}
	croles, err := cs.RbacV1().ClusterRoles().List(ctx, all)
	if err != nil {
		return snap, fmt.Errorf("list clusterroles: %w", err)
	}
	for i := range croles.Items {
		snap.roles = append(snap.roles, convRole(croles.Items[i].ObjectMeta, croles.Items[i].Rules, true))
	}

	rbs, err := cs.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, all)
	if err != nil {
		return snap, fmt.Errorf("list rolebindings: %w", err)
	}
	for i := range rbs.Items {
		snap.roleBindings = append(snap.roleBindings, convBinding(rbs.Items[i].ObjectMeta, rbs.Items[i].RoleRef, rbs.Items[i].Subjects, false))
	}
	crbs, err := cs.RbacV1().ClusterRoleBindings().List(ctx, all)
	if err != nil {
		return snap, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	for i := range crbs.Items {
		snap.roleBindings = append(snap.roleBindings, convBinding(crbs.Items[i].ObjectMeta, crbs.Items[i].RoleRef, crbs.Items[i].Subjects, true))
	}

	pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, all)
	if err != nil {
		return snap, fmt.Errorf("list pods: %w", err)
	}
	for i := range pods.Items {
		snap.pods = append(snap.pods, convPod(&pods.Items[i]))
	}

	secs, err := cs.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, all)
	if err != nil {
		return snap, fmt.Errorf("list secrets: %w", err)
	}
	for i := range secs.Items {
		if secs.Items[i].Type == corev1.SecretTypeServiceAccountToken {
			snap.secrets = append(snap.secrets, secret{Metadata: convMeta(secs.Items[i].ObjectMeta), Type: string(secs.Items[i].Type)})
		}
	}
	return snap, nil
}

// ----- client-go object -> internal snapshot struct conversions -----

func convMeta(m metav1.ObjectMeta) metadata {
	ts := ""
	if !m.CreationTimestamp.IsZero() {
		ts = m.CreationTimestamp.UTC().Format(time.RFC3339)
	}
	return metadata{
		Name: m.Name, Namespace: m.Namespace, Annotations: m.Annotations,
		Labels: m.Labels, UID: string(m.UID), CreationTimestamp: ts,
	}
}

func convSA(sa *corev1.ServiceAccount) serviceAccount {
	out := serviceAccount{Metadata: convMeta(sa.ObjectMeta), AutomountServiceAccountToken: sa.AutomountServiceAccountToken}
	for _, s := range sa.Secrets {
		out.Secrets = append(out.Secrets, saSecretRef{Name: s.Name})
	}
	return out
}

func convRole(m metav1.ObjectMeta, rules []rbacv1.PolicyRule, cluster bool) role {
	r := role{Metadata: convMeta(m), cluster: cluster}
	for _, pr := range rules {
		r.Rules = append(r.Rules, policyRule{
			APIGroups: pr.APIGroups, Resources: pr.Resources, Verbs: pr.Verbs,
			ResourceNames: pr.ResourceNames, NonResourceURLs: pr.NonResourceURLs,
		})
	}
	return r
}

func convBinding(m metav1.ObjectMeta, ref rbacv1.RoleRef, subs []rbacv1.Subject, cluster bool) roleBinding {
	rb := roleBinding{Metadata: convMeta(m), cluster: cluster, RoleRef: roleRef{Kind: ref.Kind, Name: ref.Name}}
	for _, s := range subs {
		rb.Subjects = append(rb.Subjects, subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace})
	}
	return rb
}

func convPod(p *corev1.Pod) pod {
	out := pod{Metadata: convMeta(p.ObjectMeta)}
	out.Spec.ServiceAccountName = p.Spec.ServiceAccountName
	return out
}

// buildClientset resolves cluster credentials: an explicit kubeconfig path, else in-cluster config
// (when running as a pod), else the default kubeconfig (~/.kube/config).
func buildClientset(kubeconfig string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	switch {
	case kubeconfig != "":
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	default:
		if cfg, err = rest.InClusterConfig(); err != nil {
			rules := clientcmd.NewDefaultClientConfigLoadingRules()
			cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("k8s client config: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}
