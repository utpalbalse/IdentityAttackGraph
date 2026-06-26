package k8s

import (
	"testing"

	"github.com/nhiid/nhiid/internal/models"
)

const exportJSON = `{
  "kind": "List",
  "apiVersion": "v1",
  "items": [
    {"kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"prod",
      "annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/prod-deployer"}},
      "secrets":[{"name":"deployer-token-abcde"}]},
    {"kind":"ServiceAccount","metadata":{"name":"reader","namespace":"prod"}},
    {"kind":"ServiceAccount","metadata":{"name":"gke-sync","namespace":"prod",
      "annotations":{"iam.gke.io/gcp-service-account":"data-processor@project.iam.gserviceaccount.com"}}},
    {"kind":"ClusterRole","metadata":{"name":"secret-reader"},
      "rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list"]}]},
    {"kind":"Role","metadata":{"name":"cfg-reader","namespace":"prod"},
      "rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}]},
    {"kind":"ClusterRoleBinding","metadata":{"name":"deployer-admin"},
      "roleRef":{"kind":"ClusterRole","name":"cluster-admin"},
      "subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"prod"}]},
    {"kind":"ClusterRoleBinding","metadata":{"name":"gke-secrets"},
      "roleRef":{"kind":"ClusterRole","name":"secret-reader"},
      "subjects":[{"kind":"ServiceAccount","name":"gke-sync","namespace":"prod"}]},
    {"kind":"RoleBinding","metadata":{"name":"reader-cfg","namespace":"prod"},
      "roleRef":{"kind":"Role","name":"cfg-reader"},
      "subjects":[{"kind":"ServiceAccount","name":"reader","namespace":"prod"}]},
    {"kind":"Pod","metadata":{"name":"web-123","namespace":"prod"},
      "spec":{"serviceAccountName":"deployer"}}
  ]
}`

func TestCollectEndToEnd(t *testing.T) {
	snap, err := parseExport([]byte(exportJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(snap.serviceAccounts) != 3 {
		t.Fatalf("service accounts = %d, want 3", len(snap.serviceAccounts))
	}

	b := newBuilder("staging")
	b.load(snap)
	r := b.finalize(nil)

	// Index results.
	roleByOwner := map[string]models.Role{}
	identByName := map[string]models.Identity{}
	for _, id := range r.Identities {
		identByName[id.Name] = id
	}
	for _, role := range r.Roles {
		if role.OwnerIdentityID != nil {
			roleByOwner[role.OwnerIdentityID.String()] = role
		}
	}

	// deployer: cluster-admin -> admin privilege + crown-jewel binding.
	deployer, ok := identByName["prod/deployer"]
	if !ok {
		t.Fatal("missing prod/deployer identity")
	}
	if deployer.Kind != models.KindK8sServiceAcct {
		t.Errorf("deployer kind = %s", deployer.Kind)
	}
	dr := roleByOwner[deployer.ID.String()]
	if dr.PrivilegeLevel != "admin" {
		t.Errorf("deployer privilege = %q, want admin", dr.PrivilegeLevel)
	}

	// crown-jewel binding for cluster-admin.
	var crown bool
	for _, bind := range r.ResourceBindings {
		if bind.RoleID != nil && *bind.RoleID == dr.ID && bind.ResourceCriticality == models.CritCrownJewel {
			crown = true
		}
	}
	if !crown {
		t.Error("deployer should have a crown-jewel resource binding")
	}

	// IRSA federation edge deployer -> AWS role (deterministic target).
	wantAWS := models.DeterministicID(string(models.KindAWSIAMRole), "arn:aws:iam::123456789012:role/prod-deployer")
	var sawIRSA, sawWIF bool
	for _, e := range r.TrustEdges {
		if e.EdgeType != "federated_from" || e.SrcIdentityID == nil || e.DstIdentityID == nil {
			continue
		}
		if *e.SrcIdentityID == deployer.ID && *e.DstIdentityID == wantAWS {
			sawIRSA = true
		}
	}
	wantGCP := models.DeterministicID(string(models.KindGCPServiceAcct), "data-processor@project.iam.gserviceaccount.com")
	gke := identByName["prod/gke-sync"]
	for _, e := range r.TrustEdges {
		if e.SrcIdentityID != nil && *e.SrcIdentityID == gke.ID && e.DstIdentityID != nil && *e.DstIdentityID == wantGCP {
			sawWIF = true
		}
	}
	if !sawIRSA {
		t.Error("missing IRSA federation edge deployer -> AWS role")
	}
	if !sawWIF {
		t.Error("missing Workload Identity federation edge gke-sync -> GCP SA")
	}

	// gke-sync: cluster secret reader -> privileged + crown-jewel secrets binding.
	gr := roleByOwner[gke.ID.String()]
	if gr.PrivilegeLevel != "privileged" {
		t.Errorf("gke-sync privilege = %q, want privileged", gr.PrivilegeLevel)
	}

	// reader: only configmap get -> read.
	reader := identByName["prod/reader"]
	rr := roleByOwner[reader.ID.String()]
	if rr.PrivilegeLevel != "read" {
		t.Errorf("reader privilege = %q, want read", rr.PrivilegeLevel)
	}

	// token credential for deployer.
	var tok bool
	for _, c := range r.Credentials {
		if c.IdentityID == deployer.ID && c.CredType == "k8s_sa_token" {
			tok = true
		}
	}
	if !tok {
		t.Error("deployer should have a k8s_sa_token credential")
	}

	// pod workload runs as deployer.
	var wl bool
	for _, w := range r.Workloads {
		if w.Kind == "k8s_pod" && w.IdentityID != nil && *w.IdentityID == deployer.ID {
			wl = true
		}
	}
	if !wl {
		t.Error("pod workload should reference deployer identity")
	}
}

func TestAnalyzeEntriesEscalation(t *testing.T) {
	entries := []ruleScope{{
		cluster: true,
		rules: []policyRule{{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterrolebindings"},
			Verbs:     []string{"create"},
		}},
	}}
	a := analyzeEntries("c", entries)
	if !a.HasEscalation {
		t.Error("create on clusterrolebindings should be flagged as escalation")
	}
	if a.PrivilegeLevel != "privileged" {
		t.Errorf("privilege = %q, want privileged", a.PrivilegeLevel)
	}
}
