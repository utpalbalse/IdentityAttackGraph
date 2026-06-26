package k8s

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/collectors"
	"github.com/nhiid/nhiid/internal/models"
)

// builder normalizes a parsed cluster snapshot into NHIID records. It is pure (no I/O), so the
// collector just feeds it a snapshot.
type builder struct {
	cluster    string
	accountRef string
	collectAt  time.Time

	identities map[string]*models.Identity // keyed by saKey "<ns>/<name>"
	saAnn      map[string]map[string]string
	entries    map[string][]ruleScope  // saKey -> bound (rules, scope)
	roleIdx    map[string][]policyRule // roleKey -> rules

	creds     []models.Credential
	roles     []models.Role
	trust     []models.TrustEdge
	bindings  []models.ResourceBinding
	workloads []models.Workload
	stubs     map[string]models.Identity // cloud federation targets, keyed by external id
	credSeen  map[string]bool
}

func newBuilder(cluster string) *builder {
	return &builder{
		cluster:    cluster,
		accountRef: "k8s:" + cluster,
		collectAt:  time.Now().UTC(),
		identities: map[string]*models.Identity{},
		saAnn:      map[string]map[string]string{},
		entries:    map[string][]ruleScope{},
		roleIdx:    map[string][]policyRule{},
		stubs:      map[string]models.Identity{},
		credSeen:   map[string]bool{},
	}
}

func saKeyOf(ns, name string) string {
	if ns == "" {
		ns = "default"
	}
	if name == "" {
		name = "default"
	}
	return ns + "/" + name
}

func (b *builder) extID(saKey string) string { return b.cluster + "/" + saKey }
func (b *builder) saARN(saKey string) string { return "k8s://" + b.extID(saKey) }
func (b *builder) saUUID(saKey string) uuid.UUID {
	return models.DeterministicID(string(models.KindK8sServiceAcct), b.extID(saKey))
}

// ensureSA returns the deterministic id for a ServiceAccount, creating a stub identity if absent.
func (b *builder) ensureSA(ns, name string) (string, uuid.UUID) {
	key := saKeyOf(ns, name)
	id := b.saUUID(key)
	if _, ok := b.identities[key]; !ok {
		b.identities[key] = &models.Identity{
			ID: id, Kind: models.KindK8sServiceAcct, Name: key, ARNOrEmail: b.saARN(key),
			Provider: "k8s", State: "active",
			Attributes: map[string]any{"namespace": nsOf(key), "cluster": b.cluster},
			Prov:       models.Provenance{Source: "k8s", ExternalID: b.extID(key), AccountRef: b.accountRef, CollectedAt: &b.collectAt},
		}
	}
	return key, id
}

// load ingests the snapshot into builder indices (identities, role rules, binding entries).
func (b *builder) load(snap snapshot) {
	// ServiceAccounts: create identities + capture annotations/automount/created.
	for _, sa := range snap.serviceAccounts {
		key, _ := b.ensureSA(sa.Metadata.Namespace, sa.Metadata.Name)
		ident := b.identities[key]
		ident.CreatedAtSource = parseK8sTime(sa.Metadata.CreationTimestamp)
		automount := true
		if sa.AutomountServiceAccountToken != nil {
			automount = *sa.AutomountServiceAccountToken
		}
		ident.Attributes["automount_token"] = automount
		if sa.Metadata.Annotations != nil {
			b.saAnn[key] = sa.Metadata.Annotations
		}
		// Legacy token secrets referenced directly by the SA.
		for _, s := range sa.Secrets {
			b.addToken(key, s.Name)
		}
	}

	// Index (Cluster)Role rules.
	for _, r := range snap.roles {
		b.roleIdx[roleKey(r.cluster, r.Metadata.Namespace, r.Metadata.Name)] = r.Rules
	}

	// Token secrets discovered as standalone objects.
	for _, s := range snap.secrets {
		if s.Type != "kubernetes.io/service-account-token" {
			continue
		}
		if saName := s.Metadata.Annotations["kubernetes.io/service-account.name"]; saName != "" {
			key, _ := b.ensureSA(s.Metadata.Namespace, saName)
			b.addToken(key, s.Metadata.Name)
		}
	}

	// Bindings: attach (rules, scope) to each ServiceAccount subject.
	for _, rb := range snap.roleBindings {
		rules, ok := b.resolveRole(rb.RoleRef)
		if !ok {
			continue
		}
		scope := "cluster"
		if !rb.cluster {
			scope = "ns/" + rb.Metadata.Namespace
		}
		for _, sub := range rb.Subjects {
			if sub.Kind != "ServiceAccount" {
				continue // only non-human SA subjects are inventoried here
			}
			key, _ := b.ensureSA(sub.Namespace, sub.Name)
			b.entries[key] = append(b.entries[key], ruleScope{
				rules: rules, cluster: rb.cluster, scopeURN: scope, roleName: rb.RoleRef.Name,
			})
		}
	}

	// Pods: workloads that run as a ServiceAccount.
	for _, p := range snap.pods {
		key, saID := b.ensureSA(p.Metadata.Namespace, p.Spec.ServiceAccountName)
		wlExt := b.cluster + "/" + p.Metadata.Namespace + "/" + p.Metadata.Name
		sid := saID
		b.workloads = append(b.workloads, models.Workload{
			ID:          models.DeterministicID("workload", wlExt),
			Kind:        "k8s_pod",
			ExternalID:  wlExt,
			AccountRef:  b.accountRef,
			Name:        p.Metadata.Namespace + "/" + p.Metadata.Name,
			Environment: p.Metadata.Namespace,
			IdentityID:  &sid,
			Attributes:  map[string]any{"service_account": key, "uid": p.Metadata.UID},
			Source:      "k8s",
		})
	}
}

// resolveRole returns the rules for a roleRef, falling back to well-known built-ins (cluster-admin,
// admin, edit, view) so bindings to unexported cluster roles still connect.
func (b *builder) resolveRole(ref roleRef) ([]policyRule, bool) {
	cluster := ref.Kind == "ClusterRole"
	if rules, ok := b.roleIdx[roleKey(cluster, "", ref.Name)]; ok && cluster {
		return rules, true
	}
	if cluster {
		if rules, ok := b.roleIdx["clusterrole/"+ref.Name]; ok {
			return rules, true
		}
		return builtinRules(ref.Name)
	}
	// Namespaced Role: namespace is not in the roleRef, so match by name suffix across namespaces.
	for k, rules := range b.roleIdx {
		if !isCluster(k) && nameOfRoleKey(k) == ref.Name {
			return rules, true
		}
	}
	return builtinRules(ref.Name)
}

// finalize builds the per-SA permission set, federation edges, and returns the collector result.
func (b *builder) finalize(cursor map[string]any) collectors.Result {
	for key, ident := range b.identities {
		saID := ident.ID

		// Effective RBAC -> one permission-set role owned by the SA (mirrors the AWS model so the
		// privilege risk factor, over_privileged_sa, and has_permissions graph edge all work).
		a := analyzeEntries(b.cluster, b.entries[key])
		arn := b.saARN(key)
		roleID := models.DeterministicID("role", arn)
		b.roles = append(b.roles, models.Role{
			ID: roleID, Provider: "k8s", ExternalID: arn, AccountRef: b.accountRef,
			Name:                key + ":rbac",
			PolicyDocument:      map[string]any{"has_priv_escalation": a.HasEscalation, "bound_roles": a.RoleNames, "kind": "k8s_rbac"},
			PrivilegeLevel:      a.PrivilegeLevel,
			PermissionCount:     a.PermissionCount,
			WildcardActionCount: a.WildcardVerbs,
			OwnerIdentityID:     &saID,
			Source:              "k8s",
		})
		for _, rb := range a.Bindings {
			rid := roleID
			b.bindings = append(b.bindings, models.ResourceBinding{
				RoleID: &rid, ResourceURN: rb.URN, ResourceKind: rb.Kind,
				ResourceCriticality: rb.Crit, Actions: rb.Actions, Effect: "allow",
				AccountRef: b.accountRef, Source: "k8s",
			})
		}

		// Cloud federation edges (IRSA / Workload Identity): controlling this pod identity yields the
		// linked cloud principal's privileges. Deterministic ids match the AWS/GCP collectors, so the
		// edge connects pod -> cloud role/SA -> crown jewels in a multi-collector run.
		ann := b.saAnn[key]
		if arnAWS := ann[annIRSA]; arnAWS != "" {
			dst := models.DeterministicID(string(models.KindAWSIAMRole), arnAWS)
			b.ensureCloudStub(dst, models.KindAWSIAMRole, "aws", arnAWS, nameFromARN(arnAWS), "aws:"+awsAcctFromARN(arnAWS), "k8s_irsa")
			b.trust = append(b.trust, models.TrustEdge{
				SrcIdentityID: &saID, DstIdentityID: &dst, EdgeType: "federated_from",
				Condition:  map[string]any{"provider": "aws", "mechanism": "irsa", "role_arn": arnAWS},
				AccountRef: b.accountRef, Source: "k8s",
			})
			ident.Attributes["aws_role_arn"] = arnAWS
		}
		if gsa := ann[annWIF]; gsa != "" {
			dst := models.DeterministicID(string(models.KindGCPServiceAcct), gsa)
			b.ensureCloudStub(dst, models.KindGCPServiceAcct, "gcp", gsa, gsa, "gcp:"+gcpProjectFromEmail(gsa), "k8s_workload_identity")
			b.trust = append(b.trust, models.TrustEdge{
				SrcIdentityID: &saID, DstIdentityID: &dst, EdgeType: "federated_from",
				Condition:  map[string]any{"provider": "gcp", "mechanism": "workload_identity", "gcp_service_account": gsa},
				AccountRef: b.accountRef, Source: "k8s",
			})
			ident.Attributes["gcp_service_account"] = gsa
		}
	}

	idents := make([]models.Identity, 0, len(b.identities)+len(b.stubs))
	for _, v := range b.identities {
		idents = append(idents, *v)
	}
	for _, v := range b.stubs {
		idents = append(idents, v)
	}
	return collectors.Result{
		Identities:       idents,
		Credentials:      b.creds,
		Roles:            b.roles,
		TrustEdges:       b.trust,
		ResourceBindings: b.bindings,
		Workloads:        b.workloads,
		NewCursor:        cursor,
	}
}

// ensureCloudStub records a thin identity for a cloud federation target (AWS role / GCP SA) so the
// trust edge's FK holds even if that cloud collector hasn't run yet. The deterministic id and
// (provider, external_id) key mean a later AWS/GCP collection reconciles onto the same row.
func (b *builder) ensureCloudStub(id uuid.UUID, kind models.IdentityKind, provider, extID, name, accountRef, via string) {
	if _, ok := b.stubs[extID]; ok {
		return
	}
	b.stubs[extID] = models.Identity{
		ID: id, Kind: kind, Name: name, ARNOrEmail: extID, Provider: provider, State: "active",
		Attributes: map[string]any{"external_principal": true, "discovered_via": via},
		Prov:       models.Provenance{Source: "k8s", ExternalID: extID, AccountRef: accountRef, CollectedAt: &b.collectAt},
	}
}

func (b *builder) addToken(saKey, secretName string) {
	if secretName == "" {
		return
	}
	dedupe := saKey + "|" + secretName
	if b.credSeen[dedupe] {
		return
	}
	b.credSeen[dedupe] = true
	_, saID := b.ensureSA(nsOf(saKey), nameOf(saKey))
	b.creds = append(b.creds, models.Credential{
		IdentityID: saID, CredType: "k8s_sa_token", ExternalID: secretName, Status: "active",
		AccountRef: b.accountRef, Source: "k8s",
	})
}

// ---- small key helpers ----

func roleKey(cluster bool, ns, name string) string {
	if cluster {
		return "clusterrole/" + name
	}
	return "ns/" + ns + "/" + name
}
func isCluster(k string) bool { return len(k) >= 12 && k[:12] == "clusterrole/" }
func nameOfRoleKey(k string) string {
	// "ns/<ns>/<name>"
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == '/' {
			return k[i+1:]
		}
	}
	return k
}
func nsOf(saKey string) string {
	for i := 0; i < len(saKey); i++ {
		if saKey[i] == '/' {
			return saKey[:i]
		}
	}
	return "default"
}
func nameOf(saKey string) string {
	for i := 0; i < len(saKey); i++ {
		if saKey[i] == '/' {
			return saKey[i+1:]
		}
	}
	return saKey
}

// nameFromARN returns the trailing segment of an ARN (the role name).
func nameFromARN(arn string) string {
	if i := strings.LastIndexAny(arn, "/:"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

// awsAcctFromARN extracts the account id from arn:aws:iam::<acct>:role/<name>.
func awsAcctFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return "unknown"
}

// gcpProjectFromEmail extracts the project from name@PROJECT.iam.gserviceaccount.com.
func gcpProjectFromEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at < 0 {
		return "unknown"
	}
	host := email[at+1:]
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host[:i]
	}
	return "unknown"
}
