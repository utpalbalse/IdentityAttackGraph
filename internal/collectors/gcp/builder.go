package gcp

import (
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/collectors"
	"github.com/nhiid/nhiid/internal/models"
)

// builder accumulates normalized records during a GCP collection pass. It is pure (no SDK types),
// so the collection logic in iam.go just feeds it parsed values.
type builder struct {
	projectID  string
	accountRef string
	collectAt  time.Time

	identities map[string]*models.Identity // keyed by external id (email / principal)
	creds      []models.Credential
	trust      []models.TrustEdge
	grants     map[string][]grant // service-account email -> resource grants
	usage      []models.UsageEvent
}

type grant struct {
	role        string
	resourceURN string
	crit        models.Criticality
}

func newBuilder(projectID string) *builder {
	return &builder{
		projectID:  projectID,
		accountRef: "gcp:" + projectID,
		collectAt:  time.Now().UTC(),
		identities: map[string]*models.Identity{},
		grants:     map[string][]grant{},
	}
}

func (b *builder) ensureIdentity(extID string, kind models.IdentityKind, full *models.Identity) uuid.UUID {
	id := models.DeterministicID(string(kind), extID)
	if full != nil {
		full.ID = id
		b.identities[extID] = full
		return id
	}
	if _, ok := b.identities[extID]; !ok {
		b.identities[extID] = &models.Identity{
			ID: id, Kind: kind, Name: extID, ARNOrEmail: extID, Provider: "gcp", State: "active",
			Attributes: map[string]any{},
			Prov:       models.Provenance{Source: "gcp", ExternalID: extID, AccountRef: b.accountRef, CollectedAt: &b.collectAt},
		}
	}
	return id
}

// addServiceAccount records a GCP service account as an identity.
func (b *builder) addServiceAccount(email, displayName string, disabled bool, attrs map[string]any) uuid.UUID {
	state := "active"
	if disabled {
		state = "disabled"
	}
	name := displayName
	if name == "" {
		name = email
	}
	return b.ensureIdentity(email, models.KindGCPServiceAcct, &models.Identity{
		Kind: models.KindGCPServiceAcct, Name: name, ARNOrEmail: email, Provider: "gcp", State: state,
		Attributes: attrs,
		Prov:       models.Provenance{Source: "gcp", ExternalID: email, AccountRef: b.accountRef, CollectedAt: &b.collectAt},
	})
}

// addKey records a USER-managed service-account key (the long-lived credential risk). Google-managed
// keys are skipped — they are rotated by Google and not exfiltratable.
func (b *builder) addKey(saEmail, keyName, keyType string, validAfter time.Time, disabled bool) {
	if keyType != "USER_MANAGED" {
		return
	}
	identID := b.ensureIdentity(saEmail, models.KindGCPServiceAcct, nil)
	status := "active"
	if disabled {
		status = "inactive"
	}
	var created *time.Time
	if !validAfter.IsZero() {
		created = &validAfter
	}
	b.creds = append(b.creds, models.Credential{
		IdentityID: identID, CredType: "gcp_sa_key", ExternalID: shortKeyID(keyName), Status: status,
		CreatedAtSource: created, AccountRef: b.accountRef, Source: "gcp",
		// user-managed keys do not expire by default -> modelled as a static key (ExpiresAt nil)
	})
}

// addImpersonation records that `member` can impersonate / federate into service account `saEmail`.
func (b *builder) addImpersonation(saEmail, member, role string, conditioned bool) {
	dst := b.ensureIdentity(saEmail, models.KindGCPServiceAcct, nil)
	src := b.ensureIdentity(memberID(member), memberKind(member), nil)

	cond := map[string]any{}
	if conditioned {
		cond["guards"] = []string{"iam_condition"}
	}
	if isPublicMember(member) {
		cond["wildcard_principal"] = true
	}
	edgeType := "can_impersonate"
	if federationRoles[role] {
		edgeType = "federated_from"
	}
	b.trust = append(b.trust, models.TrustEdge{
		SrcIdentityID: &src, DstIdentityID: &dst, EdgeType: edgeType,
		Condition: cond, Observed: false, AccountRef: b.accountRef, Source: "gcp",
	})
}

// noteGrant accumulates a (service account, role, resource) grant for later permission-set build.
func (b *builder) noteGrant(saEmail, role, resourceURN string, crit models.Criticality) {
	b.grants[saEmail] = append(b.grants[saEmail], grant{role: role, resourceURN: resourceURN, crit: crit})
}

// result finalizes accumulated grants into permission sets + bindings and returns the collector
// result.
func (b *builder) result(cursor map[string]any) collectors.Result {
	var roles []models.Role
	var bindings []models.ResourceBinding

	for email, gs := range b.grants {
		identID := b.ensureIdentity(email, models.KindGCPServiceAcct, nil)
		roleID := models.DeterministicID("role", email)
		var roleNames []string
		for _, g := range gs {
			roleNames = append(roleNames, g.role)
		}
		roles = append(roles, models.Role{
			ID: roleID, Provider: "gcp", ExternalID: email, AccountRef: b.accountRef,
			Name:                shortEmail(email),
			PolicyDocument:      map[string]any{"has_priv_escalation": hasEscalation(roleNames), "roles": roleNames},
			PrivilegeLevel:      privilegeLevel(roleNames),
			PermissionCount:     len(roleNames),
			WildcardActionCount: broadRoleCount(roleNames),
			OwnerIdentityID:     &identID,
			Source:              "gcp",
		})
		for _, g := range gs {
			rid := roleID
			bindings = append(bindings, models.ResourceBinding{
				RoleID: &rid, ResourceURN: g.resourceURN, ResourceKind: "gcp_project",
				ResourceCriticality: g.crit, Actions: []string{g.role}, Effect: "allow",
				AccountRef: b.accountRef, Source: "gcp",
			})
		}
	}

	idents := make([]models.Identity, 0, len(b.identities))
	for _, v := range b.identities {
		idents = append(idents, *v)
	}
	return collectors.Result{
		Identities:       idents,
		Credentials:      b.creds,
		Roles:            roles,
		TrustEdges:       b.trust,
		ResourceBindings: bindings,
		UsageEvents:      b.usage,
		NewCursor:        cursor,
	}
}
