package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/collectors"
	"github.com/nhiid/nhiid/internal/models"
)

// builder accumulates normalized records during a collection pass, deduping identities and roles
// by external_id so stub (cross-account principal) and full records reconcile to one row.
type builder struct {
	accountRef string
	collectAt  time.Time
	crit       *critResolver // resource criticality declared via tags; nil elevates nothing

	identities map[string]*models.Identity
	roles      []models.Role
	creds      []models.Credential
	trust      []models.TrustEdge
	bindings   []models.ResourceBinding
}

func newBuilder(accountRef string) *builder {
	return &builder{
		accountRef: accountRef,
		collectAt:  time.Now().UTC(),
		identities: map[string]*models.Identity{},
	}
}

// ensureIdentity returns the deterministic id for an ARN, creating a (possibly stub) identity if
// one is not already present. A later, richer record for the same ARN overwrites the stub.
func (b *builder) ensureIdentity(arn string, kind models.IdentityKind, full *models.Identity) uuid.UUID {
	id := models.DeterministicID(string(kind), arn)
	if full != nil {
		full.ID = id
		b.identities[arn] = full
		return id
	}
	if _, ok := b.identities[arn]; !ok {
		b.identities[arn] = &models.Identity{
			ID:         id,
			Kind:       kind,
			Name:       nameFromARN(arn),
			ARNOrEmail: arn,
			Provider:   "aws",
			State:      "active",
			Attributes: map[string]any{"external_principal": accountFromARN(arn) != strings.TrimPrefix(b.accountRef, "aws:")},
			Prov:       models.Provenance{Source: "aws", ExternalID: arn, AccountRef: b.accountRef, CollectedAt: &b.collectAt},
		}
	}
	return id
}

func (b *builder) result(cursor map[string]any) collectors.Result {
	idents := make([]models.Identity, 0, len(b.identities))
	for _, v := range b.identities {
		idents = append(idents, *v)
	}
	return collectors.Result{
		Identities:       idents,
		Credentials:      b.creds,
		Roles:            b.roles,
		TrustEdges:       b.trust,
		ResourceBindings: b.bindings,
		NewCursor:        cursor,
	}
}

// collectIAM pulls all IAM principals, their policies, credentials, and trust relationships.
func (c *clients) collectIAM(ctx context.Context, b *builder) error {
	// 1) One paginated call returns users, roles, and managed-policy documents.
	managed := map[string]string{} // policy arn -> default-version document (URL-encoded JSON)
	var users []iamtypes.UserDetail
	var roles []iamtypes.RoleDetail

	p := iam.NewGetAccountAuthorizationDetailsPaginator(c.iam, &iam.GetAccountAuthorizationDetailsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("get-account-authorization-details: %w", err)
		}
		users = append(users, page.UserDetailList...)
		roles = append(roles, page.RoleDetailList...)
		for _, mp := range page.Policies {
			doc := defaultPolicyVersion(mp)
			if doc != "" {
				managed[awssdk.ToString(mp.Arn)] = doc
			}
		}
	}

	for i := range users {
		c.buildUser(ctx, b, users[i], managed)
	}
	for i := range roles {
		b.buildRole(roles[i], managed)
	}
	return nil
}

// buildUser maps an IAM user, its access keys (+ last-used), and its permission set.
func (c *clients) buildUser(ctx context.Context, b *builder, u iamtypes.UserDetail, managed map[string]string) {
	arn := awssdk.ToString(u.Arn)
	created := awssdk.ToTime(u.CreateDate)
	ident := &models.Identity{
		Kind:            models.KindAWSIAMUser,
		Name:            awssdk.ToString(u.UserName),
		ARNOrEmail:      arn,
		Provider:        "aws",
		State:           "active",
		CreatedAtSource: &created,
		Attributes:      map[string]any{"path": awssdk.ToString(u.Path), "user_id": awssdk.ToString(u.UserId)},
		Prov:            models.Provenance{Source: "aws", ExternalID: arn, AccountRef: b.accountRef, CollectedAt: &b.collectAt},
	}
	identID := b.ensureIdentity(arn, models.KindAWSIAMUser, ident)

	// Access keys + last-used.
	var lastSeen *time.Time
	kp := iam.NewListAccessKeysPaginator(c.iam, &iam.ListAccessKeysInput{UserName: u.UserName})
	for kp.HasMorePages() {
		page, err := kp.NextPage(ctx)
		if err != nil {
			break
		}
		for _, k := range page.AccessKeyMetadata {
			keyID := awssdk.ToString(k.AccessKeyId)
			created := awssdk.ToTime(k.CreateDate)
			cred := models.Credential{
				IdentityID:      identID,
				CredType:        "aws_access_key",
				ExternalID:      keyID,
				Status:          strings.ToLower(string(k.Status)),
				CreatedAtSource: &created,
				AccountRef:      b.accountRef,
				Source:          "aws",
			}
			if lu, err := c.iam.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId}); err == nil && lu.AccessKeyLastUsed != nil {
				used := awssdk.ToTime(lu.AccessKeyLastUsed.LastUsedDate)
				if !used.IsZero() {
					cred.LastUsedAt = &used
					cred.LastUsedRegion = awssdk.ToString(lu.AccessKeyLastUsed.Region)
					cred.LastUsedService = awssdk.ToString(lu.AccessKeyLastUsed.ServiceName)
					lastSeen = laterTime(lastSeen, &used)
				}
			}
			b.creds = append(b.creds, cred)
		}
	}
	ident.LastSeenAt = lastSeen

	// Permission set (inline + attached) owned directly by the user.
	docs := collectPolicyDocs(u.UserPolicyList, u.AttachedManagedPolicies, managed)
	b.addPermissionSet(arn, awssdk.ToString(u.UserName), identID, docs, nil)
}

// buildRole maps an IAM role, its permission set, and its assume-role trust relationships.
func (b *builder) buildRole(r iamtypes.RoleDetail, managed map[string]string) {
	arn := awssdk.ToString(r.Arn)
	created := awssdk.ToTime(r.CreateDate)
	ident := &models.Identity{
		Kind:            models.KindAWSIAMRole,
		Name:            awssdk.ToString(r.RoleName),
		ARNOrEmail:      arn,
		Provider:        "aws",
		State:           "active",
		CreatedAtSource: &created,
		Attributes:      map[string]any{"path": awssdk.ToString(r.Path), "role_id": awssdk.ToString(r.RoleId)},
		Prov:            models.Provenance{Source: "aws", ExternalID: arn, AccountRef: b.accountRef, CollectedAt: &b.collectAt},
	}
	if r.RoleLastUsed != nil {
		used := awssdk.ToTime(r.RoleLastUsed.LastUsedDate)
		if !used.IsZero() {
			ident.LastSeenAt = &used
		}
	}
	identID := b.ensureIdentity(arn, models.KindAWSIAMRole, ident)

	// Permission set owned by the role.
	docs := collectPolicyDocs(r.RolePolicyList, r.AttachedManagedPolicies, managed)
	roleRecordID := b.addPermissionSet(arn, awssdk.ToString(r.RoleName), identID, docs, map[string]any{"assumable": true})

	// Trust relationships from the assume-role policy.
	for _, g := range parseTrustPolicy(awssdk.ToString(r.AssumeRolePolicyDocument)) {
		if g.Service {
			continue // service principals are not lateral-movement edges between NHIs
		}
		cond := map[string]any{}
		if len(g.Guards) > 0 {
			cond["guards"] = g.Guards
		}
		if g.Wildcard {
			cond["wildcard_principal"] = true
		}
		edge := models.TrustEdge{
			DstRoleID:  &roleRecordID,
			EdgeType:   "can_assume",
			Condition:  cond,
			Observed:   false, // policy-implied; CloudTrail confirms actual use
			AccountRef: b.accountRef,
			Source:     "aws",
		}
		if g.External {
			edge.EdgeType = "federated_from"
		}
		if g.Wildcard {
			// Unbounded principal: model as an external "any-principal" node.
			srcID := b.ensureIdentity("aws:*:any-principal", models.KindOther, nil)
			edge.SrcIdentityID = &srcID
		} else {
			srcKind := kindFromARN(g.PrincipalARN)
			srcID := b.ensureIdentity(g.PrincipalARN, srcKind, nil)
			edge.SrcIdentityID = &srcID
			if acct := accountFromARN(g.PrincipalARN); acct != "" && acct != strings.TrimPrefix(b.accountRef, "aws:") {
				cond["cross_account"] = true
			}
		}
		b.trust = append(b.trust, edge)
	}
}

// addPermissionSet creates a roles record (owned by identID) plus its resource bindings, and
// returns the role record id. extra carries role-specific attributes (e.g. assumable).
func (b *builder) addPermissionSet(arn, name string, identID uuid.UUID, docs []string, extra map[string]any) uuid.UUID {
	a := analyzePolicies(docs, b.crit)
	roleID := models.DeterministicID("role", arn)
	policyDoc := map[string]any{"has_priv_escalation": a.HasPrivEscalation}
	for k, v := range extra {
		policyDoc[k] = v
	}
	b.roles = append(b.roles, models.Role{
		ID:                    roleID,
		Provider:              "aws",
		ExternalID:            arn,
		AccountRef:            b.accountRef,
		Name:                  name,
		PolicyDocument:        policyDoc,
		PrivilegeLevel:        a.PrivilegeLevel,
		IsAssumable:           extra["assumable"] == true,
		PermissionCount:       a.PermissionCount,
		WildcardActionCount:   a.WildcardActionCount,
		WildcardResourceCount: a.WildcardResourceCount,
		OwnerIdentityID:       &identID,
		Source:                "aws",
	})
	for _, bd := range a.Bindings {
		rid := roleID
		b.bindings = append(b.bindings, models.ResourceBinding{
			RoleID:              &rid,
			ResourceURN:         bd.ResourceURN,
			ResourceKind:        resourceKind(bd.ResourceURN),
			ResourceCriticality: bd.Criticality,
			Actions:             bd.Actions,
			Effect:              bd.Effect,
			AccountRef:          b.accountRef,
			Source:              "aws",
		})
	}
	return roleID
}

// ----- helpers -----

func defaultPolicyVersion(mp iamtypes.ManagedPolicyDetail) string {
	def := awssdk.ToString(mp.DefaultVersionId)
	for _, v := range mp.PolicyVersionList {
		if awssdk.ToString(v.VersionId) == def || v.IsDefaultVersion {
			return awssdk.ToString(v.Document)
		}
	}
	return ""
}

func collectPolicyDocs(inline []iamtypes.PolicyDetail, attached []iamtypes.AttachedPolicy, managed map[string]string) []string {
	var docs []string
	for _, p := range inline {
		if d := awssdk.ToString(p.PolicyDocument); d != "" {
			docs = append(docs, d)
		}
	}
	for _, ap := range attached {
		if d, ok := managed[awssdk.ToString(ap.PolicyArn)]; ok {
			docs = append(docs, d)
		}
	}
	return docs
}

func kindFromARN(arn string) models.IdentityKind {
	switch {
	case strings.Contains(arn, ":user/"):
		return models.KindAWSIAMUser
	case strings.Contains(arn, ":role/"):
		return models.KindAWSIAMRole
	default:
		return models.KindOther
	}
}

func nameFromARN(arn string) string {
	if i := strings.LastIndexAny(arn, "/:"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

func resourceKind(urn string) string {
	// arn:aws:s3:::bucket → service is field index 2.
	parts := strings.Split(urn, ":")
	if len(parts) >= 3 && parts[2] != "" {
		return parts[2]
	}
	return "unknown"
}

func laterTime(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.After(*a) {
		return b
	}
	return a
}
