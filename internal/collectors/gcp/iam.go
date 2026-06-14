package gcp

import (
	"context"
	"fmt"
	"time"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	iam "google.golang.org/api/iam/v1"
)

// collectIAM discovers service accounts, their user-managed keys, who can impersonate them, and the
// project-level role bindings that determine what they can reach.
func (c *clients) collectIAM(ctx context.Context, b *builder, projectID string) error {
	parent := "projects/" + projectID

	err := c.iam.Projects.ServiceAccounts.List(parent).Pages(ctx, func(resp *iam.ListServiceAccountsResponse) error {
		for _, sa := range resp.Accounts {
			b.addServiceAccount(sa.Email, sa.DisplayName, sa.Disabled, map[string]any{
				"unique_id":        sa.UniqueId,
				"oauth2_client_id": sa.Oauth2ClientId,
			})
			c.collectKeys(ctx, b, sa)
			c.collectImpersonation(ctx, b, sa)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("list service accounts: %w", err)
	}

	// Project IAM policy → resource bindings for each service-account member.
	pol, err := c.crm.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get project iam policy: %w", err)
	}
	urn := "gcp:project:" + projectID
	for _, binding := range pol.Bindings {
		for _, m := range binding.Members {
			if isServiceAccountMember(m) {
				_, email := parseMember(m)
				b.noteGrant(email, binding.Role, urn, roleCriticality(binding.Role))
			}
		}
	}
	return nil
}

// collectKeys lists a service account's keys; only user-managed (long-lived) keys are credentials.
func (c *clients) collectKeys(ctx context.Context, b *builder, sa *iam.ServiceAccount) {
	resp, err := c.iam.Projects.ServiceAccounts.Keys.List(sa.Name).Context(ctx).Do()
	if err != nil {
		return
	}
	for _, k := range resp.Keys {
		validAfter, _ := time.Parse(time.RFC3339, k.ValidAfterTime)
		b.addKey(sa.Email, k.Name, k.KeyType, validAfter, k.Disabled)
	}
}

// collectImpersonation reads a service account's IAM policy; members holding token-creator /
// actAs / WIF roles can impersonate or federate into it — the GCP lateral-movement edges.
func (c *clients) collectImpersonation(ctx context.Context, b *builder, sa *iam.ServiceAccount) {
	pol, err := c.iam.Projects.ServiceAccounts.GetIamPolicy(sa.Name).Context(ctx).Do()
	if err != nil {
		return
	}
	for _, binding := range pol.Bindings {
		if !impersonationRoles[binding.Role] && !federationRoles[binding.Role] {
			continue
		}
		conditioned := binding.Condition != nil
		for _, m := range binding.Members {
			b.addImpersonation(sa.Email, m, binding.Role, conditioned)
		}
	}
}
