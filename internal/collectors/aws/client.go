// Package aws collects IAM principals, credentials, trust relationships, and usage events from a
// single AWS account. It authenticates via assume-role (with ExternalId) for cross-account access
// so NHIID stores no long-lived target credentials (see docs/THREAT_MODEL.md). All collection is
// read-only; the required least-privilege policy is documented in docs/AWS_COLLECTOR.md.
package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Options configures an AWS collector.
type Options struct {
	// RoleARN, if set, is assumed for cross-account collection. If empty, ambient credentials
	// (env, shared config, instance/IRSA role) are used directly.
	RoleARN string
	// ExternalID is the agreed third-party confused-deputy guard required by the target's trust
	// policy. Strongly recommended for cross-account roles.
	ExternalID string
	// Region for API calls (IAM is global but the SDK still needs a region; CloudTrail is regional).
	Region string
	// MaxRetries bounds the SDK's adaptive retry with exponential backoff.
	MaxRetries int
	// CloudTrailLookbackHours bounds the first (cursorless) CloudTrail pull.
	CloudTrailLookbackHours int
}

// clients bundles the AWS service clients a collection pass needs.
type clients struct {
	iam        *iam.Client
	cloudtrail *cloudtrail.Client
	sts        *sts.Client
	accountID  string
}

// newClients loads AWS config, optionally assumes a role, and constructs service clients.
func newClients(ctx context.Context, opts Options) (*clients, error) {
	maxRetries := opts.MaxRetries
	if maxRetries == 0 {
		maxRetries = 8
	}
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(defaultRegion(opts.Region)),
		config.WithRetryer(func() awssdk.Retryer {
			// Adaptive retry handles throttling (Rate exceeded) with exponential backoff + jitter.
			return retry.AddWithMaxAttempts(retry.NewAdaptiveMode(), maxRetries)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	// Cross-account: wrap base credentials in an assume-role provider (short-lived STS creds).
	if opts.RoleARN != "" {
		base := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(base, opts.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "nhiid-collector"
			if opts.ExternalID != "" {
				o.ExternalID = awssdk.String(opts.ExternalID)
			}
		})
		cfg.Credentials = awssdk.NewCredentialsCache(provider)
	}

	c := &clients{
		iam:        iam.NewFromConfig(cfg),
		cloudtrail: cloudtrail.NewFromConfig(cfg),
		sts:        sts.NewFromConfig(cfg),
	}

	// Resolve the account id for canonical account_ref and self-checks.
	id, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts get-caller-identity (check credentials / assume-role trust): %w", err)
	}
	c.accountID = awssdk.ToString(id.Account)
	return c, nil
}

func defaultRegion(r string) string {
	if r != "" {
		return r
	}
	return "us-east-1"
}

// accountRef normalizes an account id into NHIID's canonical "aws:<id>" form.
func accountRef(accountID string) string {
	accountID = strings.TrimPrefix(accountID, "aws:")
	return "aws:" + accountID
}
