package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nhiid/nhiid/internal/collectors"
)

// Collector implements collectors.Collector for a single AWS account.
type Collector struct {
	opts Options
	log  *slog.Logger
}

// New constructs an AWS collector. roleARN/externalID enable cross-account assume-role; leave
// roleARN empty to use ambient credentials (IRSA / env / shared config).
func New(opts Options, log *slog.Logger) *Collector {
	return &Collector{opts: opts, log: log}
}

func (c *Collector) ID() string { return "aws" }

// Collect runs IAM discovery (full snapshot, idempotent) and CloudTrail usage ingestion
// (incremental from the cursor). The two phases share one set of clients and one account_ref.
func (c *Collector) Collect(ctx context.Context, accountRefIn string, cursor map[string]any) (collectors.Result, error) {
	clients, err := newClients(ctx, c.opts)
	if err != nil {
		return collectors.Result{}, err
	}
	ref := accountRef(clients.accountID)
	if c.log != nil {
		c.log.Info("aws collector authenticated", "account", ref, "assumed_role", c.opts.RoleARN != "")
	}

	// Phase 0: resource criticality tags. Read before IAM so bindings can be elevated as they are
	// built. Non-fatal: a missing tag:GetResources permission degrades to action-inferred
	// criticality (no crown-jewel classification) rather than failing the whole collection.
	tagKey := c.opts.criticalityTagKey()
	resolver, terr := clients.collectResourceTags(ctx, tagKey)
	if terr != nil && c.log != nil {
		c.log.Warn("resource criticality tags degraded (crown-jewel classification disabled)", "err", terr, "tag_key", tagKey)
	} else if c.log != nil && resolver.len() > 0 {
		c.log.Info("resource criticality tags loaded", "tag_key", tagKey, "tagged_resources", resolver.len())
	}

	// Phase 1: IAM inventory (users, roles, credentials, trust, bindings).
	b := newBuilder(ref)
	b.crit = resolver
	if err := clients.collectIAM(ctx, b); err != nil {
		return collectors.Result{}, fmt.Errorf("collect iam: %w", err)
	}

	// Phase 2: CloudTrail usage events (incremental). Failure here is non-fatal — inventory still
	// has value without usage signal; we log and proceed so a missing CloudTrail doesn't block.
	events, newCursor, err := clients.collectCloudTrail(ctx, ref, cursor, c.opts.CloudTrailLookbackHours)
	if err != nil && c.log != nil {
		c.log.Warn("cloudtrail collection degraded", "err", err, "events_collected", len(events))
	}

	res := b.result(newCursor)
	res.UsageEvents = events

	// Phase 3: Secrets Manager inventory (metadata only — never the secret value). Non-fatal.
	secrets, serr := clients.collectSecrets(ctx, ref)
	if serr != nil {
		if c.log != nil {
			c.log.Warn("secrets manager collection degraded", "err", serr)
		}
	} else {
		res.Secrets = secrets
	}

	if c.log != nil {
		c.log.Info("aws collection complete",
			"identities", len(res.Identities), "credentials", len(res.Credentials),
			"roles", len(res.Roles), "trust_edges", len(res.TrustEdges),
			"bindings", len(res.ResourceBindings), "usage_events", len(res.UsageEvents),
			"secrets", len(res.Secrets))
	}
	return res, nil
}
