# Demo estate — a disposable, vulnerable-by-design AWS account for NHIID

This Terraform builds the smallest **real** AWS environment that reproduces NHIID's hero finding on
live data, then tears down in one command. It's the cloud analog of a deliberately-broken app you'd
install to demo a scanner.

```
svc-billing-export (IAM user + access key)      ← "leaked" into a repo
      │  can assume  (trust policy has NO ExternalId / MFA)   → conditionless_assume_role
      ▼
billing-admin (IAM role, s3:* on the billing bucket)          → over_privileged_sa, high_blast_radius
      │  acts on
      ▼
<prefix>-prod-billing (S3, tagged nhiid:criticality=crown_jewel)   ← the crown jewel
```

One `terraform apply` = that whole path, on your own account, discoverable by the read-only collector.

## Safety & cost

- **Safe by construction:** every resource is prefixed `nhiid-demo-`, tagged `nhiid:estate=demo`,
  buckets are **empty, private, and public-access-blocked**, and the only credential created belongs
  to a user whose *sole* permission is `sts:AssumeRole` on the demo role. There is no real data
  anywhere — a screenshot cannot leak anything.
- **Cost ≈ $0.** IAM users/roles/policies, empty S3 buckets, and tags are all free; the collector
  only reads. `enable_cloudtrail=true` adds a trail (pennies for a short session) — leave it off
  unless you specifically want the usage signal.
- **Use a throwaway or personal sandbox account.** Do not apply this into an account with real
  workloads.

## Deploy → collect → destroy

```bash
cd deploy/terraform/demo-estate
terraform init
terraform apply                       # ~15 IAM/S3 resources, ~20s

# Point the collector at it. Same-account with your own creds is simplest:
cd ../../..
AWS_PROFILE=<your-sandbox> go run ./cmd/collector --provider aws --region us-east-1

# Build the graph, score, and detect:
go run ./cmd/worker --once --job graph
go run ./cmd/worker --once --job score
go run ./cmd/worker --once --job detect

# ...open the UI, take your screenshots, then:
cd deploy/terraform/demo-estate
terraform destroy                     # removes everything the prefix owns
```

Cross-account (the realistic setup) instead of same-account:

```bash
terraform output collector_role_arn   # the read-only role this estate created
go run ./cmd/collector --provider aws \
  --role-arn "$(terraform output -raw collector_role_arn)" \
  --external-id "$(terraform output -raw collector_external_id)" \
  --region us-east-1
```

### Staging the "leaked key" (optional, for the repo finding)

The estate's access key grants **only** `sts:AssumeRole` on the demo role, so it is safe to plant.
Commit it to a **throwaway private repo**, then scan that repo so `secret_exposed_in_repo` fires:

```bash
terraform output leaked_access_key_id
terraform output -raw leaked_access_key_secret
# ...write both into a .env in a throwaway repo, commit, then:
go run ./cmd/collector --provider repo --scan-path /path/to/throwaway-repo --repo you/throwaway
```

`terraform destroy` deactivates the key, so it is dead the moment you're done.

## What this live estate produces — and what it doesn't

Honesty matters here (recruiters will ask). A *freshly created* estate can't fake the passage of
time, so it fires the structural signals but not the time/behavior ones:

| Signal | Fires on this estate? | Why |
|--------|----------------------|-----|
| `conditionless_assume_role` | ✅ | trust policy has no ExternalId/MFA condition |
| `over_privileged_sa` / priv-esc | ✅ | `s3:*`/`dynamodb:*` + `iam:PassRole` on `over-privileged-ci` |
| `high_blast_radius` + crown-jewel path | ✅ | `billing-admin` reaches the crown-jewel bucket |
| crown-jewel elevation via tag | ✅ | `nhiid:criticality=crown_jewel` on `prod-billing` (needs `tag:GetResources`) |
| `secret_exposed_in_repo` | ✅ *(if you plant the key)* | see "Staging the leaked key" above |
| `stale_access_key` / freshness | ❌ | the key is brand new; freshness needs an aged key |
| `usage` factor, `impossible_travel`, geo anomalies | ❌ | needs CloudTrail history (`enable_cloudtrail`) **and** geo-IP enrichment (roadmap) |

For the fully-populated, multi-signal picture used in the screenshots and posts, see the built-in
demo dataset ([docs/DEMO.md](../../../docs/DEMO.md), `make demo`) — this estate reproduces its AWS
core (Scenario 1) on live infrastructure so the path is real, not just modeled.

## Inputs

| Variable | Default | Purpose |
|----------|---------|---------|
| `region` | `us-east-1` | region for S3/CloudTrail (IAM is global) |
| `name_prefix` | `nhiid-demo` | prefix on every resource; teardown boundary |
| `criticality_tag_key` | `nhiid:criticality` | must match collector `--criticality-tag` |
| `create_collector_role` | `true` | create the read-only cross-account role |
| `collector_trusted_principal_arn` | `""` (→ account root) | who may assume that role |
| `collector_external_id` | `nhiid-demo-external-id` | ExternalId for the collector |
| `enable_cloudtrail` | `false` | add a usage-history trail (pennies) |

## Outputs

`collector_role_arn`, `collector_external_id`, `crown_jewel_bucket`, `dev_scratch_bucket`,
`billing_admin_role_arn`, `svc_billing_export_user`, `leaked_access_key_id`, and
`leaked_access_key_secret` (sensitive). See [outputs.tf](outputs.tf).
