# AWS Collector

The AWS collector discovers IAM principals, their credentials, trust relationships, and usage
events from a single account. It is **read-only** and authenticates via **assume-role with
ExternalId** so IdentityAttackGraph stores no long-lived target credentials (see
[THREAT_MODEL.md](THREAT_MODEL.md)).

Implementation: [internal/collectors/aws/](../internal/collectors/aws/).

---

## What it collects

| Source | Produces | API |
|--------|----------|-----|
| IAM users | identities (`aws_iam_user`), `attributes.path/user_id` | `GetAccountAuthorizationDetails` |
| IAM access keys | credentials (`aws_access_key`) + last-used region/service/date | `ListAccessKeys`, `GetAccessKeyLastUsed` |
| IAM roles | identities (`aws_iam_role`), role last-used | `GetAccountAuthorizationDetails` |
| Inline + attached policies | `roles` permission sets (privilege level, wildcard counts, priv-esc flag) + `resource_bindings` | `GetAccountAuthorizationDetails` |
| Assume-role trust policies | `trust_edges` (`can_assume` / `federated_from`), with guards (ExternalId/MFA/IP/org), cross-account + wildcard flags | parsed from `AssumeRolePolicyDocument` |
| CloudTrail | `usage_events` (event, source, region, IP, user-agent, error) attributed to the acting principal | `LookupEvents` |
| Secrets Manager | `secrets` inventory (name, rotation enabled, last-rotated, **last-accessed**, version count) → `unused_secret` detector. Metadata only — `GetSecretValue` is never called. | `ListSecrets` |
| Resource criticality tags | elevates `resource_bindings` criticality to **crown_jewel** (see [Crown-jewel tagging](#crown-jewel-tagging)) | `GetResources` |

**Idempotent:** every entity is keyed by a deterministic UUID derived from its ARN
(`models.DeterministicID`), so re-running the collector never duplicates rows and lets trust edges
reference principals (including cross-account ones, which become enrichable stubs) before they are
persisted.

**Incremental:** IAM is a full snapshot each run (it's small); CloudTrail is incremental from a
saved cursor (`cloudtrail_after` timestamp in `collector_state`). First run pulls
`--cloudtrail-lookback-hours` of history.

---

## How identities map to the model

- An **IAM role** is both an identity *and* a permission set. The collector creates one
  `aws_iam_role` identity and one `roles` record (keyed by the role ARN, `owner_identity_id` = the
  role identity). Assume-role trust edges point *to* this `roles` record.
- An **IAM user's** inline/attached policies become a `roles` record owned by the user
  (`owner_identity_id` = the user), so the risk engine counts the user's directly-held privileges.
- `RoleRepo.ForIdentity` returns both directly-owned permission sets **and** roles reachable via
  assume-role trust edges — so a user that can assume a powerful role inherits that blast radius.

---

## Least-privilege IAM policy (the role NHIID assumes)

Attach this to the role in each target account. It is read-only and deliberately **excludes**
`secretsmanager:GetSecretValue` and `kms:Decrypt` — the collector reads metadata, never secret
material.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMInventory",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:ListUsers", "iam:ListRoles",
        "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
        "iam:GetRole", "iam:ListRoleTags", "iam:ListUserTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "UsageEvents",
      "Effect": "Allow",
      "Action": ["cloudtrail:LookupEvents"],
      "Resource": "*"
    },
    {
      "Sid": "SecretsInventory",
      "Effect": "Allow",
      "Action": ["secretsmanager:ListSecrets"],
      "Resource": "*"
    },
    {
      "Sid": "Identify",
      "Effect": "Allow",
      "Action": ["sts:GetCallerIdentity"],
      "Resource": "*"
    },
    {
      "Sid": "ResourceCriticalityTags",
      "Effect": "Allow",
      "Action": ["tag:GetResources"],
      "Resource": "*"
    }
  ]
}
```

`tag:GetResources` is used only to read the criticality tag (below). If you omit it, collection
still succeeds; resources simply never reach `crown_jewel` criticality.

## Trust policy on the assumed role

Pin the exact NHIID principal and require an ExternalId (confused-deputy guard):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<NHIID_ACCOUNT>:role/nhiid-collector" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<SHARED_SECRET>" } }
  }]
}
```

---

## Crown-jewel tagging

Whether a resource is a **crown jewel** (the asset you cannot lose) is a business fact AWS cannot
infer: to an IAM policy, `prod-billing` and `dev-scratch` are both just S3 buckets. So the collector
infers criticality from actions only up to `high`, and takes the top level from an explicit resource
tag:

```
nhiid:criticality = crown_jewel     # also accepts: high | medium | low
```

Tag the resources that matter (buckets, tables, secrets, KMS keys, …):

```bash
aws resourcegroupstaggingapi tag-resources \
  --resource-arn-list arn:aws:s3:::prod-billing \
  --tags nhiid:criticality=crown_jewel
```

On the next run the collector reads these via `tag:GetResources` and **elevates any permission
binding that can act on a tagged resource** to that criticality. Elevation requires both a resource
match (the policy's `Resource` covers the tagged ARN, including the bucket→objects case) and an
action that applies to the resource's service, so an unrelated `ec2:*` grant is not elevated by an
S3 crown jewel. This is what lights up the `crown_jewel_1hop` / `crown_jewel_chain` blast-radius
signals and the "leaked key → crown jewel" attack path on real AWS.

- Change the key with `--criticality-tag team:crit`; disable the lookup entirely with
  `--criticality-tag -`.
- It is **not** a full IAM policy evaluator: it does not resolve conditions, `NotAction`, or
  cross-statement deny precedence for the tag path (only `Allow` statements are analyzed).

---

## Running it

```bash
# Cross-account (recommended): assume a read-only role with an ExternalId
go run ./cmd/collector \
  --provider aws \
  --role-arn arn:aws:iam::123456789012:role/nhiid-collector \
  --external-id "$NHIID_EXTERNAL_ID" \
  --region us-east-1 \
  --cloudtrail-lookback-hours 24

# Same-account / local dev: use ambient credentials (env, shared config, IRSA)
AWS_PROFILE=security-audit go run ./cmd/collector --provider aws --region us-east-1
```

The account id is resolved from `sts:GetCallerIdentity`; the canonical `account_ref` is
`aws:<account-id>`.

After collection, build the graph, score, and detect:

```bash
go run ./cmd/worker --once --job graph
go run ./cmd/worker --once --job score
go run ./cmd/worker --once --job detect
```

---

## Reliability & limits

- **Retries/backoff:** the SDK is configured with adaptive retry + exponential backoff to absorb
  IAM/CloudTrail throttling (`Rate exceeded`).
- **Pagination:** all list calls are fully paginated. CloudTrail is capped at
  `maxCloudTrailPages` (≈2500 events) per run to respect its ~2 req/s limit; the cursor resumes
  next run.
- **Degraded mode:** if CloudTrail is unavailable/denied, inventory still succeeds (usage signal
  is simply absent) — the collector logs a warning and proceeds.
- **Geo enrichment:** CloudTrail provides source IP but not country/ASN. Geo/impossible-travel
  anomaly detectors require a geo-IP enrichment step (roadmap) to fire on live AWS data.

## Security notes (from the threat model)

- No standing target credentials: short-lived STS sessions only.
- Secret material is never read or stored; only ARNs/metadata/last-used.
- All collector activity is itself recorded in the target's CloudTrail; `collector_runs` provides
  reconciling provenance.
