# GCP Collector

Discovers service accounts, their user-managed keys, who can impersonate them, and the project
IAM bindings that determine what they can reach — from a single GCP project. **Read-only**, and
authenticates via **Application Default Credentials / Workload Identity Federation** (no stored
static keys). Implementation: [internal/collectors/gcp/](../internal/collectors/gcp/).

GCP's lateral-movement model differs from AWS: instead of `sts:AssumeRole`, a principal that holds
`roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` (actAs) **on** a service
account can impersonate it. Those grants become `can_impersonate` / `federated_from` trust edges in
the graph — the GCP attack-path primitive.

---

## What it collects

| Source | Produces | API |
|--------|----------|-----|
| Service accounts | identities (`gcp_service_account`) | `projects.serviceAccounts.list` |
| User-managed SA keys | credentials (`gcp_sa_key`, modeled as static — no expiry) | `serviceAccounts.keys.list` |
| SA IAM policy | `trust_edges` — `can_impersonate` (tokenCreator/actAs/keyAdmin/owner/editor) and `federated_from` (workloadIdentityUser); conditionless unless an IAM Condition is set; `wildcard_principal` for `allUsers`/`allAuthenticatedUsers` | `serviceAccounts.getIamPolicy` |
| Project IAM policy | `roles` permission set per SA + `resource_bindings` to the project (criticality from the role: `roles/owner` and data-service admin → crown jewel) | `projects.getIamPolicy` |
| Cloud Audit Logs | `usage_events` (method, service, caller IP, principal), incremental via cursor | `logging.entries.list` |

Google-managed keys are intentionally skipped — they're rotated by Google and not exfiltratable;
**user-managed keys** are the long-lived credential risk.

## Role classification (see [roles.go](../internal/collectors/gcp/roles.go))

- **escalation:** `owner`, `iam.securityAdmin`, `iam.serviceAccountTokenCreator`,
  `iam.serviceAccountUser`, `iam.serviceAccountKeyAdmin`, `iam.roleAdmin`,
  `resourcemanager.organizationAdmin`, `iam.workloadIdentityPoolAdmin`
- **impersonation (on a SA):** tokenCreator, serviceAccountUser (actAs), keyAdmin, owner, editor
- **federation:** `iam.workloadIdentityUser`
- **criticality:** `roles/owner` → crown jewel; data-service admin (storage/bigquery/secretmanager/
  cloudkms/spanner/sql/…) → crown jewel; other admin → high; writer/publisher → medium.

## Least-privilege setup

Grant the collector principal read-only roles on the target project:

```
roles/iam.securityReviewer        # list SAs, read IAM policies (project + per-SA)
roles/iam.serviceAccountViewer    # service account + key metadata
roles/logging.viewer              # Cloud Audit Logs (usage events)
```

Authenticate with **Workload Identity Federation** (preferred — no keys) or ADC:

```bash
# WIF / ADC (no static key)
gcloud auth application-default login         # local dev
# or set GOOGLE_APPLICATION_CREDENTIALS to a WIF credential config

go run ./cmd/collector --provider gcp --project my-gcp-project --audit-lookback-hours 24

# explicit credentials file (e.g. WIF config), if not using ambient ADC
go run ./cmd/collector --provider gcp --project my-gcp-project --gcp-credentials ./wif.json
```

The canonical `account_ref` is `gcp:<project-id>`.

## How it lands in the graph

A service account with `roles/owner` on its project, that a CI deployer can impersonate without an
IAM Condition, produces this attack path:

```
ci-deployer  --impersonates-->  data-processor  --has_permissions-->  [owner perms]  --binds_to-->  gcp:project (crown jewel)
```

The same pipeline as AWS then scores blast radius, fires `high_blast_radius` /
`conditionless_assume_role`-class findings, and renders the path in the Attack Graph view.

## Limits

- Project-scoped (folder/org bindings and per-resource policies beyond the project are a follow-up).
- Cloud Audit Logs lack geo/ASN, so geo/impossible-travel detectors need a geo-IP enrichment step
  to fire on live GCP data (same as AWS CloudTrail).
- Custom-role permission expansion is approximated by role name; full IAM permission resolution is
  a later enhancement.
