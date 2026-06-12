# IdentityAttackGraph Data Model

The model is **graph-oriented**: normalized entity tables are the source of truth, and they are
projected into `graph_nodes` / `graph_edges` for attack-path traversal. Everything carries **provenance**.

See [migrations/0001_init.sql](../migrations/0001_init.sql) for the executable DDL.

---

## 1. Entity overview

```
                    ┌──────────┐         owns          ┌────────────┐
                    │ identity │──────────────────────▶│ credential │
                    └────┬─────┘                        └────────────┘
            uses │       │ has_binding        ┌──────────┐
       ┌──────────▼──┐   │                    │  secret  │◀── references ── workload
       │  workload   │   │ assumes/mints      └────┬─────┘
       └─────┬───────┘   ▼                         │ exposed_in
             │      ┌──────────┐               ┌────▼──────┐
   runs_in   │      │   role   │               │ repository│
             ▼      └────┬─────┘               └───────────┘
       ┌──────────┐      │ grants
       │ resource │◀─────┘ (resource_binding)
       └──────────┘
```

Owners, findings, remediation_actions, usage_events, snapshots, collector_runs, and audit_log
attach to the above.

---

## 2. Core tables

All tables include `id uuid pk`, `created_at`, `updated_at`. **Provenance columns** (on every
collected entity): `source text` (e.g. `aws`,`gcp`,`github`,`k8s`), `external_id text`
(stable provider id used for idempotent upsert), `account_ref text` (account/project),
`collector_run_id uuid`, `collected_at timestamptz`, `raw_hash text`, `attributes jsonb`.

### identities
The central NHI record.
- `kind` enum: `aws_iam_user | aws_iam_role | aws_sts_session | gcp_service_account |
  k8s_service_account | workload_identity | api_client | ai_agent | other`
- `name`, `arn_or_email` (canonical principal), `account_ref`, `provider`
- `state` enum: `active | disabled | deleted`
- `owner_id` (fk owners, nullable → orphan signal)
- `created_at_source` (provider creation time), `last_seen_at` (last usage), `last_rotated_at`
- `risk_score int`, `risk_breakdown jsonb` (cached latest score)
- `is_ai_agent bool`, `ai_agent_meta jsonb` (tooling scope, TTL, framework)

### credentials
Auth material attached to an identity (NOT the secret value).
- `identity_id` fk
- `cred_type` enum: `aws_access_key | gcp_sa_key | oauth_token | api_key | bearer_token |
  certificate | password`
- `external_id` (e.g. AccessKeyId, key fingerprint — never the secret)
- `status` enum: `active | inactive | compromised`
- `created_at_source`, `last_used_at`, `last_used_region`, `last_used_service`, `expires_at`

### secrets
A *managed* secret object (Secrets Manager / Secret Manager / Vault / K8s Secret).
- `store` enum: `aws_secrets_manager | gcp_secret_manager | vault | k8s_secret | other`
- `external_id` (ARN/name), `account_ref`
- `last_rotated_at`, `rotation_enabled bool`, `version_count int`
- `material_fingerprint` (sha256 of value if NHIID ever sees it — usually null)
- `referenced_by_count int` (cache)

### roles
A privilege grant container (IAM role/policy set, GCP role binding target).
- `provider`, `external_id`, `account_ref`, `name`
- `policy_document jsonb` (normalized statements)
- `privilege_level` enum: `read | write | admin | privileged` (derived)
- `is_assumable bool`, `trust_policy jsonb`
- `permission_count int`, `wildcard_action_count int`, `wildcard_resource_count int`

### trust_edges
Assume-role / token-minting / impersonation relationships (also projected to graph).
- `src_identity_id` / `src_role_id` (one set)
- `dst_role_id` / `dst_identity_id`
- `edge_type` enum: `can_assume | can_impersonate | can_mint_token | federated_from`
- `condition jsonb` (e.g. ExternalId, MFA, IP conditions)
- `observed bool` (true if seen in logs, false if only policy-implied)

### resource_bindings
Identity/role → cloud resource permission (the "what can it touch").
- `identity_id` or `role_id`
- `resource_urn` (canonical: `aws:s3:bucket:...`, `gcp:storage:bucket:...`)
- `resource_kind`, `resource_criticality` enum: `low | medium | high | crown_jewel`
- `actions text[]`, `effect` enum: `allow | deny`

### usage_events  *(partitioned by month)*
Normalized identity-usage from CloudTrail / Cloud Audit Logs / token issuance.
- `identity_id`, `event_time`, `event_name`, `event_source` (service)
- `src_ip inet`, `src_asn int`, `src_region`, `src_country`, `user_agent`, `runtime`
- `mfa_used bool`, `error_code`, `request_params_hash`
- `raw_hash`, `provenance` columns
- Indexed on `(identity_id, event_time desc)`; partitioned monthly for scale.

### workloads
A compute principal that *uses* an identity (ECS task, Lambda, GKE pod, CI job).
- `kind` enum: `ecs_task | lambda | ec2 | gke_pod | cloud_run | ci_job | other`
- `external_id`, `account_ref`, `name`, `environment` (prod/staging/dev from tags)
- `identity_id` (the NHI it runs as)

### repositories
- `provider` enum: `github | gitlab`
- `external_id`, `org`, `name`, `visibility` enum: `public | private | internal`
- `default_branch`, `last_scanned_at`

### owners
- `kind` enum: `user | team | service`, `email`, `display_name`, `source` (tag/csv/iac)

### findings
A detection result.
- `detector` (stable id, e.g. `stale_access_key`), `category`, `severity` enum:
  `info | low | medium | high | critical`
- `identity_id` (subject), `title`, `narrative` (attack story), `evidence jsonb`
- `fingerprint` (stable dedupe key), `status` enum: `open | triaged | suppressed | resolved`
- `risk_contribution int`, `first_seen_at`, `last_seen_at`, `snapshot_id`

### remediation_actions
- `finding_id` fk, `action` enum: `rotate | revoke | disable_key | reduce_scope |
  add_condition | require_mfa | shorten_ttl | break_trust | remove_identity`
- `status` enum: `recommended | planned | in_progress | done | wont_fix`
- `risk_before int`, `risk_after int`, `risk_delta int`, `assignee`, `notes`

### graph_nodes / graph_edges
Projection layer for traversal.
- `graph_nodes(id, node_type, entity_id, account_ref, label, attributes jsonb, criticality)`
- `graph_edges(id, src_node_id, dst_node_id, edge_type, weight, attributes jsonb, observed)`
- `edge_type` examples: `owns | uses | assumes | impersonates | references | exposes |
  binds_to | runs_in | federated_from`

### snapshots
Immutable point-in-time marker for reproducibility.
- `id`, `started_at`, `finished_at`, `scope jsonb` (accounts/providers), `entity_counts jsonb`

### collector_runs
- `collector`, `account_ref`, `cursor_before`, `cursor_after`, `records_in`, `records_upserted`,
  `errors int`, `started_at`, `finished_at`, `status`

### collector_state
Per-collector cursor for incremental sync: `(collector, account_ref) → cursor jsonb`.

### audit_log
- `actor`, `action`, `target_type`, `target_id`, `before jsonb`, `after jsonb`, `at`

---

## 3. Graph projection rules

| Normalized source | Node(s) | Edge |
|---|---|---|
| identity owns credential | identity, credential | `owns` |
| workload runs as identity | workload, identity | `uses` |
| trust_edge can_assume | identity/role, role | `assumes` |
| trust_edge can_impersonate | identity, identity | `impersonates` |
| secret referenced by workload | workload, secret | `references` |
| credential material in repo | repository, identity/secret | `exposes` |
| resource_binding | identity/role, resource | `binds_to` |
| workload in account/env | workload, account-node | `runs_in` |
| GCP WIF federation | external_idp, identity | `federated_from` |

Node `criticality` is inherited from `resource_criticality` for resources and derived for
identities by max-reachable resource criticality (computed by the graph engine).

---

## 4. Indexing & scale notes

- `usage_events` partitioned monthly; old partitions detached/archived per retention.
- `identities (account_ref, kind)`, `(risk_score desc)` for triage queue.
- `findings (status, severity, last_seen_at desc)`; unique on `fingerprint` (partial, where open).
- `pg_trgm` GIN on `identities.name`, `identities.arn_or_email` for fuzzy inventory search.
- Graph working sets are loaded per-query (by account/scope), not the whole graph, keeping
  traversal memory bounded.
