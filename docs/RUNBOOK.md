# IdentityAttackGraph Runbook

Operations guide for running and maintaining IdentityAttackGraph.

## Services
| Service | Purpose | Health |
|---------|---------|--------|
| `api` | REST API | `GET /healthz`, `/readyz` |
| `worker` | job consumer (collect/graph/score/detect) | metrics `nhiid_jobs_*` |
| `postgres` | system of record | `pg_isready` |
| `nats` | job stream | `/healthz` on monitor port |
| `redis` | rate-limit + cache | `redis-cli ping` |
| `web` | UI (static) | served via api/CDN |

## Common operations

**Local bring-up:** `make dev` → `make migrate` (auto) → `make seed`. Tear down: `make down`.

**Trigger a collection:**
`POST /api/v1/collect {"provider":"aws","account":"123456789012","collectors":["iam","cloudtrail"]}`
or CLI: `nhiid-collector --provider aws --account 123456789012 --collector iam`.

**Re-score / re-detect a snapshot:** worker jobs `score` and `detect` are idempotent; enqueue via
`POST /api/v1/collect` flow or `nhiid-worker --once --job score`.

## Key metrics (Prometheus)
- `nhiid_ingestion_lag_seconds{collector,account}` — now − newest event ingested. **Alert > 1h.**
- `nhiid_collector_run_duration_seconds`, `nhiid_collector_errors_total`
- `nhiid_jobs_inflight`, `nhiid_jobs_failed_total{job}`
- `nhiid_records_upserted_total{entity}`
- `nhiid_http_request_duration_seconds`, `nhiid_findings_open{severity}`

## Alerts → response
| Alert | Likely cause | Action |
|-------|--------------|--------|
| Ingestion lag high | collector failing / throttled / creds expired | check `collector_runs`, target IAM, rate-limit metrics |
| `jobs_failed_total` rising | poison job / store down | inspect worker logs (job id), check pg/nats |
| `readyz` failing | dependency down | check pg/nats/redis connectivity |
| Suppression churn alert | possible tampering | review `audit_log` for suppression changes |
| Collector errors spike | target trust/policy change | verify assume-role/WIF + ExternalId |

## Credential / access runbook
- NHIID pod identity = IRSA role; target access = assume-role (ExternalId) / GCP WIF.
- **Rotate ExternalId:** update Terraform var → apply → confirm collectors recover.
- **Revoke a target account:** remove the trust statement; collectors for it fail closed.
- No long-lived target creds exist to rotate by design.

## Data / retention
- `usage_events` partitioned monthly; archive/detach partitions older than retention (default 13mo).
- Snapshots immutable; prune per policy via `cmd/migrate`-managed job.

## Backup / DR
- RDS automated backups + PITR; Terraform-managed. Restore = standard RDS PITR; re-run graph
  build + score jobs to rebuild derived state (all derivable from normalized tables).

## Troubleshooting
- **No identities after collect:** check `collector_runs.status/errors`, target policy includes
  `iam:List*/Get*`, `iam:GenerateServiceLastAccessedDetails`.
- **Detections not firing:** confirm `usage_events` ingested (CloudTrail enabled) and baseline
  warm-up passed; check suppressions.
- **Graph empty:** ensure `graph_build` job ran after collection (worker logs).
