# IdentityAttackGraph Getting Started

## Quick start (local development)

### Prerequisites
- Docker & Docker Compose
- Go 1.25+ (for collector and worker commands)
- Node 20+ (for React dev server)

### One-command stack
```bash
make dev
```

This brings up:
- PostgreSQL (port 5432)
- Redis (port 6379)
- NATS JetStream (port 4222)
- API server (port 8080)
- Web UI (port 5173)
- Worker (background job processor)

### Seed the demo environment
```bash
make seed
```

This loads a synthetic multi-account AWS+GCP fixture with:
- 4 identities (2 AWS, 1 GCP, 1 orphaned)
- 1 access key exposed in a private repo
- 1 role assuming another with no ExternalId condition
- 1 identity with crown-jewel S3 bucket access

### View the dashboard
Open http://localhost:5173 in a browser. You should see:
- **Inventory tab:** 4 identities with risk scores
- **Triage tab:** findings from the detection engine firing on the demo data

### Run scoring and detection manually
```bash
make migrate          # Apply schema (auto on `make dev`)
go run ./cmd/collector --provider fixture --fixture fixtures/demo_env.json
go run ./cmd/collector --provider k8s --cluster demo --k8s-export fixtures/k8s_cluster.json  # K8s SAs + RBAC + IRSA/WIF
go run ./cmd/worker --once --job graph
go run ./cmd/worker --once --job score
go run ./cmd/worker --once --job detect
```

The K8s fixture adds a `prod/deployer` ServiceAccount bound to `cluster-admin` (and annotated for
IRSA) — after the worker runs it surfaces `over_privileged_sa` + `high_blast_radius`, with an
attack path pod → ServiceAccount → cluster secrets, plus a `federated_from` edge to the AWS role.

### Stop the stack
```bash
make down
```

---

## Architecture walkthrough

1. **Collectors** (`cmd/collector`) — discover identities from cloud providers or load fixtures.
   - Outputs: normalized records upserted idempotently to the store.
   - Run once per collection period or subscribe to a job queue.

2. **Store** (`internal/store`) — pgx repositories for all entities.
   - Every identity, credential, secret, role, finding, etc. is persisted here.
   - Upserts are keyed by `(provider, external_id)` → idempotent replay-safe.

3. **Graph engine** (`internal/graph`) — in-memory directed property graph.
   - Loads nodes/edges from the store, computes blast radius and attack paths.
   - BFS/DFS for traversal, witness finding for shortest paths.

4. **Risk engine** (`internal/risk`) — 6-factor explainable scoring.
   - Privilege, exposure, freshness, usage, trust, blast_radius.
   - Weights are hot-reloadable; scores are reproducible.

5. **Detection engine** (`internal/detect`) — rule + anomaly detectors.
   - Rules: orphaned, stale, over-privileged, wildcard-trust, conditionless-assume, secret-in-repo, high-blast, ai-agent-overscoped.
   - Anomalies: impossible-travel, unusual-geo, new-asn, usage-spike, first-use-sensitive, privilege-creep.
   - Every finding carries evidence + fingerprint for dedupe.

6. **API** (`cmd/api`, `internal/api`) — REST endpoints for inventory, findings, triage, export.
   - Served by chi router; JSON request/response.
   - Optional GraphQL planned (v1.0).

7. **Web UI** (`web/`) — React + TypeScript dashboard.
   - Inventory search, identity detail, triage queue, attack-path graph.
   - Calls `/api/v1/` endpoints; built with Vite.

8. **Worker** (`cmd/worker`) — job consumer for graph build, scoring, detection.
   - Runs continuously; processes all identities and emits findings.
   - Feeds the risk and detection engines.

---

## Next steps

- **Local development:** edit Go code, `make build && make dev` to restart.
- **Web dev:** `cd web && npm run dev` for Vite hot reload.
- **Point at real AWS:** `go run ./cmd/collector --provider aws --role-arn <arn> --external-id <id>` (see [AWS_COLLECTOR.md](AWS_COLLECTOR.md)).
- **Point at real GCP:** `go run ./cmd/collector --provider gcp --project <id>` using ADC or a WIF credentials file (see [GCP_COLLECTOR.md](GCP_COLLECTOR.md)).
- **Production deploy:** `terraform apply` in [../deploy/terraform/](../deploy/terraform/) (VPC/EKS/RDS/ElastiCache/IRSA), then `helm upgrade --install nhiid deploy/helm/nhiid` (see [../deploy/helm/README.md](../deploy/helm/README.md)).
- **Tests:** unit tests for risk engine, detection logic, graph traversal. Integration tests with a test DB.

---

## Key files for understanding the system

| File | Purpose |
|------|---------|
| `docs/ARCHITECTURE.md` | Component overview, data flow, deployment topology |
| `docs/DATA_MODEL.md` | SQL schema, unified types, provenance |
| `docs/RISK_MODEL.md` | Risk scoring formula, factor weights, examples |
| `docs/DETECTIONS.md` | Every detector, logic, evidence shape |
| `internal/models/models.go` | Go domain types (mirror of SQL) |
| `internal/risk/score.go` | Risk engine core logic |
| `internal/detect/detect.go` | Detection engine harness |
| `internal/detect/rules.go` | Rule detectors |
| `internal/detect/anomaly.go` | Anomaly detectors |
| `migrations/0001_init.sql` | Full schema (executable DDL) |
| `cmd/api/main.go` | API server entry point |
| `cmd/worker/main.go` | Worker / job consumer |
| `web/src/App.tsx` | React dashboard |

---

## Troubleshooting

**"Failed to connect to database"**
- `docker compose logs postgres` — check if Postgres is healthy.
- `docker exec <container> psql -U nhiid -d nhiid -c "SELECT 1"` — test connection.

**"API returns 500 for identities"**
- Check worker is running: `docker compose logs worker`.
- Ensure `make seed` was run to load fixture data.

**Web UI shows "Loading..." forever**
- Check browser dev console for CORS or network errors.
- Verify API server is reachable: `curl http://localhost:8080/healthz`.

---

## What's in the MVP

✅ Fixture collector (loads synthetic AWS+GCP environment)  
✅ Core data model + SQL schema  
✅ Store layer (identity, credential, role, finding repos)  
✅ Risk engine (6-factor transparent scoring)  
✅ Detection engine (9 rule detectors, 6 anomaly detectors)  
✅ Graph engine (blast radius, attack-path traversal)  
✅ Full REST API (inventory, graph/attack-paths, findings, triage, remediation, exports, snapshots, suppressions, audit, config — see [API.md](API.md))  
✅ React dashboard (inventory, triage, identity detail, Cytoscape attack-graph view)  
✅ Docker Compose (local dev, one command)  
✅ **AWS collector** — real IAM/STS/CloudTrail discovery with assume-role (see [AWS_COLLECTOR.md](AWS_COLLECTOR.md))  
✅ **GCP collector** — service accounts, keys, impersonation/WIF trust, project IAM, audit logs (see [GCP_COLLECTOR.md](GCP_COLLECTOR.md))  
✅ **Repo secret scanner** — ingests SecretSweep JSON/SARIF reports → exposures → `secret_exposed_in_repo` (see [REPO_SCANNER.md](REPO_SCANNER.md))  
✅ **Kubernetes collector** — ServiceAccounts, effective RBAC, pod workloads, token creds, and IRSA/Workload-Identity federation edges (pod → cloud attack paths) (see [K8S_COLLECTOR.md](K8S_COLLECTOR.md))  
✅ **RBAC** — bearer-token + JWT (HS256/RS256), viewer/analyst/admin, all mutations audited (see [AUTH.md](AUTH.md))  
✅ **Prometheus metrics** — `/metrics` listener + derived gauges (ingestion lag, findings, job status)  
✅ **NATS JetStream** job queue + **Redis** per-principal rate limiter  
✅ Exports — JSON / SARIF 2.1.0 / CSV  
✅ **Helm chart** — api/worker/web, migration hook, IRSA service account, Ingress, HPA/PDB, ServiceMonitor (see [../deploy/helm/README.md](../deploy/helm/README.md))  
✅ **Terraform (EKS)** — VPC, EKS, RDS Postgres, ElastiCache, IRSA + least-priv cross-account collector roles (see [../deploy/terraform/README.md](../deploy/terraform/README.md))  
✅ **Alerting** — Slack / generic-webhook notifications on new findings, severity threshold, at-least-once delivery (see [ALERTING.md](ALERTING.md))  

❌ Secrets Manager scanner (Phase 1)  
❌ Live GitHub/GitLab secret scanner — report ingest only, no live scan (Phase 1)  
❌ GraphQL API (v1.0)  
❌ OIDC JWKS auto-fetch — static JWT validation only (v1.0)  
❌ Live client-go K8s source — export ingest works; live cluster API pending (Phase 2)  
❌ OpenTelemetry traces — metrics implemented, tracing pending (Phase 5)  
