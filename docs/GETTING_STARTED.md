# IdentityAttackGraph Getting Started

## Quick start (local development)

### Prerequisites
**Docker & Docker Compose — that's all.** Every build (Go, Node) and the migrations run inside
containers. `make` is an optional convenience on Linux/macOS; Go 1.26+ / Node 20+ are needed only if
you want to run binaries or the Vite dev server directly on your host.

### One command: stack + demo data
```bash
docker compose -f deploy/docker-compose.yml --profile demo up --build -d
```

Builds and starts PostgreSQL (5432), Redis (6379), NATS JetStream (4222), the API (8080), the
worker, and the web UI (5173); applies migrations; then seeds the synthetic AWS+GCP+K8s dataset and
runs graph → score → detect once.

Where `make` is available, the equivalent is `make dev` (stack only) then `make demo` (seed + print
the narrated attack-path simulation).

### View the dashboard
Open <http://localhost:5173>. You should see **12 identities** scored in Inventory, **36 findings**
in Triage, and the kill chain in Attack Graph.

### What the demo dataset contains
12 non-human identities across AWS, GCP, and Kubernetes — including an access key exposed in a
private repo (`svc-billing-export`), a role assumable with **no ExternalId condition**
(`billing-admin`), a crown-jewel S3 bucket two hops from that leaked key, an over-scoped AI agent,
an orphaned identity, and stale keys. The K8s fixture adds a `prod/deployer` ServiceAccount bound to
`cluster-admin` and annotated for IRSA, which surfaces `over_privileged_sa` + `high_blast_radius`
with an attack path pod → ServiceAccount → cluster secrets, plus a `federated_from` edge into AWS.

Full breakdown: [DEMO.md](DEMO.md).

### Narrated attack-path simulation
```bash
docker compose -f deploy/docker-compose.yml exec api simulate        # or: make sim
```

### Re-run the pipeline by hand
All binaries (`collector`, `worker`, `migrate`, `simulate`) ship in the image, so no local Go is
required:
```bash
CO="docker compose -f deploy/docker-compose.yml"
$CO exec -T api collector --provider fixture --fixture fixtures/demo_env.json
$CO exec -T api collector --provider k8s --cluster demo --k8s-export fixtures/k8s_cluster.json
$CO exec -T api worker --once --job all      # or --job graph|score|detect
```

With a local Go toolchain you can equivalently run `go run ./cmd/collector ...` from the repo root.

### Stop the stack
```bash
docker compose -f deploy/docker-compose.yml down -v                  # or: make down
```

---

## Point it at a real cloud

Collection is **read-only** and never reads secret material. Set up the target first — for AWS,
a read-only role with an ExternalId ([AWS_COLLECTOR.md](AWS_COLLECTOR.md)); or build a disposable,
deliberately-vulnerable practice account with
[../deploy/terraform/demo-estate/](../deploy/terraform/demo-estate/).

### One-off collection
```bash
CO="docker compose -f deploy/docker-compose.yml"
$CO exec -T api collector --provider aws --role-arn <arn> --external-id <id> --region us-east-1
$CO exec -T api collector --provider gcp --project <project-id>
$CO exec -T api collector --provider k8s --cluster prod --k8s-export cluster.json
$CO exec -T api collector --provider repo --scan-path ./checkout --repo acme/api
$CO exec -T api worker --once --job all       # graph → score → detect
```

### Continuous collection (keep the inventory fresh)
The worker re-runs graph/score/detect every 60s, but that only re-processes whatever the collectors
last wrote. To keep discovery itself running, give the collector an `--interval`:

```bash
COLLECTOR_PROVIDER=aws \
COLLECTOR_INTERVAL=30m \
COLLECTOR_ARGS="--role-arn arn:aws:iam::123456789012:role/nhiid-collector --external-id $NHIID_EXTERNAL_ID --region us-east-1" \
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
docker compose -f deploy/docker-compose.yml --profile collect up -d
```

Credentials are passed through from your shell — nothing is baked into the image. Re-collecting is
safe: every entity is keyed by a deterministic UUID, so a repeat run updates rows in place instead
of duplicating them. The container handles `SIGTERM`, so `docker compose down` stops it cleanly.

Standalone (no compose), the same flag works directly:
```bash
collector --provider aws --interval 30m --role-arn <arn> --external-id <id>
```

On Kubernetes, let the cluster schedule it instead — enable `collector.enabled` and add one
`collector.targets` entry per account to get a CronJob each
([../deploy/helm/README.md](../deploy/helm/README.md)).

---

## Architecture walkthrough

1. **Collectors** (`cmd/collector`) — discover identities from AWS, GCP, Kubernetes, repositories, or fixtures.
   - Outputs: normalized records upserted idempotently to the store (deterministic UUIDv5 ids).
   - Run once per collection period or subscribe to the NATS job queue.

2. **Store** (`internal/store`) — pgx repositories for all entities.
   - Every identity, credential, secret, role, finding, etc. is persisted here.
   - Upserts are keyed by `(provider, external_id)` → idempotent replay-safe.

3. **Graph engine** (`internal/graph`) — in-memory directed property graph.
   - Loads nodes/edges from the store, computes blast radius and attack paths.
   - BFS/DFS for traversal, witness finding for shortest paths.

4. **Risk engine** (`internal/risk`) — 6-factor explainable scoring.
   - Privilege, exposure, freshness, usage, trust, blast_radius.
   - Weights are hot-reloadable; scores are reproducible.

5. **Detection engine** (`internal/detect`) — 17 detectors (10 rule + 7 anomaly).
   - Rules: orphaned, stale, stale-key, over-privileged, wildcard-trust, conditionless-assume, secret-in-repo, high-blast, ai-agent-overscoped, unused-secret.
   - Anomalies: impossible-travel, unusual-geo, new-asn, usage-spike, first-use-sensitive, privilege-creep, suspicious-role-chain.
   - Every finding carries evidence + fingerprint for dedupe. FP controls: warm-up, egress allowlist, break-glass, corroboration, suppression, confidence.

6. **API** (`cmd/api`, `internal/api`, `internal/graphqlapi`) — REST + GraphQL for inventory, findings, triage, export.
   - Served by chi router; JSON request/response; GraphQL at `/api/v1/graphql`.
   - RBAC via bearer token or OIDC JWT (with JWKS auto-fetch).

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
- **Point at a real cloud:** see [Point it at a real cloud](#point-it-at-a-real-cloud) above —
  one-off, continuous (`--interval`), or a Kubernetes CronJob.
- **Production deploy:** `terraform apply` in [../deploy/terraform/](../deploy/terraform/) (VPC/EKS/RDS/ElastiCache/IRSA), then `helm upgrade --install nhiid deploy/helm/nhiid` (see [../deploy/helm/README.md](../deploy/helm/README.md)).
- **Tests:** `make test` runs unit tests for the risk engine, all 17 detectors, graph traversal, every collector, JWKS validation, and the GraphQL schema. There are no DB-backed integration tests; the store layer and the full collect → graph → score → detect pipeline are exercised end-to-end by `make demo` against the containerised Postgres.

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
✅ Detection engine (17 detectors: 10 rule + 7 anomaly)  
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
✅ **OpenTelemetry tracing** — OTLP/gRPC spans for API requests, collector runs, and worker jobs (no-op unless `telemetry.otel_endpoint` is set)  
✅ **Secret-redacting logs**, **`govulncheck`** in CI, and a **k6 load test** ([../deploy/loadtest/](../deploy/loadtest/))  
✅ **Attack-path simulation** — `make demo` / `simulate` narrates leaked-key → crown-jewel, over-scoped AI agent, and cross-cloud K8s paths with live detections + remediation (see [DEMO.md](DEMO.md))  
✅ **Release automation** — GHCR images + GitHub release on version tag ([../.github/workflows/release.yml](../.github/workflows/release.yml))  
✅ **Secrets Manager scanner** — AWS Secrets Manager inventory (rotation + last-accessed) feeding `unused_secret` (see [AWS_COLLECTOR.md](AWS_COLLECTOR.md))  
✅ **Live secret scanner** — repo collector `--scan-path` walks a working tree (curated patterns + entropy) → exposures, in addition to SecretSweep report ingest (see [REPO_SCANNER.md](REPO_SCANNER.md))  
✅ **GraphQL API** — `/api/v1/graphql` over inventory, findings, attack paths, and blast radius (see [API.md](API.md))  
✅ **OIDC JWKS auto-fetch** — RS256 keys fetched + cached by `kid` from the issuer's `.well-known` (or an explicit JWKS URL), refreshed on rotation (see [AUTH.md](AUTH.md))  
✅ **Live client-go K8s source** — collect ServiceAccounts/RBAC/pods from a live cluster (kubeconfig or in-cluster), or ingest a kubectl export (see [K8S_COLLECTOR.md](K8S_COLLECTOR.md))  

Everything documented is implemented — there are no `❌` items left in the MVP + v1.0 scope.  
