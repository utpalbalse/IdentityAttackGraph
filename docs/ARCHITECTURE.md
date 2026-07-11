# IdentityAttackGraph Architecture

This document is the authoritative design reference for IdentityAttackGraph. It covers the 
architecture overview, component diagram, data flow, deployment topology, and the repository structure.

---

## 1. Design goals & principles

NHIID is built like a real enterprise security platform, not a script:

- **Graph-first data model.** Identities, secrets, workloads, roles, resources, and trust
  relationships are nodes and edges. Almost every interesting security question
  ("can this leaked key reach prod data?") is a graph traversal.
- **Incremental over batch.** Collectors do a full snapshot on first run, then ingest deltas
  (CloudTrail / Cloud Audit Logs / change events). Full re-scans are the fallback, not the norm.
- **Explainability is non-negotiable.** Every risk score is a sum of named, weighted factors.
  Every alert carries evidence and an attack narrative. No black boxes.
- **Provenance everywhere.** Every record carries `source`, `collected_at`, `collector_run_id`,
  and the raw payload hash. You can always answer "where did this come from and when?".
- **Idempotent, isolated collectors.** A collector is a pure function of (provider creds, cursor)
  → normalized records. It can be run, replayed, and tested in isolation.
- **Minimize false positives.** Detections are tuned to require corroborating evidence and
  support per-environment suppression and baselining.
- **Auditable & reproducible.** Snapshots are immutable. Re-running detection over a snapshot
  yields the same findings. Everything is observable and deployable via IaC.

---

## 2. Component diagram (text)

```
                                  ┌────────────────────────────────────────────────┐
                                  │                  CONTROL PLANE                  │
                                  │                                                │
  ┌──────────────┐   schedule     │   ┌───────────┐      enqueue     ┌───────────┐ │
  │  Scheduler   │───────────────────▶│  Worker   │◀───────────────  │   API     │ │
  │ (cron/jobs)  │                 │   │  pool     │   collect/score  │  (REST)   │ │
  └──────────────┘                 │   └─────┬─────┘                  └─────┬─────┘ │
                                  │         │                              │       │
                                  └─────────┼──────────────────────────────┼───────┘
                                            │ jobs (NATS JetStream)        │ queries
                                            ▼                              ▼
        ┌───────────────────────────── INGESTION LAYER ──────────────────────────────┐
        │                                                                             │
        │  AWS collector     GCP collector     K8s collector     Repo scanner         │
        │  - IAM/STS         - IAM             - ServiceAccounts  - GitHub/GitLab      │
        │  - CloudTrail      - Cloud Audit     - Roles/Bindings   - secret material    │
        │  - ECS/EKS         - Cloud Run/GKE   - Secrets          - SA JSON / tokens   │
        │  - Secrets Mgr     - Secret Manager  - annotations      - CI variables       │
        │  - Lambda/S3/KMS   - workload ident.                                         │
        │  - Config                                                                   │
        └───────────────────────────────────┬─────────────────────────────────────────┘
                                            │ raw provider objects
                                            ▼
        ┌───────────────────── NORMALIZATION LAYER ─────────────────────┐
        │  source adapters → UnifiedIdentity / Credential / Secret /     │
        │  Role / TrustEdge / ResourceBinding / UsageEvent / Workload    │
        │  + provenance (source, collected_at, run_id, raw_hash)         │
        └───────────────────────────────┬───────────────────────────────┘
                                        ▼
        ┌──────────────────────── PERSISTENCE ──────────────────────────┐
        │  PostgreSQL 16  (system of record)                            │
        │  - normalized entity tables    - graph_nodes / graph_edges    │
        │  - usage_events (partitioned)  - findings / remediation       │
        │  - snapshots (immutable)       - audit_log                    │
        │  Redis: rate-limit + hot caches    NATS: job stream            │
        └───────────────────────────────┬───────────────────────────────┘
                                        ▼
        ┌───────────────── ANALYTICS / DECISION ENGINES ────────────────┐
        │                                                               │
        │  Graph Engine     Risk Engine        Detection Engine         │
        │  - load nodes/    - 6 factor scores  - rule detectors         │
        │    edges into     - weighted sum     - anomaly detectors      │
        │    adjacency      - explainable      - baseline / peer-group   │
        │  - BFS/DFS paths  - per-identity     - evidence + narrative    │
        │  - blast radius     breakdown        - dedupe + suppression    │
        │  - attack paths                                               │
        └───────────────────────────────┬───────────────────────────────┘
                                        ▼
        ┌──────────────────────── PRESENTATION ─────────────────────────┐
        │  REST API (chi) + GraphQL  →  React + TS UI (Vite, Cytoscape)  │
        │  - inventory search    - identity detail view                 │
        │  - triage queue        - attack-path view                     │
        │  - findings + evidence - remediation panel                    │
        │  exports: JSON / SARIF / CSV     alerting: Slack / webhook     │
        └───────────────────────────────────────────────────────────────┘

        Cross-cutting: OpenTelemetry traces, Prometheus metrics, structured logs (slog),
        RBAC (token / OIDC-JWT with JWKS), audit trail, /healthz + /readyz.
```

---

## 3. Data flow

### 3.1 Collection (incremental sync)

1. Scheduler enqueues a `collect` job per `(provider, account/project, collector)` onto NATS.
2. A worker claims the job, loads the **cursor** for that collector (e.g. last CloudTrail event
   time, or last IAM snapshot ETag) from `collector_state`.
3. The collector calls provider APIs with pagination + rate-limit handling + exponential backoff.
   On first run it does a full snapshot; afterwards it requests only deltas since the cursor.
4. Raw provider objects are handed to the **normalizer**, which emits unified records tagged with
   provenance. The raw payload is hashed (sha256) and the hash stored; raw bodies are optionally
   retained in object storage for audit.
5. Normalized records are **upserted** into Postgres inside a transaction keyed by a stable
   `external_id` (idempotent — re-running a collector does not duplicate rows).
6. The collector advances the cursor and records a `collector_run` row (counts, duration, errors).

### 3.2 Graph build

7. A `graph_build` job projects normalized entities into `graph_nodes` and `graph_edges`
   (identity→secret, workload→identity, role→role assume, secret→repo, identity→resource, …).
   This is incremental: only entities changed since the last build are reprojected.

### 3.3 Scoring & detection

8. A `score` job recomputes risk for affected identities. The Risk Engine pulls the identity's
   graph neighborhood + usage stats and produces a 6-factor breakdown and composite score.
9. A `detect` job runs rule + anomaly detectors over changed entities and recent usage events,
   emitting `findings` with evidence, severity, and an attack narrative. Findings are deduped
   against open findings (stable fingerprint) and pass through suppression rules.

### 3.4 Serving

10. The API serves inventory search, identity detail, findings/triage, graph/attack-path
    queries, and exports over **REST and GraphQL** (`/api/v1/graphql`). The UI consumes the REST
    API. New findings above a severity threshold are dispatched to Slack/webhook sinks.

### 3.5 Remediation loop

11. A finding produces one or more **remediation recommendations** (rotate/revoke/reduce-scope/…).
    Operators mark actions planned/done; the engine recomputes risk and records the **risk delta**,
    giving measurable risk reduction over time.

---

## 4. Why these technology choices

| Concern | Choice | Rationale |
|--------|--------|-----------|
| Core engine | **Go 1.26** | First-class AWS/GCP/K8s SDKs, static binaries, great concurrency for collectors, strong-enough types, trivial to deploy. Rust was considered; Go wins on cloud-SDK maturity and team velocity for a security platform. |
| System of record | **PostgreSQL 16** | ACID, JSONB for provider payloads, partitioning for usage events, recursive CTEs for graph traversal, `pg_trgm` for search. One dependency to operate. |
| Graph | **Relational + in-memory engine** | We persist `graph_nodes`/`graph_edges` in Postgres (durable, queryable) and load working sets into an in-memory adjacency structure in Go for fast BFS/DFS attack-path traversal. A dedicated graph DB (Neo4j) is deliberately avoided for MVP to reduce operational surface; the engine is abstracted so it can be swapped later. |
| Async jobs | **NATS JetStream** | Durable, lightweight, easy local dev, at-least-once with acks. Kafka is overkill at MVP scale and heavy to run. |
| Cache / rate-limit | **Redis** | Token-bucket state shared across workers, hot-path caches. |
| API | **chi** router + **GraphQL** (graphql-go) | Minimal, idiomatic REST with per-route RBAC middleware; a GraphQL read surface (`/api/v1/graphql`) for the graph/attack-path shape. |
| AuthN | **bearer token / OIDC JWT** | JWT validated HS256 or RS256 with **JWKS auto-fetch** (keys discovered from the issuer, cached by `kid`, refreshed on rotation). |
| Alerting | **Slack / generic webhook** | New findings ≥ threshold dispatched at-least-once (stamped only after a successful send). |
| Migrations | **raw SQL + embedded migrator** | No external tool needed to clone-and-run; migrations are versioned SQL applied by `cmd/migrate`. |
| DB access | **pgx + hand-written repos** | Type-safe enough, no codegen step a contributor must learn. |
| Frontend | **React + TS + Vite** | Standard enterprise stack; fast dev server. |
| Graph viz | **Cytoscape.js** | Mature, handles large graphs, good layout algorithms. |
| Telemetry | **OpenTelemetry + Prometheus + slog** | Traces for collectors, metrics for lag/throughput, structured logs. |
| IaC | **Terraform + Helm** | Terraform for cloud infra (RDS, IAM, networking); Helm for the k8s workloads. |

---

## 5. Deployment topology

**Local (dev):** `docker compose` brings up postgres, nats, redis, api, worker, web. Fixtures
seed the DB so no cloud creds are required.

**Production (AWS target):**

```
                  Internet
                     │
                ┌────▼────┐
                │  ALB    │  (TLS, OIDC auth at edge)
                └────┬────┘
                     │
          ┌──────────▼───────────┐         ┌──────────────────────┐
          │ EKS cluster          │         │  RDS PostgreSQL (HA)  │
          │  - api (Deployment)  │◀───────▶│  Multi-AZ, encrypted  │
          │  - worker (Deploy)   │         └──────────────────────┘
          │  - web (static/CDN)  │         ┌──────────────────────┐
          │  - nats (StatefulSet)│◀───────▶│  ElastiCache (Redis)  │
          └──────────┬───────────┘         └──────────────────────┘
                     │  IRSA (workload identity, no static keys)
                     ▼
        Read-only cross-account roles in each target AWS account
        Read-only service account / WIF federation in each GCP project
```

Collectors authenticate to target accounts via **assume-role (AWS)** and **workload identity
federation (GCP)** — NHIID stores no long-lived target credentials. Its own pod identity is an
IRSA role; target access is least-privilege read-only (`SecurityAudit`-style + specific reads).

---

## 6. Repository structure

```
nhiid/
├── cmd/
│   ├── api/            # REST + GraphQL API server entrypoint
│   ├── worker/         # job consumer (collect/graph/score/detect/alert)
│   ├── collector/      # one-shot collector CLI (for cron/debug)
│   ├── simulate/       # narrated attack-path walkthrough
│   └── migrate/        # apply SQL migrations
├── internal/
│   ├── config/         # typed config loader (env + yaml)
│   ├── log/            # slog setup, secret-redacting handler
│   ├── metrics/        # Prometheus collectors + derived-gauge refresher
│   ├── tracing/        # OpenTelemetry (OTLP) tracer provider
│   ├── models/         # unified domain types (the schema in Go)
│   ├── store/          # pgx repositories
│   ├── queue/          # NATS JetStream publish/subscribe
│   ├── ratelimit/      # Redis per-principal rate limiter
│   ├── graph/          # in-memory graph engine, traversal, attack paths
│   ├── risk/           # risk engine: factors, weights, scoring, explain
│   ├── detect/         # detection engine: rules + anomaly detectors
│   ├── simulate/       # attack-path narration (pure)
│   ├── collectors/
│   │   ├── collector.go     # Collector interface + run harness
│   │   ├── aws/             # IAM/STS/CloudTrail/Secrets Manager
│   │   ├── gcp/             # IAM/Audit Logs/impersonation/WIF
│   │   ├── k8s/             # ServiceAccounts/RBAC/pods — live client-go or export
│   │   ├── repo/            # built-in secret scanner + SecretSweep ingest
│   │   └── fixture/         # synthetic demo loader
│   ├── remediate/      # remediation recommendation generation
│   ├── export/         # JSON / SARIF / CSV exporters
│   ├── auth/           # RBAC: bearer token / OIDC JWT + JWKS
│   ├── notify/         # Slack / webhook alerting
│   ├── graphqlapi/     # GraphQL schema + resolvers
│   └── api/            # chi handlers, middleware, RBAC, DTOs
├── migrations/         # 0001_init.sql … 0006_alerting.sql
├── web/                # React + TS dashboard (Vite, Cytoscape)
├── deploy/
│   ├── docker-compose.yml
│   ├── docker/         # Dockerfiles
│   ├── helm/           # k8s chart
│   ├── terraform/      # AWS infra (EKS/RDS/ElastiCache/IRSA)
│   └── loadtest/       # k6 SLO load test
├── scripts/            # simulate_attack.{sh,ps1}
├── fixtures/           # synthetic demo datasets (json)
├── configs/            # default config + risk weights yaml
├── docs/               # this folder (+ docs/samples/)
├── Makefile
├── go.mod
└── LICENSE
```

---

## 7. Assumptions

- Read-only access to target clouds is acceptable and grantable (SecurityAudit + targeted reads).
- CloudTrail / Cloud Audit Logs are enabled in target accounts (delivered to a log bucket or
  queryable). Where not, NHIID degrades to snapshot-only inventory (no usage/anomaly signals).
- Single-region control plane for MVP; multi-region is a later concern.
- "Owner" mapping comes from tags/labels, IaC metadata, or an uploaded ownership CSV — there is
  no universal owner source, so we support several and record provenance.
- Scale target for MVP: ~10k identities, ~100 accounts/projects, low-millions of usage events.
  The design (partitioned events, incremental sync, working-set graph) extends past that.

## 8. Non-goals (architecture level)

- Not an inline enforcement / blocking control (no PEP, no admission webhook that denies).
  NHIID **detects and recommends**; it does not sit in the auth path.
- Not a SIEM. It ingests identity-relevant events, not all logs.
- Not a secrets manager. It *finds* secrets and exposure; it does not store or broker them.
- Not a CSPM for general misconfig. It is identity-centric by design.
