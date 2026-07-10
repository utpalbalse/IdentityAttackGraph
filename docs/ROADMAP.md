# IdentityAttackGraph Implementation Roadmap

Phased implementation plan. Each phase lists objectives, tasks, modules, acceptance criteria, 
risks, and dependencies. Phases are independently demoable and shippable.

---

## Phase 0 — Scaffold & dev environment
**Objectives:** repo, docs, one-command local dev, CI green.
**Tasks:** repo layout; design docs; `go.mod`; config/log/telemetry; docker-compose (pg/nats/redis);
Makefile; CI (build/test/lint/vuln); LICENSE.
**Modules:** `internal/config`, `internal/log`, `internal/telemetry`, `deploy/docker-compose.yml`,
`.github/workflows/ci.yml`.
**Acceptance:** `make dev` boots the stack; `make test` and CI pass; docs render.
**Risks:** scope creep in docs. **Deps:** none.

## Phase 1 — AWS collector + core schema + basic UI
**Objectives:** discover AWS NHIs, persist normalized inventory, list them in UI.
**Tasks:** SQL migrations (core tables); `models`; `store` repos; AWS collectors (IAM users/roles,
access keys + last-used, STS); normalizer; collector run harness + cursor state; REST
`/identities` list/detail; React inventory table + detail.
**Modules:** `migrations/0001_init.sql`, `internal/models`, `internal/store`,
`internal/collectors/aws`, `internal/normalize`, `internal/api`, `web/`.
**Acceptance:** point at an AWS account (or fixture) → identities + credentials appear with
provenance and last-used; idempotent re-run creates no dupes.
**Risks:** IAM API pagination/rate limits; last-used latency. **Deps:** Phase 0.

## Phase 2 — GCP collector + graph builder + search
**Objectives:** GCP NHIs; build the identity graph; searchable inventory.
**Tasks:** GCP collectors (service accounts, keys, IAM bindings, WIF); extend normalizer;
`graph_nodes/edges` projection job; in-memory graph engine (load + BFS/DFS); neighborhood API +
UI graph view; trgm search.
**Modules:** `internal/collectors/gcp`, `internal/graph`, graph projection in `internal/store`,
`web/` graph page.
**Acceptance:** AWS+GCP identities in one inventory; graph neighborhood renders; search works.
**Risks:** GCP IAM binding model differs from AWS; WIF mapping. **Deps:** Phase 1.

## Phase 3 — Detection engine + risk scoring
**Objectives:** explainable risk scores + first detections.
**Tasks:** risk engine (6 factors, weights config, explain); peer-group baselines; rule detectors
(orphaned, stale, over-privileged, wildcard-trust, conditionless-assume, high-blast); anomaly
detectors (unusual-geo, impossible-travel, spike, first-use, privilege-creep); usage_events
ingestion from CloudTrail; findings persistence + dedupe; risk + findings in UI/detail.
**Modules:** `internal/risk`, `internal/detect`, `configs/risk_weights.yaml`, CloudTrail collector.
**Acceptance:** scores reproducible from a snapshot; ≥8 detectors fire on the seed dataset with
evidence + narrative; FP controls (warm-up/allowlist/dedupe) in place.
**Risks:** anomaly FPs; baseline cold-start. **Deps:** Phase 2.

## Phase 4 — Alerting + remediation
**Objectives:** triage workflow + remediation with measurable risk reduction.
**Tasks:** triage queue (urgency sort); remediation recommendation generator; status workflow;
risk-delta tracking; attack-path API + view; exports (JSON/SARIF/CSV); audit log.
**Modules:** `internal/remediate`, `internal/export`, triage/remediation API + UI panels.
**Acceptance:** each high finding yields ranked remediations with projected risk delta; completing
one recomputes score and records delta; SARIF validates.
**Risks:** remediation correctness. **Deps:** Phase 3.

## Phase 5 — K8s deploy + observability + hardening
**Objectives:** production-ready.
**Status:** done — ✅ Dockerfiles, ✅ Helm chart (`deploy/helm/nhiid`), ✅ Terraform
(`deploy/terraform`: VPC/EKS/RDS/ElastiCache + IRSA + least-priv cross-account collector roles),
✅ Prometheus metrics (ingestion lag, throughput, job status), ✅ OTel traces (OTLP/gRPC for API
requests, collector runs, worker jobs), ✅ RBAC (token + JWT), ✅ secret-redacting logs,
✅ `govulncheck` in CI, ✅ k6 load test (`deploy/loadtest`). Remaining for v1.0: OIDC JWKS auto-fetch.
**Tasks:** Dockerfiles; Helm chart; Terraform (RDS, EKS, IRSA, least-priv collector roles);
OTel traces; Prometheus metrics (ingestion lag, throughput, job status); RBAC + OIDC;
secret-redacting logs; `govulncheck`; load test.
**Modules:** `deploy/helm`, `deploy/terraform`, `deploy/docker`, `internal/telemetry` (expand).
**Acceptance:** `helm install` runs on EKS; collectors use IRSA + assume-role (no static creds);
dashboards show lag/throughput; least-priv policy CI-linted.
**Risks:** cross-account trust setup. **Deps:** Phase 4.

## Phase 6 — Demo dataset + attack simulation + release polish
**Objectives:** compelling, reproducible demo + release.
**Status:** done — ✅ rich synthetic fixture (multi-account AWS+GCP + K8s, repo leak, conditionless
assume chain, **over-scoped AI agent**), ✅ `cmd/simulate` scripted attack-path walkthrough
(`internal/simulate` + tests) that narrates foothold → crown jewel with live detections and the
severing remediation, ✅ `make demo` / `make sim` + `scripts/simulate_attack.{sh,ps1}`, ✅ committed
sample reports (`docs/samples/`: SARIF/JSON/CSV + simulation), ✅ README "See it in action" +
`docs/DEMO.md`, ✅ release workflow (`.github/workflows/release.yml`: GHCR images + GitHub release on
tag). Also root-caused a dormant `ai_agent_overscoped` detector (List now hydrates ai_agent_meta).
**Tasks:** rich synthetic fixture (multi-account AWS+GCP, repo leak, assume chain, AI agent);
scripted "attack" that walks an attack path; screenshots/gif; README polish; sample reports;
tagged release + container images.
**Modules:** `fixtures/`, `cmd/simulate`, `internal/simulate`, `scripts/simulate_attack.*`, docs.
**Acceptance:** `make demo` → end-to-end demo with detections + attack-path; v0.1 released.
**Risks:** demo realism. **Deps:** Phase 5.

---

## Cross-phase definition of done
- Unit + integration tests for new modules; collectors have replay fixtures.
- New detections documented in `docs/DETECTIONS.md` with evidence shape.
- No secret material stored/logged/returned; provenance on every collected record.
- Metrics + structured logs for every job type.
