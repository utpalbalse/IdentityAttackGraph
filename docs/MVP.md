# IdentityAttackGraph MVP Scope & Non-Goals

The MVP is **production-shippable** by one engineer and demoable without real cloud credentials
(via synthetic fixtures). It covers Phases 0–4 plus Docker Compose deployment.

> **Note:** this document records the original MVP boundary. The project has since completed
> Phases 5–6 and the v1.0 backlog — Kubernetes collection, Helm/Terraform, Prometheus + OpenTelemetry,
> OIDC-JWKS RBAC, Slack/webhook alerting, a GraphQL API, AWS Secrets Manager, and a live repo secret
> scanner are all implemented. See [ROADMAP.md](ROADMAP.md) and [GETTING_STARTED.md](GETTING_STARTED.md).

## In scope (MVP)

1. **Discovery** — AWS (IAM users/roles, access keys + last-used, STS trust) and GCP (service
   accounts, SA keys, IAM bindings, workload identity) collectors, incremental with cursors.
2. **Normalized inventory** with ownership (from tags/labels/CSV) and full provenance.
3. **Identity graph** — nodes/edges projection + in-memory traversal (neighborhood, blast radius,
   attack paths).
4. **Detections (≥8 firing on seed; 17 detectors implemented today):** orphaned, stale key,
   over-privileged SA, conditionless/wildcard trust, secret-exposed-in-repo, high-blast-radius,
   unusual-geo, impossible-travel, usage-spike, first-use-sensitive-action, and more — see
   [DETECTIONS.md](DETECTIONS.md).
5. **Explainable risk score** — 6 factors, tunable weights, per-identity breakdown.
6. **Triage dashboard + searchable API** — inventory search, identity detail, triage queue,
   finding evidence + narrative, attack-path view, remediation panel.
7. **Exports** — JSON, SARIF, CSV.
8. **Scheduled + incremental ingestion**; **one-command local dev** (docker-compose) with seed.
9. **Observability basics** — structured logs, core metrics, health endpoints, audit log.

## Explicit non-goals (MVP)

- **No inline enforcement / blocking.** Detect + recommend only; not in the auth path.
- **No Azure / Okta collectors** yet (the collector interface is ready; these are post-v1.0).
  *(Slack alerting and generic-webhook notification shipped after the MVP.)*
- **No managed multi-tenant SaaS / billing.** Single-org deployment.
- **No full graph DB.** Relational + in-memory engine; Neo4j-style backend deferred.
- **No automated remediation execution.** We generate plans + track status/risk-delta; humans act.
- **No general CSPM** (non-identity misconfig) or full SIEM log ingestion.
- **No reading of secret values.** Exposure findings carry location + fingerprint only.
- **No ML model in the risk score.** Anomaly signals are statistical + evidenced, fed as discrete
  factors; the composite remains a transparent weighted sum.

## MVP acceptance (demo script)

```
make dev && make seed
# UI: inventory shows AWS+GCP identities with risk scores
# Triage queue: top item is the leaked-key-reaching-crown-jewel identity
# Open it: 6-factor breakdown + attack-path graph + remediation = "rotate + break trust"
# Mark remediation done -> risk recomputes, risk-reduction metric updates
# Export findings as SARIF -> validates
```
