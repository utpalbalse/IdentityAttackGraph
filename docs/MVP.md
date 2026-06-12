# NHIID MVP Scope & Non-Goals

The MVP is **actually shippable** by one engineer and demoable without a real cloud account
(via the synthetic fixture). It covers Phases 0–4 plus a docker-compose deploy.

## In scope (MVP)

1. **Discovery** — AWS (IAM users/roles, access keys + last-used, STS trust) and GCP (service
   accounts, SA keys, IAM bindings, workload identity) collectors, incremental with cursors.
2. **Normalized inventory** with ownership (from tags/labels/CSV) and full provenance.
3. **Identity graph** — nodes/edges projection + in-memory traversal (neighborhood, blast radius,
   attack paths).
4. **Detections (≥8 firing on seed):** orphaned, stale key, over-privileged SA, conditionless/
   wildcard trust, secret-exposed-in-repo, high-blast-radius, unusual-geo, impossible-travel,
   usage-spike, first-use-sensitive-action.
5. **Explainable risk score** — 6 factors, tunable weights, per-identity breakdown.
6. **Triage dashboard + searchable API** — inventory search, identity detail, triage queue,
   finding evidence + narrative, attack-path view, remediation panel.
7. **Exports** — JSON, SARIF, CSV.
8. **Scheduled + incremental ingestion**; **one-command local dev** (docker-compose) with seed.
9. **Observability basics** — structured logs, core metrics, health endpoints, audit log.

## Explicit non-goals (MVP)

- **No inline enforcement / blocking.** Detect + recommend only; not in the auth path.
- **No Azure / Okta / Slack / generic CI** collectors yet (interfaces are ready; impls are v1.0).
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
