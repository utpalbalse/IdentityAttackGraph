# IdentityAttackGraph — Launch & Positioning

## Why this project lands with Big Tech hiring managers

Non-human identities now outnumber humans 10–50:1 in cloud estates, and identity compromise 
(leaked keys, over-scoped service accounts, abused workload identities) is behind a major share 
of cloud security breaches. IdentityAttackGraph demonstrates the exact competencies a Staff/Senior 
cloud-security or detection-engineering role screens for:

- **Systems engineering:** a Go services platform (collectors, queue, store, engines) — not a script.
- **Security domain depth:** IAM trust chains, privilege escalation primitives, blast-radius/
  attack-path reasoning, anomaly detection with FP controls.
- **Data/graph modeling:** a graph engine and traversal logic built from scratch.
- **Detection engineering:** explainable, evidence-backed detections with baselining + suppression.
- **Production maturity:** IaC, observability, threat model, RBAC, least-privilege collection.

## GitHub launch checklist
- Crisp README with an architecture diagram and a 30-second `make dev && make seed` demo.
- An animated GIF of the triage queue → identity detail → attack-path → remediation flow.
- `docs/` design set (this folder) — recruiters and engineers both skim these.
- Good first issues + roadmap; clear non-goals so scope reads as deliberate.
- Tagged `v0.1` release with container images and a sample SARIF report.
- Topics: `cloud-security`, `iam`, `nhi`, `detection-engineering`, `aws`, `gcp`, `security-tools`.

## Narrative for résumé / interviews
> Designed and built IdentityAttackGraph, an open-source security platform that inventories 
> non-human identities across multi-account AWS and GCP, models them as a property graph for 
> attack-path reasoning, computes explainable 6-factor risk scores, and runs custom rule + 
> anomaly detections (impossible travel, privilege creep, conditionless assume-role, secret 
> exposure) with measurable remediation guidance. Go + Postgres + NATS; React/TS UI; Terraform/Helm 
> deployment; complete threat model and architecture.

Talking points that interview well: the risk-scoring weight rationale, the FP-control strategy,
why relational+in-memory graph over Neo4j at this scale, and the least-privilege/no-standing-creds
collection design from the threat model.

## Suggested demo path (live)
1. `make seed` → inventory of AWS+GCP NHIs with scores.
2. Triage queue → click the critical "leaked key → crown jewel" identity.
3. Show 6-factor breakdown; open the attack-path graph (2 hops to prod-billing).
4. Apply remediation (rotate + break trust) → score drops → risk-reduction metric ticks.
5. Export SARIF; show it validating.
