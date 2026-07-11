# IdentityAttackGraph — Launch & Positioning

## Why this project lands with Big Tech hiring managers

Non-human identities now outnumber humans 10–50:1 in cloud estates, and identity compromise 
(leaked keys, over-scoped service accounts, abused workload identities) is behind a major share 
of cloud security breaches. IdentityAttackGraph demonstrates the exact competencies a Staff/Senior 
cloud-security or detection-engineering role screens for:

- **Systems engineering:** a Go services platform (collectors, queue, store, engines, REST+GraphQL) — not a script.
- **Security domain depth:** IAM trust chains, privilege-escalation primitives, K8s RBAC, cross-cloud
  workload-identity federation (IRSA/WIF), blast-radius/attack-path reasoning, anomaly detection with FP controls.
- **Data/graph modeling:** a from-scratch graph engine + traversal, with deterministic IDs that
  reconcile the same identity across AWS, GCP, and Kubernetes into one attack path.
- **Detection engineering:** 17 explainable, evidence-backed detectors with baselining + suppression,
  including over-scoped **AI-agent** identities.
- **Production maturity:** IaC (Helm/Terraform), observability (Prometheus + OpenTelemetry), threat
  model, RBAC (OIDC-JWKS), least-privilege no-standing-credential collection.

## GitHub launch checklist
- Crisp README with an architecture diagram and a 30-second `make dev && make seed` demo.
- An animated GIF of the triage queue → identity detail → attack-path → remediation flow.
- `docs/` design set (this folder) — recruiters and engineers both skim these.
- Good first issues + roadmap; clear non-goals so scope reads as deliberate.
- Committed sample outputs (`docs/samples/`: SARIF/JSON/CSV + the attack simulation) so the output
  is visible without running anything. (A tagged release + container images can follow when desired.)
- Topics: `cloud-security`, `iam`, `nhi`, `detection-engineering`, `aws`, `gcp`, `security-tools`.

## Narrative for résumé / interviews
> Designed and built IdentityAttackGraph, an open-source security platform that inventories
> non-human identities across multi-account AWS, GCP, and Kubernetes, models them as a property
> graph for cross-cloud attack-path reasoning (a leaked key or a pod's IRSA role → a crown-jewel
> resource), computes explainable 6-factor risk scores, and runs 17 custom rule + anomaly detectors
> (impossible travel, privilege creep, conditionless assume-role, suspicious role chains, over-scoped
> AI agents, secret exposure) with measurable remediation guidance. Go + Postgres + NATS; REST +
> GraphQL; React/TS + Cytoscape UI; Prometheus/OpenTelemetry; Terraform/Helm deployment; complete
> threat model and architecture.

Talking points that interview well: the risk-scoring weight rationale, the FP-control strategy,
why relational+in-memory graph over Neo4j at this scale, and the least-privilege/no-standing-creds
collection design from the threat model.

## Suggested demo path (live)
1. `make demo` → inventory of AWS+GCP+K8s NHIs with scores + a narrated attack-path simulation.
2. Triage queue → click the critical "leaked key → crown jewel" identity.
3. Show 6-factor breakdown; open the attack-path graph (2 hops to prod-billing).
4. Apply remediation (rotate + break trust) → score drops → risk-reduction metric ticks.
5. Query the same data over GraphQL; export SARIF and show it validating.
