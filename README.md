# IdentityAttackGraph — Non-Human Identity Inventory & Detection

> Discover, inventory, normalize, score, and detect abuse of **non-human identities** (service accounts, 
> access keys, API tokens, workload identities, secrets, certificates, and AI-agent identities) 
> across multi-account AWS and multi-project GCP.

IdentityAttackGraph answers six critical security questions:

1. **What** machine identities exist?
2. **Where** are they used (which workloads, repos, resources)?
3. **Which** are over-privileged, stale, or orphaned?
4. **Which** are behaving abnormally **right now**?
5. **What** is the blast radius if one is compromised?
6. **What** should we remediate first, and how much risk does that remove?

This is a **from-scratch** security platform. The inventory model, normalization, graph engine,
risk scoring, attack-path reasoning, and detection logic are all implemented here — not a
wrapper around existing tools. We integrate with cloud provider APIs for data collection only.

---

## Status

Early, actively-built MVP. See [docs/ROADMAP.md](docs/ROADMAP.md) for the milestone plan and
[docs/MVP.md](docs/MVP.md) for what is in/out of the first shippable cut.

## Documentation

| Doc | What's in it |
|-----|--------------|
| [docs/DEMO.md](docs/DEMO.md) | **Start here** — one-command demo + narrated attack path |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, component diagram, data flow |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, threats, trust boundaries, mitigations |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | Unified schema, entities, graph model |
| [docs/RISK_MODEL.md](docs/RISK_MODEL.md) | Scoring formula, factor weights, rationale |
| [docs/DETECTIONS.md](docs/DETECTIONS.md) | Every detection, its logic, and evidence shape |
| [docs/API.md](docs/API.md) | REST API surface |
| [docs/AUTH.md](docs/AUTH.md) | Bearer-token RBAC (viewer/analyst/admin); OIDC path |
| [docs/ALERTING.md](docs/ALERTING.md) | Slack/webhook alerting on new findings (severity threshold, at-least-once) |
| [docs/AWS_COLLECTOR.md](docs/AWS_COLLECTOR.md) | AWS collector: least-priv policy, assume-role, what it collects |
| [docs/GCP_COLLECTOR.md](docs/GCP_COLLECTOR.md) | GCP collector: SAs, keys, impersonation/WIF trust, project IAM |
| [docs/K8S_COLLECTOR.md](docs/K8S_COLLECTOR.md) | Kubernetes collector: ServiceAccounts, RBAC, IRSA/Workload-Identity federation |
| [docs/REPO_SCANNER.md](docs/REPO_SCANNER.md) | Repo secret scanner: SecretSweep report ingest → exposures |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased milestone plan with acceptance criteria |
| [docs/MVP.md](docs/MVP.md) | MVP scope + non-goals |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Operating, troubleshooting, on-call |

## Quick start (local, one command)

No local Go or Node toolchain required — everything builds and runs in containers.

```bash
make dev          # compose up: postgres, redis, nats, migrate (one-shot), api, worker, web
make demo         # seed AWS+GCP+K8s fixtures, run graph/score/detect, print the attack simulation
open http://localhost:5173
```

`make dev` runs DB migrations automatically (the `migrate` service applies the embedded SQL, then
api/worker/web start from compiled binaries). On Windows without `make`, use the compose commands
directly: `docker compose -f deploy/docker-compose.yml up --build -d`.

## See it in action

`make demo` ends by narrating the worst attack paths it finds — computed live from the graph, with
the detections that caught each and the one remediation that severs it (full output in
[docs/DEMO.md](docs/DEMO.md) and [docs/samples/](docs/samples/)):

```text
━━━ Scenario 1 · Leaked credential → crown jewel
  target  svc-billing-export  (risk 67)
  RECON   attacker finds credential material at .env:12 (pattern aws_akia) — belongs to svc-billing-export
  STEP 0  ▸ svc-billing-export [identity]
  STEP 1  → assumes role billing-admin [role] ▲ high
  STEP 2  → gains access to arn:aws:s3:::prod-billing [resource] ◆ CROWN JEWEL
  IMPACT  1 crown jewel(s) reachable · nearest crown jewel 2 hop(s) · reaches admin: true
  CAUGHT  secret_exposed_in_repo (critical), conditionless_assume_role (high), high_blast_radius (high), …
  FIX     reduce_scope  →  risk 67→30 (−37)
```

The synthetic dataset ships the mistakes attackers exploit: a key committed to a repo, a
conditionless assume-role chain to a crown-jewel bucket, an **over-scoped AI agent** reaching a
secret, a **Kubernetes** ServiceAccount bound to cluster-admin with an IRSA edge into AWS, GCP
impersonation, and orphaned/stale credentials — all detected with **no cloud credentials**.

## Architecture at a glance

```
 collectors (aws/gcp/k8s/repo)  ->  normalizer  ->  Postgres (system of record)
                                                       |
                                            graph builder (nodes+edges)
                                                       |
                      +--------------------------------+--------------------------------+
                      |                                |                                 |
                 risk engine                    detection engine                  graph engine
              (explainable score)           (rules + anomaly)                 (attack-path traversal)
                      |                                |                                 |
                      +--------------------------------+---------------------------------+
                                                       |
                                              REST API  ->  React UI
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full text component diagram and data flow.

## Repository layout

See [docs/ARCHITECTURE.md#repository-structure](docs/ARCHITECTURE.md) for the annotated tree.
Top level:

```
cmd/            # entrypoints: api, worker, collector, migrate
internal/       # core engine (models, store, graph, risk, detect, collectors, api)
migrations/     # versioned SQL schema
web/            # React + TypeScript dashboard
deploy/         # docker-compose, Dockerfiles, helm, terraform
fixtures/       # synthetic demo datasets
docs/           # design documentation
```

## License

Apache-2.0. See [LICENSE](LICENSE).
