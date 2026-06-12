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
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, component diagram, data flow |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, threats, trust boundaries, mitigations |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | Unified schema, entities, graph model |
| [docs/RISK_MODEL.md](docs/RISK_MODEL.md) | Scoring formula, factor weights, rationale |
| [docs/DETECTIONS.md](docs/DETECTIONS.md) | Every detection, its logic, and evidence shape |
| [docs/API.md](docs/API.md) | REST API surface |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased milestone plan with acceptance criteria |
| [docs/MVP.md](docs/MVP.md) | MVP scope + non-goals |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Operating, troubleshooting, on-call |

## Quick start (local, one command)

```bash
make dev          # docker compose up: postgres, nats, redis, api, worker, web
make seed         # load synthetic multi-account AWS+GCP fixture (no cloud creds needed)
open http://localhost:5173
```

The seed dataset includes:
- Orphaned access keys
- Over-privileged service accounts
- Cross-account assume-role chains
- Credentials exposed in repositories
- Detections fire without any real cloud credentials

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
