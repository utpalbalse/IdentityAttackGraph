# NHIID — Non-Human Identity Inventory & Detection

> Discover, inventory, normalize, score, and detect abuse of **non-human identities** (NHIs)
> — service accounts, access keys, API tokens, workload identities, secrets, certificates,
> and AI-agent identities — across multi-account AWS and multi-project GCP.

NHIID answers six questions a security team actually asks during an incident or audit:

1. **What** machine identities exist?
2. **Where** are they used (which workloads, repos, resources)?
3. **Which** are over-privileged, stale, or orphaned?
4. **Which** are behaving abnormally **right now**?
5. **What** is the blast radius if one is compromised?
6. **What** should we remediate first, and how much risk does that remove?

This is a **from-scratch** platform. The inventory model, normalization, graph engine,
risk scoring, attack-path reasoning, and detection logic are all implemented here — not a
wrapper around Semgrep/Wazuh/Suricata. We integrate with cloud provider APIs for collection
only.

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

The seed dataset ships a realistic environment — orphaned access keys, an over-privileged
GCP service account, a cross-account assume-role chain, and a secret leaked into a repo — so
you can see detections fire without touching a real cloud account.

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
