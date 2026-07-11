# IdentityAttackGraph API

REST over JSON. Base path `/api/v1`. Auth: `Authorization: Bearer <session-jwt>` (OIDC at edge).
RBAC roles: `viewer` (read), `analyst` (read + triage/remediation), `admin` (all + config + suppressions). 
All mutations are audited. Pagination is cursor-based (`?cursor=&limit=`).

A **GraphQL** read API is available at `/api/v1/graphql` (see below); REST remains authoritative.

> **Status:** every `/api/v1` route below is implemented. **RBAC is enforced** in `token` and
> `jwt` auth modes (viewer/analyst/admin); the default `off` mode leaves the API open for the demo.
> A Redis per-principal rate limiter and the Prometheus `/metrics` listener (separate port) are
> live. `POST /collect` enqueues onto **NATS JetStream** (worker consumes); it falls back to
> in-process if the queue is down. **OIDC JWKS auto-fetch** (RS256 keys by `kid`) and a **GraphQL**
> read API are implemented.

---

## Health & meta
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/healthz` | – | liveness |
| GET | `/readyz` | – | readiness (db/nats/redis) |
| GET | `/metrics` | – | Prometheus (internal listener) |
| GET | `/api/v1/version` | viewer | build + schema version |

## Inventory
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/api/v1/identities` | viewer | search/list. filters: `provider,kind,account,owner,env,state,min_risk,max_risk,stale,has_finding,is_ai_agent,q` |
| GET | `/api/v1/identities/{id}` | viewer | identity detail (owner, privileges, last_seen, last_rotated, trust, workloads, secrets, anomaly history, risk explanation) |
| GET | `/api/v1/identities/{id}/credentials` | viewer | credentials (metadata only) |
| GET | `/api/v1/identities/{id}/usage` | viewer | usage timeline (paginated) |
| GET | `/api/v1/identities/{id}/risk` | viewer | full 6-factor breakdown + signals |
| GET | `/api/v1/credentials` | viewer | credential inventory |
| GET | `/api/v1/secrets` | viewer | secret inventory |
| GET | `/api/v1/workloads` | viewer | workload inventory |
| GET | `/api/v1/repositories` | viewer | scanned repos |

## Graph & attack paths
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/api/v1/graph/neighborhood?node={id}&depth=` | viewer | subgraph around a node (nodes+edges) |
| GET | `/api/v1/identities/{id}/attack-paths` | viewer | ranked attack paths to crown-jewels/admin, node-by-node |
| GET | `/api/v1/identities/{id}/blast-radius` | viewer | reachable resources + criticality rollup |

## Findings & triage
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/api/v1/findings` | viewer | filters: `detector,severity,status,account,identity,min_confidence` |
| GET | `/api/v1/findings/{id}` | viewer | finding + evidence + narrative + timeline |
| PATCH | `/api/v1/findings/{id}` | analyst | update status (`triaged/resolved`), assignee, notes |
| POST | `/api/v1/findings/{id}/suppress` | admin | create audited suppression (reason + expiry) |
| GET | `/api/v1/triage` | viewer | top-N by remediation urgency (the triage queue) |

## Remediation
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/api/v1/findings/{id}/remediations` | viewer | recommended actions + projected risk delta |
| PATCH | `/api/v1/remediations/{id}` | analyst | set status (`planned/in_progress/done/wont_fix`) |
| GET | `/api/v1/metrics/risk-reduction` | viewer | risk removed over time from completed remediations |

## Jobs & collection
| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/api/v1/collect` | admin | trigger collection. provider ∈ `fixture\|aws\|gcp\|k8s\|repo` (e.g. `{"provider":"k8s","cluster":"prod","k8s_export":"/path/cluster.json"}`) |
| GET | `/api/v1/collector-runs` | analyst | recent runs, status, ingestion lag |
| GET | `/api/v1/snapshots` | viewer | snapshot history |

## Exports
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/api/v1/export/findings?format=json\|sarif\|csv` | analyst | export findings |
| GET | `/api/v1/export/inventory?format=json\|csv` | analyst | export inventory |

## Admin / config
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET/PUT | `/api/v1/config/risk-weights` | admin | view/update risk weights (audited, snapshot-pinned) |
| GET | `/api/v1/audit` | admin | audit log query |

## GraphQL

| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET/POST | `/api/v1/graphql` | viewer | GraphQL read API over inventory, findings, attack paths, and blast radius |

Queries: `identities(provider,kind,minRisk,limit)`, `identity(id)`, `findings(severity,status,detector,limit)`,
`triage(limit)`. The `identity` type resolves nested `findings`, `attackPaths { impact hops narrative steps }`,
and `blastRadius { crownJewelCount reachesAdmin nearestCrownJewel }`. Example:

```graphql
{ identities(minRisk: 60) {
    name riskScore
    attackPaths { impact hops narrative }
    blastRadius { crownJewelCount reachesAdmin }
} }
```

```bash
curl -XPOST localhost:8080/api/v1/graphql -H 'content-type: application/json' \
  -d '{"query":"{ triage { name riskScore findings { detector severity } } }"}'
```

---

## Representative payloads

`GET /api/v1/identities/{id}` (abridged):
```json
{
  "id": "8f3...", "kind": "aws_iam_user", "name": "svc-billing-export",
  "provider": "aws", "account_ref": "aws:123456789012", "state": "active",
  "owner": null,
  "last_seen_at": "2025-11-20T04:12:00Z", "last_rotated_at": null,
  "risk_score": 78, "severity": "critical",
  "risk_breakdown": {
    "composite": 78,
    "factors": {
      "privilege": {"score": 28, "signals": ["wildcard_action:s3:*", "write_crown_jewel"]},
      "exposure": {"score": 75, "signals": ["in_private_repo", "static_key_no_expiry"]},
      "freshness": {"score": 80, "signals": ["unused_200d", "rotation_unmanaged"]},
      "usage": {"score": 0, "signals": []},
      "trust": {"score": 0, "signals": []},
      "blast_radius": {"score": 75, "signals": ["reaches_crown_jewel_1hop"]}
    },
    "weights": {"privilege":0.22,"blast_radius":0.22,"exposure":0.20,"trust":0.14,"usage":0.12,"freshness":0.10}
  },
  "trust_relationships": [], "workloads": [], 
  "exposed_secrets": [{"repo":"acme/billing","path":".env","commit":"a1b2","verified":false}],
  "open_findings": [{"detector":"secret_exposed_in_repo","severity":"high","id":"f1..."}]
}
```

`GET /api/v1/identities/{id}/attack-paths` (abridged):
```json
{
  "paths": [{
    "rank": 1, "impact": "crown_jewel", "hops": 2,
    "narrative": "svc-billing-export can assume role billing-admin (no ExternalId), which has s3:* on prod-billing (crown_jewel).",
    "path": [
      {"node":"identity:svc-billing-export","via":null},
      {"node":"role:billing-admin","via":"assumes(conditionless)"},
      {"node":"resource:aws:s3:prod-billing","via":"binds_to(s3:*)","criticality":"crown_jewel"}
    ]
  }]
}
```
