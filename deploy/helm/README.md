# NHIID Helm chart

Deploys the IdentityAttackGraph (NHIID) **api**, **worker**, and **web** to Kubernetes.
Postgres, Redis, and NATS are expected to be supplied externally (RDS / ElastiCache / managed
NATS) in production; optional in-cluster subcharts are bundled for dev/standalone use.

Chart path: `deploy/helm/nhiid`.

## What the chart creates

| Object | Purpose |
|--------|---------|
| `Deployment/<r>-api` (+ Service, optional HPA, PDB) | REST API on `:8080`, metrics on `:9090` |
| `Deployment/<r>-worker` (+ headless metrics Service) | graph/score/detect jobs + NATS consumer |
| `Deployment/<r>-web` (+ Service) | React UI on `:5173` (nginx) |
| `Job/<r>-migrate` (Helm pre-install/pre-upgrade hook) | runs `migrate up` before app pods |
| `ConfigMap/<r>-config` | renders `config.yaml`, mounted over the image default |
| `Secret/<r>-secret` | `database-dsn`, optional `jwt-secret` / `auth-tokens` |
| `ServiceAccount/<r>` | IRSA-annotatable identity for collectors |
| `Ingress` | optional; `/api` → api, `/` → web |
| `ServiceMonitor` | optional Prometheus Operator scrape of api + worker |

The DB DSN (and JWT secret) are injected as env (`NHIID_DATABASE_DSN`, `NHIID_AUTH_JWT_SECRET`)
from the Secret and override the mounted `config.yaml`; everything else comes from the ConfigMap.

## Quick start — self-contained (dev/standalone)

Brings up in-cluster Postgres + Redis + NATS via subcharts:

```bash
helm dependency update deploy/helm/nhiid
helm upgrade --install nhiid deploy/helm/nhiid \
  -n nhiid --create-namespace \
  --set postgresql.enabled=true \
  --set redis.enabled=true \
  --set nats.enabled=true

# seed the demo dataset (no cloud creds needed)
kubectl -n nhiid exec deploy/nhiid-worker -- collector --provider fixture --fixture fixtures/demo_env.json

kubectl -n nhiid port-forward svc/nhiid-web 5173:5173   # open http://localhost:5173
```

## Production (EKS)

Provision infra with [`deploy/terraform`](../terraform), then install with managed data stores.
See [`values-prod.example.yaml`](values-prod.example.yaml) for a complete example:

```bash
helm upgrade --install nhiid deploy/helm/nhiid -n nhiid --create-namespace \
  -f deploy/helm/values-prod.example.yaml
```

Key production values:
- `serviceAccount.annotations."eks.amazonaws.com/role-arn"` — Terraform `irsa_role_arn` output.
- `secrets.existingSecret` — a Secret synced from Secrets Manager (Terraform `db_dsn_secret_arn`)
  by the External Secrets Operator, containing `database-dsn`.
- `externalRedis.url` / `externalNats.url` — managed endpoints.
- `config.auth.mode: jwt` (or `token`) — **always enable auth outside a demo.**

## Validate before applying

```bash
helm lint deploy/helm/nhiid
helm template nhiid deploy/helm/nhiid -f deploy/helm/values-prod.example.yaml | kubectl apply --dry-run=client -f -
```

## Notes

- `config.auth.mode=off` (default) leaves the API open — intended only for local demos.
- The api/worker pods run read-only-rootfs as uid 10001 with all capabilities dropped; only
  `/tmp` is writable.
- Changing config or secrets rolls the api/worker pods automatically (checksum annotations).
