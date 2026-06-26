# Kubernetes Collector

Discovers **non-human identities inside Kubernetes** — ServiceAccounts, their effective RBAC,
the pods that run as them, legacy token credentials — and, most importantly, the **cloud
federation edges** (EKS IRSA / GKE Workload Identity) that link a pod's identity to cloud
privileges. This turns "a pod is compromised" into a concrete, traversable attack path:

```
pod ─uses→ k8s ServiceAccount ─has_permissions→ effective RBAC ─binds_to→ cluster secrets (crown jewel)
                              └─federated_from→ AWS IAM role / GCP service account ─→ cloud crown jewels
```

## Input: a cluster export

The collector ingests a `kubectl -o json` export. This keeps it dependency-free and lets it run
from anywhere with kubeconfig access (CI, a jump host) without granting the platform live cluster
credentials. Produce the export with one command:

```bash
kubectl get serviceaccounts,roles,clusterroles,rolebindings,clusterrolebindings,pods \
  -A -o json > cluster.json
```

Then collect:

```bash
go run ./cmd/collector --provider k8s --cluster prod-us-east-1 --k8s-export cluster.json
# or via the API (admin):
curl -XPOST localhost:8080/api/v1/collect \
  -d '{"provider":"k8s","cluster":"prod-us-east-1","k8s_export":"/path/cluster.json"}'
```

The account ref is `k8s:<cluster>`. Re-running is idempotent (deterministic UUIDv5 ids).

## What it normalizes

| Source object | Becomes |
|---------------|---------|
| `ServiceAccount` | identity (`k8s_service_account`), `k8s:<cluster>/<ns>/<name>` |
| `Role` / `ClusterRole` (via bindings) | aggregated into one **effective permission set** per SA |
| `RoleBinding` / `ClusterRoleBinding` | the binding that grants those rules (scoped) |
| `Pod.spec.serviceAccountName` | workload (`k8s_pod`) → `uses` → identity |
| SA token secrets | credential (`k8s_sa_token`) |
| `eks.amazonaws.com/role-arn` annotation | `federated_from` trust edge → AWS IAM role |
| `iam.gke.io/gcp-service-account` annotation | `federated_from` trust edge → GCP service account |

Each ServiceAccount's bound (Cluster)Roles are aggregated into **one permission set owned by that
SA** — the same model the AWS/GCP collectors use — so the privilege risk factor, the
`over_privileged_sa` detector, and the `has_permissions` graph edge all work without K8s-specific
special cases.

## RBAC privilege analysis

The collector classifies a ServiceAccount's effective privilege from its rules:

- **admin** — cluster-wide `*/*/*` (cluster-admin equivalent). Emits a crown-jewel resource binding.
- **privileged** — RBAC self-escalation (`bind`/`escalate`/`impersonate`, or write on
  roles/rolebindings), cluster-wide **secret read** (credential theft primitive), `pods/exec`,
  or namespace-admin.
- **write** — create/update/patch/delete on resources.
- **read** — only get/list/watch.

Sensitive capabilities also become **resource bindings** so they show up in blast-radius and
attack-path traversal: cluster-wide secret read → `k8s:<cluster>:cluster:secrets` (crown jewel),
namespaced secret read → high, `pods/exec` → high.

Bindings to well-known built-in cluster roles that aren't in the export (`cluster-admin`, `admin`,
`edit`, `view`) are still resolved via their known rule shapes, so the edge connects.

## Cloud federation (the cross-cloud attack path)

When a ServiceAccount is annotated for IRSA or Workload Identity, the collector emits a
`federated_from` trust edge to the cloud principal, **using the same deterministic id the AWS/GCP
collector assigns** (`DeterministicID("aws_iam_role", arn)` / `DeterministicID("gcp_service_account",
email)`). A thin **stub identity** is emitted for that target so the edge's referential integrity
holds even if the cloud collector hasn't run yet; when it does run, it reconciles onto the same row
(keyed by `provider, external_id`) and the stub fills out into the real principal — extending the
attack path from the pod all the way into cloud crown jewels.

## What fires on it

The generic detectors apply with no K8s special-casing — e.g. a ServiceAccount bound to
cluster-admin raises `over_privileged_sa` and `high_blast_radius` (it reaches cluster secrets and an
admin role); a stale `k8s_sa_token` raises `stale_access_key`.

## Not yet

- Live `client-go` source (kubeconfig / in-cluster) — the normalization is identical; only the
  object source differs.
- K8s audit-log ingestion for usage signals (anomaly detectors). The export path carries no audit
  events, so usage-based anomalies are AWS/GCP-only for now.
- Group subjects (`system:serviceaccounts:*`) — only direct `ServiceAccount` subjects are mapped.
