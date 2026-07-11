# Kubernetes Collector

Discovers **non-human identities inside Kubernetes** — ServiceAccounts, their effective RBAC,
the pods that run as them, legacy token credentials — and, most importantly, the **cloud
federation edges** (EKS IRSA / GKE Workload Identity) that link a pod's identity to cloud
privileges. This turns "a pod is compromised" into a concrete, traversable attack path:

```
pod ─uses→ k8s ServiceAccount ─has_permissions→ effective RBAC ─binds_to→ cluster secrets (crown jewel)
                              └─federated_from→ AWS IAM role / GCP service account ─→ cloud crown jewels
```

## Two sources, one normalizer

The collector has two interchangeable sources feeding the **identical** normalization:

**1. Live cluster (client-go).** Collect straight from the API server using a kubeconfig or, in a
pod, in-cluster config (a read-only ServiceAccount is enough):

```bash
go run ./cmd/collector --provider k8s --cluster prod-us-east-1                 # in-cluster / default kubeconfig
go run ./cmd/collector --provider k8s --cluster prod-us-east-1 --kubeconfig ~/.kube/config
# or via the API (admin): {"provider":"k8s","cluster":"prod","kubeconfig":"/path"}  (or omit for in-cluster)
```

**2. kubectl export.** Dependency-free ingest of a `kubectl -o json` export — handy for CI or a jump
host without granting the platform live credentials:

```bash
kubectl get serviceaccounts,roles,clusterroles,rolebindings,clusterrolebindings,pods \
  -A -o json > cluster.json
go run ./cmd/collector --provider k8s --cluster prod-us-east-1 --k8s-export cluster.json
```

The account ref is `k8s:<cluster>`. Re-running is idempotent (deterministic UUIDv5 ids). The live
source lists ServiceAccounts, Roles/ClusterRoles, Role/ClusterRoleBindings, Pods, and token Secrets;
the required RBAC is read (`get`/`list`) on those resources.

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

- K8s audit-log ingestion for usage signals (anomaly detectors). Neither source carries audit
  events, so usage-based anomalies are AWS/GCP-only for now.
- Group subjects (`system:serviceaccounts:*`) — only direct `ServiceAccount` subjects are mapped.
