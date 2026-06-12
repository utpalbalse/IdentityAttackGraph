# IdentityAttackGraph Threat Model

Methodology: asset-centric + STRIDE on trust boundaries. IdentityAttackGraph is a security tool 
that holds a map of an organization's most sensitive identities; compromising it would be a 
force-multiplier, so the tool itself is modeled as a high-value target.

---

## 1. Assets

| # | Asset | Why it matters |
|---|-------|----------------|
| A1 | Identity inventory + graph | A complete map of every NHI, its privileges, and reachable blast radius. A roadmap for an attacker. |
| A2 | Secret-exposure findings | Pointers to where real credential material leaked (repo, CI, artifact). |
| A3 | NHIID's own cloud access (IRSA role / read roles in target accounts) | Read access to IAM/CloudTrail across the org. |
| A4 | Postgres system-of-record | All normalized data + provenance + audit log. |
| A5 | Detection logic & suppressions | If an attacker can edit suppressions, they blind the tool. |
| A6 | API tokens / operator sessions | Access to all of the above. |

**Design rule:** NHIID stores **no long-lived target-cloud credentials** and **never the secret
material itself** — only metadata, fingerprints, and locations. Findings reference *where* a
secret is, not its value.

---

## 2. Trust boundaries

```
[ Operator browser ] --TLS/OIDC--> [ ALB ] --> [ API ]  ── boundary B1 (external auth)
[ API ] --> [ Postgres / Redis / NATS ]                 ── boundary B2 (data tier)
[ Worker ] --assume-role/WIF--> [ Target AWS/GCP ]      ── boundary B3 (cross-account)
[ Repo scanner ] --token--> [ GitHub/GitLab ]           ── boundary B4 (SCM)
[ Worker ] <--jobs-- [ NATS ]                           ── boundary B5 (job integrity)
```

---

## 3. STRIDE by boundary

### B1 — External (operator ↔ API)
- **Spoofing:** OIDC/SSO at the edge; short-lived signed session tokens; no static API passwords.
- **Tampering:** TLS everywhere; CSRF protection on state-changing routes.
- **Repudiation:** Every state change writes an `audit_log` row (actor, action, target, before/after).
- **Information disclosure:** RBAC (viewer/analyst/admin); object-level authz on findings/exports.
- **DoS:** Rate limiting at edge + per-token; pagination caps; query timeouts.
- **EoP:** Role checks enforced server-side on every handler, never trusted from the client.

### B2 — Data tier (API/worker ↔ stores)
- Postgres/Redis/NATS reachable only inside the cluster network (no public ingress).
- TLS to RDS; credentials from a secret store / IRSA, never in images or env-dumped logs.
- Principle of least privilege DB roles: API uses a role that cannot DROP/ALTER.

### B3 — Cross-account collection (worker ↔ target cloud) **[highest risk]**
- **Least privilege:** target roles are read-only (`SecurityAudit` + explicit `Get*/List*/Describe*`).
  No `secretsmanager:GetSecretValue` on secret bodies — we read metadata/ARNs only.
- **No standing creds:** STS assume-role with `ExternalId` + session tagging; GCP workload identity
  federation. Tokens are short-lived and never persisted.
- **Tamper-evidence:** all collector activity is itself logged in the target's CloudTrail; NHIID
  records `collector_run` provenance to reconcile.
- **Blast-radius containment:** a compromised NHIID can *read* a lot, so target trust policies
  pin the exact NHIID principal + ExternalId; rotation runbook exists.

### B4 — SCM scanning (worker ↔ GitHub/GitLab)
- Scanner token is read-only, scoped to required orgs; stored in the secret store.
- Secret material discovered in repos is **fingerprinted, not stored**; the finding records
  repo+path+commit+line, never the secret value. Verified-vs-unverified is tracked.

### B5 — Job integrity (NATS)
- JetStream with auth; workers validate job schema + provenance; jobs are idempotent so a
  replayed/poisoned job cannot corrupt state (upserts keyed by external_id).

---

## 4. Top threats & mitigations (ranked)

| Risk | Threat | Mitigation |
|------|--------|------------|
| **Critical** | Compromise of NHIID → org-wide identity map + read access | No standing target creds; least-priv read roles pinned to ExternalId; encrypted store; full audit; secret bodies never read/stored. |
| **High** | Secret-exposure findings leak the secrets they describe | Findings store location + fingerprint only; secret values never persisted or logged; redacting log handler. |
| **High** | Attacker edits suppressions/detections to blind the tool | Suppression changes are admin-only, audited, and version-pinned to snapshots; alert on suppression churn. |
| **High** | Over-broad collector IAM role | Hard-coded least-privilege policy in Terraform; CI lints the policy; deny `GetSecretValue`/`kms:Decrypt`. |
| **Medium** | Stale/poisoned data → false confidence | Provenance + `collected_at` surfaced in UI; ingestion-lag metric + alert; snapshots immutable. |
| **Medium** | PII / sensitive identifiers in inventory | Field-level classification; redaction in exports per role; retention policy. |
| **Medium** | Supply-chain (deps) | Pinned modules, `go vet`/`govulncheck` in CI, SBOM, signed images. |
| **Low** | Operator phishing | OIDC/SSO + MFA at edge; short sessions; admin actions re-prompt. |

---

## 5. Security requirements that fall out of this

1. Secret material is **never** stored, logged, or returned by the API — only fingerprints/locations.
2. The collector IAM/GCP policy is least-privilege read-only and CI-enforced.
3. All target access is short-lived (assume-role / WIF); zero long-lived target creds at rest.
4. RBAC + object-level authz on every API route; all mutations audited.
5. A redacting `slog` handler scrubs known secret-shaped values from logs.
6. Stores are private-network only, encrypted at rest and in transit.
7. Detections/suppressions are admin-gated, audited, and version-pinned to snapshots.
8. Ingestion lag and collector errors are monitored and alertable (stale data is a security risk).
