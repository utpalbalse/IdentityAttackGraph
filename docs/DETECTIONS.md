# IdentityAttackGraph Detections

Every detection is **custom-built**, **explainable**, and emits a `finding` with: stable `detector` id,
`severity`, structured `evidence`, and a human-readable **attack narrative**. Detectors are
either **rule-based** (deterministic over current state) or **anomaly-based** (statistical over
usage history with per-identity/peer baselines). All support suppression + dedupe by fingerprint.

Reference implementation: [internal/detect/](../internal/detect/).

---

## Detector catalog

| id | type | severity | subject |
|----|------|----------|---------|
| `orphaned_identity` | rule | medium | identity |
| `stale_identity` | rule | low–medium | identity |
| `stale_access_key` | rule | medium | credential |
| `unused_secret` | rule | low | secret |
| `over_privileged_sa` | rule | high | identity |
| `privilege_creep` | anomaly | medium | identity |
| `wildcard_trust` | rule | high | role/identity |
| `conditionless_assume_role` | rule | high | trust_edge |
| `suspicious_role_chain` | anomaly | high | trust path |
| `unusual_geo` | anomaly | medium | usage |
| `impossible_travel` | anomaly | high | usage |
| `new_asn_or_runtime` | anomaly | low–medium | usage |
| `usage_spike` | anomaly | medium | usage |
| `first_use_sensitive_action` | anomaly | high | usage |
| `secret_exposed_in_repo` | rule | high–critical | secret/cred |
| `high_blast_radius` | rule | high | identity |
| `ai_agent_overscoped` | rule | high | ai_agent |

---

## Rule detectors (logic)

### orphaned_identity
**Definition:** identity exists and is `active`, but has **no** valid mapping to a workload, a
repo, or an owner, AND is not itself a workload principal.
**Logic:** `owner_id IS NULL AND NOT EXISTS(workload uses identity) AND NOT EXISTS(repo exposes)
AND last_seen older than grace`. Excludes break-glass identities via allowlist tag.
**Evidence:** missing-mapping flags, creation date, last_seen, account.
**Narrative:** "Identity X has no owner, no workload running as it, and no repo reference. It is
unaccounted for — a classic abandoned credential an attacker can use without anyone noticing."

### stale_identity / stale_access_key
**Definition:** no legitimate usage in `stale_window` (default 90d), or `last_used_at` null and
`age > 30d`. For keys, uses CloudTrail `last_used` + key `last_used_at`.
**Evidence:** last_seen, age, window. **Narrative:** dormant credential = unmonitored attack surface.

### unused_secret
**Definition:** managed secret with `referenced_by_count = 0` and no access within the staleness
window (or never accessed). Raised by a dedicated pass over the secret inventory (identity-agnostic,
like repo-scoped exposures), not a per-identity detector.
**Evidence:** store, external id, name, last access, reference count — never the secret value.
Implemented in [internal/detect/secret.go](../internal/detect/secret.go).

### over_privileged_sa
**Definition:** identity holds `admin`/`*:*`/`iam:*`, OR write to crown-jewel, OR a
privilege-escalation action (`iam:PassRole`+`lambda:CreateFunction`, `iam:CreatePolicyVersion`,
GCP `iam.serviceAccounts.actAs`/`setIamPolicy`).
**Evidence:** the exact statements/actions matched, resource criticality.
**Narrative:** describes the concrete escalation primitive available.

### wildcard_trust / conditionless_assume_role
**Definition:** trust policy principal is `*` or external, or an assume relationship has **no**
condition (no ExternalId/MFA/IP/org). Cross-account amplifies severity.
**Evidence:** trust_policy json, missing conditions, src/dst accounts.

### secret_exposed_in_repo
**Definition:** credential material fingerprint discovered by the repo scanner matches a known
credential/secret, OR matches high-confidence provider patterns (AWS AKIA, GCP SA JSON,
PEM private key, bearer tokens) with entropy + context checks. **Severity escalates to critical
for public repos and verified-live creds.**
**Evidence:** repo, path, commit, line, pattern, verified flag — **never the secret value**.
**Narrative:** the exposure path and what the credential can reach (joined with blast radius).

### high_blast_radius
**Definition:** graph engine finds the identity can reach a `crown_jewel` (≤ N hops) or can
escalate to admin via a path.
**Evidence:** the literal path (node-by-node) returned by the attack-path traversal.

### ai_agent_overscoped
**Definition:** `is_ai_agent` AND (broad API scope OR TTL > threshold OR weak scoping OR
unrestricted tool access per `ai_agent_meta`).
**Evidence:** granted scopes/tools, TTL, missing constraints.
**Narrative:** an autonomous agent with broad, long-lived, weakly-scoped access is a
high-consequence target; describes the over-grant.

---

## Anomaly detectors (logic)

All anomaly detectors operate over `usage_events` with a **baseline** built per identity (and
fall back to peer-group when an identity is new). Baselines store: known regions/countries,
known ASNs, known runtimes, hourly volume distribution (mean/σ), and known sensitive actions.

### unusual_geo / new_asn_or_runtime
First observation of a region/country/ASN/runtime not in the identity's baseline set (with a
warm-up period to avoid flagging brand-new identities). Confidence scales with baseline maturity.

### impossible_travel
Two authenticated events from geographically distant locations within a time window that implies
travel speed > `max_kmh` (default ~900 km/h). Uses geo-IP centroids; ignores known VPN/egress
ranges via allowlist. **Evidence:** the two events, distance, implied speed.

### usage_spike
Event volume in a window exceeds `mean + Nσ` (default N=4) of the identity's hourly baseline,
or exceeds a hard floor multiple. Robust to low-volume identities via a minimum-events guard.

### first_use_sensitive_action
First-ever invocation (per baseline) of an action in the sensitive set (`iam:*`, `kms:Decrypt`,
`sts:AssumeRole` to a new target, `secretsmanager:GetSecretValue`, GCP `setIamPolicy`).
High severity because first-time privilege use often marks the pivot in an intrusion.

### privilege_creep
Current permission count (or reachable-resource count) exceeds the identity's own historical
baseline by `creep_factor`, **or** exceeds peer-group P90. Distinguishes "granted more" from
"used more". **Evidence:** before/after permission sets, peer P90.

### suspicious_role_chain
Anomalous assume-role / impersonation / federation **sequence**: an attack path with ≥1 trust
pivot (`assumes`/`impersonates`/`federated_from`/`can_mint_token`) spanning ≥2 hops that reaches
higher privilege (admin or crown-jewel) than any single direct grant — i.e. lateral movement, not a
direct binding. The graph engine's attack-path traversal supplies the candidate chains; observed
assume/impersonate `usage_events` corroborate and raise confidence (66 → 82).
**Evidence:** the capability edge sequence, trust-hop count, impact, and observed-pivot count.
Implemented in [internal/detect/rolechain.go](../internal/detect/rolechain.go).

---

## False-positive controls

- **Warm-up:** anomaly detectors require a minimum baseline maturity before firing.
- **Allowlists:** known egress ranges, VPN ASNs, break-glass identities, scheduled batch windows.
- **Corroboration:** several detectors require ≥2 signals (e.g. geo anomaly + sensitive action).
- **Suppression:** admin-gated, audited, snapshot-pinned suppressions with expiry.
- **Dedupe:** stable `fingerprint` per (detector, subject, salient-evidence) collapses repeats;
  findings re-surface only on materially new evidence.
- **Confidence:** every finding carries a confidence derived from baseline maturity + signal count;
  the UI lets analysts filter low-confidence.
