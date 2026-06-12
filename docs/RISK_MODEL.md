# IdentityAttackGraph Risk Model

Risk is **transparent and tunable**. Every identity's composite score is a weighted sum of six
sub-scores, each in `[0,100]`, each itself explainable down to the contributing signals. No
hidden ML in the score — anomaly detections feed the *usage* factor as discrete, evidenced signals.

The canonical weights live in [configs/risk_weights.yaml](../configs/risk_weights.yaml) and are
hot-loadable. The reference implementation is [internal/risk/](../internal/risk/).

---

## 1. Composite formula

```
composite = clamp_0_100(
    Σ ( weight_f × subscore_f )   for f in {privilege, exposure, freshness, usage, trust, blast}
)
```

Default weights (sum = 1.0):

| Factor | Weight | Why this weight |
|--------|-------:|-----------------|
| `privilege`   | 0.22 | Over-permission is the most common and most exploitable NHI problem. |
| `blast_radius`| 0.22 | What an identity can *reach* (incl. via chaining) is the true impact. |
| `exposure`    | 0.20 | A leaked/exposed credential is pre-compromise; weight it heavily. |
| `trust`       | 0.14 | Broad/condition-free trust = lateral-movement fuel. |
| `usage`       | 0.12 | Anomalous/abnormal use is a live signal but noisier; weight modestly. |
| `freshness`   | 0.10 | Stale/unrotated raises likelihood but is lower direct impact. |

Rationale for the split: **impact factors** (privilege + blast = 0.44) and **pre-compromise
exposure** (0.20) dominate, because NHIID's job is to prevent incidents, not just chase noise.
Live-behavior `usage` is meaningful but kept below impact factors to suppress false positives.

Severity bands: `0–24 low · 25–49 medium · 50–74 high · 75–100 critical`.

---

## 2. Sub-score definitions

Each sub-score is `clamp_0_100(Σ signal_points)`. Signals are additive and capped so one signal
can't dominate. All thresholds are config-driven.

### 2.1 Privilege score
Measures permission breadth relative to need.
| Signal | Points |
|--------|-------:|
| Has `admin`/`*:*` or `iam:*` | +60 |
| Wildcard action in any policy (`s3:*`) | +8 each (cap 24) |
| Wildcard resource (`Resource:*`) | +6 each (cap 18) |
| Can perform privilege-escalation action (e.g. `iam:PassRole`, `iam:CreatePolicyVersion`, GCP `setIamPolicy`) | +20 |
| Permission count > peer-group P90 (privilege creep) | +15 |
| Write access to crown-jewel resource | +20 |

### 2.2 Exposure score
Pre-compromise credential exposure.
| Signal | Points |
|--------|-------:|
| Credential material found in **public** repo | +80 |
| In private repo / CI variable / artifact | +45 |
| Verified-live exposed credential | +20 (additive to above) |
| Long-lived static key (no expiry) exists | +20 |
| Secret with rotation disabled | +15 |
| Key/secret older than `max_cred_age` | +10 |

### 2.3 Freshness score
Staleness & rotation hygiene.
| Signal | Points |
|--------|-------:|
| No usage in `stale_window` (default 90d) | +40 |
| Never used since creation, age > 30d | +30 |
| Credential not rotated in `max_rotation_age` (default 180d) | +25 |
| `last_rotated_at` unknown / rotation unmanaged | +15 |

### 2.4 Usage score
Anomalous live behavior. Fed by detection-engine signals (each is evidenced).
| Signal | Points |
|--------|-------:|
| Impossible travel observed | +35 |
| First-seen new region/country | +20 |
| New ASN / new runtime | +15 |
| Sudden volume spike (>Nσ over baseline) | +20 |
| First-ever use of a sensitive action (e.g. `iam:*`, `kms:Decrypt`) | +25 |
| Off-hours burst for an otherwise-scheduled identity | +10 |

### 2.5 Trust score
Trust-relationship exposure.
| Signal | Points |
|--------|-------:|
| Assumable with **no condition** (no ExternalId/MFA/IP) | +40 |
| Cross-account trust | +20 |
| Trusts a wildcard / external principal | +30 |
| Part of an assume-role chain of depth ≥ 2 | +15 |
| Can mint tokens / impersonate other identities | +20 |

### 2.6 Blast-radius score
Reachable impact, computed by the **graph engine** (incl. multi-hop chaining).
| Signal | Points |
|--------|-------:|
| Can reach a `crown_jewel` resource (≤1 hop) | +60 |
| Can reach crown-jewel via chain (2–3 hops) | +40 |
| Reaches `high`-criticality resources (count-scaled) | +5 each (cap 30) |
| Reachable-resource count > P90 | +15 |
| Can escalate to admin via a path | +30 |

---

## 3. Worked example

An orphaned AWS IAM user with an access key unused for 200 days, holding `s3:*` on a prod bucket
tagged crown-jewel, key found in a private repo:

```
privilege : admin? no · s3:* wildcard +8 · write to crown-jewel +20            = 28
exposure  : in private repo +45 · static key no-expiry +20 · key>maxage +10    = 75
freshness : unused 200d +40 · not rotated +25 · rotation unmanaged +15  = 80 -> 80
usage     : (no live anomalies)                                                = 0
trust     : (no assume relationships)                                          = 0
blast     : reaches crown-jewel ≤1 hop +60 · reachable>P90 +15                 = 75

composite = 0.22*28 + 0.20*75 + 0.10*80 + 0.12*0 + 0.14*0 + 0.22*75
          = 6.16 + 15.0 + 8.0 + 0 + 0 + 16.5 = 45.66  -> rounded 46  (MEDIUM)
```

The exposure + blast factors are what an analyst sees first in the breakdown, with the exact
signals listed — so the "why" is immediate.

---

## 4. Remediation urgency

Urgency is **not** the same as the score — it blends score with exploitability/ease:

```
urgency = composite
          + 15 if exposure_verified_live
          + 10 if reachable_crown_jewel
          + 10 if publicly_exposed
          - 10 if behind_strong_trust_condition
```

Triage queue sorts by urgency, then composite. This pushes "leaked key that reaches prod" above
"merely over-privileged but unreachable" even at equal composite scores.

---

## 5. Tuning & governance

- All weights/thresholds live in YAML and are reloadable; changes are audited and snapshot-pinned.
- Per-environment overrides (prod stricter than dev) supported via config scopes.
- Peer-group baselines (for privilege creep / reachable-count P90) are computed per
  `(account, identity-kind)` cohort and recomputed on each scoring run.
- Scores are reproducible: re-scoring a snapshot with the same weights yields identical results.
