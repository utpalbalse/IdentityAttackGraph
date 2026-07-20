# Demo — from zero to a narrated attack path in one command

No cloud credentials required. Everything runs against synthetic fixtures that model a real
multi-account AWS + GCP + Kubernetes environment with the mistakes attackers actually exploit.

```bash
make dev      # bring up postgres, redis, nats, api, worker, web
make demo     # seed AWS+GCP+K8s fixtures, run graph/score/detect, print the attack simulation
```

`make demo` ends by running `simulate`, which reads the **live attack graph** and narrates the
worst paths it finds — foothold → capability hops → crown jewel — with the detections that caught
each and the single remediation that severs it:

```text
  IdentityAttackGraph — Attack-Path Simulation
  ─────────────────────────────────────────────
  12 identities · 26 graph nodes · 18 edges · 5 crown jewels

━━━ Scenario 1 · Leaked credential → crown jewel
  target  svc-billing-export  (risk 70)
  RECON   attacker finds credential material at .env:12 (pattern aws_akia) — belongs to svc-billing-export
  STEP 0  ▸ svc-billing-export [identity]
  STEP 1  → assumes role billing-admin [role] ▲ high
  STEP 2  → gains access to arn:aws:s3:::prod-billing [resource] ◆ CROWN JEWEL
  IMPACT  1 crown jewel(s) reachable · nearest crown jewel 2 hop(s) · reaches admin: true
  CAUGHT  secret_exposed_in_repo (critical), suspicious_role_chain (high),
          conditionless_assume_role (high), high_blast_radius (high), over_privileged_sa (high), …
  FIX     reduce_scope  →  risk 70→33 (−37)

━━━ Scenario 2 · Over-scoped AI agent
  target  prod-copilot-agent  (risk 39)
  AGENT   framework=langchain model=gpt-4o ttl=720h broad_scope=true uncontrolled_tools=true
  STEP 0  ▸ prod-copilot-agent [identity]
  STEP 1  → wields the permissions of prod-copilot-agent [role] ▲ high
  STEP 2  → gains access to arn:aws:secretsmanager:…:secret:prod/app/master [resource] ◆ CROWN JEWEL
  IMPACT  1 crown jewel(s) reachable · reaches admin: true
  CAUGHT  ai_agent_overscoped (high), high_blast_radius (high), over_privileged_sa (high), …
  FIX     reduce_scope  →  risk 39→2 (−37)
```

(Full output: [samples/attack_simulation.txt](samples/attack_simulation.txt); JSON:
[samples/attack_simulation.json](samples/attack_simulation.json).)

## What the demo dataset contains

| Storyline | Identities | The problem | Detections that fire |
|-----------|-----------|-------------|----------------------|
| **Leaked key → crown jewel** | `svc-billing-export` (AWS user) → `billing-admin` role → `s3:prod-billing` | Access key committed to a repo `.env`; role assumable with **no ExternalId**; role has `s3:*` on a crown-jewel bucket | `secret_exposed_in_repo`, `conditionless_assume_role`, `over_privileged_sa`, `high_blast_radius`, plus anomaly signals (`impossible_travel`, `first_use_sensitive_action`) |
| **Over-scoped AI agent** | `prod-copilot-agent` (`ai_agent`) → Secrets Manager secret | 720h token, broad API scope, uncontrolled tools, admin role reaching a crown-jewel secret | `ai_agent_overscoped`, `over_privileged_sa`, `high_blast_radius` |
| **Cross-cloud workload identity** | `prod/deployer` (K8s SA) → cluster-admin → cluster secrets; **IRSA edge** to an AWS role | A pod bound to `cluster-admin` and federated into AWS via IRSA | `over_privileged_sa`, `high_blast_radius` (+ the `federated_from` edge that would extend into AWS once the AWS collector runs) |
| **GCP impersonation** | `ci-deployer` can impersonate `data-processor` (owner of the project) | Impersonation into a project-owner SA | `high_blast_radius`, `over_privileged_sa` |
| **Hygiene** | `svc-orphaned`, stale keys | No owner/workload; unused long-lived keys | `orphaned_identity`, `stale_access_key` |

## Then explore

- **Web UI** — <http://localhost:5173>: inventory sorted by risk, the triage queue, an identity's
  6-factor risk breakdown, and the **Cytoscape attack-graph** view.
- **API** — `curl localhost:8080/api/v1/triage`, `.../identities/{id}/attack-paths`,
  `.../identities/{id}/blast-radius`.
- **Exports** — `.../export/findings?format=sarif` (see [samples/](samples/)).
- **Remediation** — `PATCH .../remediations/{id}` to `done`, then watch
  `.../metrics/risk-reduction` update.

## Run it against real clouds

Swap the fixture for a live collector — same pipeline, same graph, same detections:

```bash
collector --provider aws --role-arn <arn> --external-id <id>      # see docs/AWS_COLLECTOR.md
collector --provider gcp --project <id>                            # see docs/GCP_COLLECTOR.md
kubectl get sa,roles,clusterroles,rolebindings,clusterrolebindings,pods -A -o json > c.json
collector --provider k8s --cluster prod --k8s-export c.json        # see docs/K8S_COLLECTOR.md
```

With AWS + K8s both collected, the IRSA `federated_from` edge connects **pod → AWS role → crown
jewel** into a single cross-cloud attack path.
