# Authentication & RBAC

The API supports bearer-token RBAC. Implementation: [internal/auth](../internal/auth/auth.go).

## Modes

| Mode | Behavior |
|------|----------|
| `off` (default) | API is open — the demo and UI work unauthenticated. The audit actor comes from the `X-Actor` header (default `anonymous`). |
| `token` | Requests must send `Authorization: Bearer <token>`. Each token maps to a `subject` + `role`. Unknown/missing token → `401`; insufficient role → `403`. The audit actor is the token's subject. |

Set via config (`auth.mode`) or `NHIID_AUTH_MODE`.

## Roles (hierarchical: viewer < analyst < admin)

| Role | Can access |
|------|-----------|
| `viewer` | all reads — inventory, graph, attack-paths, findings, triage, snapshots, risk-reduction |
| `analyst` | viewer **+** triage/remediation `PATCH`, exports, collector-runs |
| `admin` | analyst **+** `POST /collect`, finding suppression, `config/risk-weights`, `audit` |

Per-route minimums are enforced in the router ([cmd/api/main.go](../cmd/api/main.go)).

## Configuring tokens (token mode)

Provide tokens as a JSON array, via env or a file:

```bash
export NHIID_AUTH_MODE=token
export NHIID_AUTH_TOKENS='[
  {"token":"viewer-secret","subject":"sara@sec","role":"viewer"},
  {"token":"analyst-secret","subject":"raj@sec","role":"analyst"},
  {"token":"admin-secret","subject":"alice@sec","role":"admin"}
]'
```

or `auth.tokens_file: /etc/nhiid/tokens.json` (same JSON shape).

```bash
# viewer can read but not export
curl -H "Authorization: Bearer viewer-secret"  localhost:8080/api/v1/identities      # 200
curl -H "Authorization: Bearer viewer-secret"  localhost:8080/api/v1/export/findings  # 403
curl -H "Authorization: Bearer admin-secret"   localhost:8080/api/v1/audit            # 200
curl                                            localhost:8080/api/v1/identities      # 401
```

## OIDC / JWT (production path)

Static tokens are intended for service-to-service and bootstrap use. The production design is OIDC:
an SSO proxy or the API validates an RS256 JWT against the IdP's JWKS, maps a claim (e.g. `groups`)
to a role, and the same `Authenticate` middleware yields the `Principal`. This slots in behind the
existing interface without touching handlers; it is **not yet implemented** (tracked on the roadmap).

## Notes

- Tokens are compared by exact match and never logged (the redacting log handler also scrubs
  bearer-shaped values).
- Health (`/healthz`, `/readyz`) and the Prometheus `/metrics` listener are unauthenticated by
  design (scrape/liveness); `/metrics` runs on a separate internal port (9090), not the public API.
