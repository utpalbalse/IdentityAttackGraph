# Authentication & RBAC

The API supports bearer-token RBAC. Implementation: [internal/auth](../internal/auth/auth.go).

## Modes

| Mode | Behavior |
|------|----------|
| `off` (default) | API is open — the demo and UI work unauthenticated. The audit actor comes from the `X-Actor` header (default `anonymous`). |
| `token` | Requests must send `Authorization: Bearer <token>`. Each token maps to a `subject` + `role`. Unknown/missing token → `401`; insufficient role → `403`. The audit actor is the token's subject. |
| `jwt` | Validate an OIDC bearer **JWT** — HS256 (shared secret) or RS256 (IdP public key, PEM). Signature, `exp`, and optional `iss`/`aud` are checked; the role comes from a configurable claim (string or `groups` array). |

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

## OIDC / JWT

JWT validation is implemented (`mode: jwt`) for both HS256 and RS256:

```bash
export NHIID_AUTH_MODE=jwt
export NHIID_AUTH_JWT_SECRET=...           # HS256, or set auth.jwt_public_key_file for RS256
# config: jwt_role_claim (default "role"), jwt_issuer, jwt_audience
curl -H "Authorization: Bearer <jwt>" localhost:8080/api/v1/identities
```

With RS256 you paste the IdP's signing public key (PEM) and set `jwt_issuer`/`jwt_audience` — this
is interoperable with any OIDC provider. The one remaining step for zero-config OIDC is **JWKS
auto-fetch + key rotation** (discover keys from the IdP's `/.well-known/jwks.json`); the validator
already runs behind the same `Authenticate` middleware, so adding it touches no handlers.

## Notes

- Tokens are compared by exact match and never logged (the redacting log handler also scrubs
  bearer-shaped values).
- Health (`/healthz`, `/readyz`) and the Prometheus `/metrics` listener are unauthenticated by
  design (scrape/liveness); `/metrics` runs on a separate internal port (9090), not the public API.
