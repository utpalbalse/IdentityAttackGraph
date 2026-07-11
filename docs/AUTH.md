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
# HS256:
export NHIID_AUTH_JWT_SECRET=...
# RS256 via JWKS auto-fetch (zero-config OIDC): set only the issuer, the JWKS URI is discovered.
export NHIID_AUTH_JWT_ISSUER=https://accounts.example.com
#   or point directly at the JWKS endpoint:
export NHIID_AUTH_JWT_JWKS_URL=https://accounts.example.com/.well-known/jwks.json
# RS256 with a static key instead: set auth.jwt_public_key_file (PEM)
# config: jwt_role_claim (default "role"), jwt_issuer, jwt_audience
curl -H "Authorization: Bearer <jwt>" localhost:8080/api/v1/identities
```

**JWKS auto-fetch** (`internal/auth/jwks.go`) is implemented: RS256 signing keys are fetched from
the issuer's `.well-known/openid-configuration` → `jwks_uri` (or the explicit `jwt_jwks_url`),
parsed and cached by `kid`, and refreshed on a cache miss (which is exactly what an IdP key rotation
looks like) or after a TTL — so validation keeps working across rotations with no restart. On a
transient fetch failure a still-cached key is served. A static `jwt_public_key_file` (PEM) remains
supported for airgapped setups. The validator runs behind the same `Authenticate` middleware.

## Notes

- Tokens are compared by exact match and never logged (the redacting log handler also scrubs
  bearer-shaped values).
- Health (`/healthz`, `/readyz`) and the Prometheus `/metrics` listener are unauthenticated by
  design (scrape/liveness); `/metrics` runs on a separate internal port (9090), not the public API.
