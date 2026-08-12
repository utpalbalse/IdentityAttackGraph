# Security Policy

IdentityAttackGraph is a security tool that reads privileged inventory from cloud accounts, so the
bar for its own security is high. This document covers how to report a vulnerability and what the
project guarantees about its own behaviour.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately via GitHub's [private vulnerability
reporting](https://github.com/utpalbalse/IdentityAttackGraph/security/advisories/new) — the
**Security → Report a vulnerability** button on the repository. That opens a channel visible only to
the maintainers.

Helpful things to include: affected version or commit, the component (collector, API, worker, web),
reproduction steps or a proof of concept, and the impact you believe it has.

This is a personal open-source project maintained by one person, not a funded product with an
on-call rotation. Expect an acknowledgement within about a week. There is no bug bounty. Please give
a reasonable window to ship a fix before disclosing publicly — 90 days is a good default, and less
if a fix lands sooner.

## Supported versions

The project has not cut a stable release yet. Only the current `main` branch is supported; fixes
land there. Pin a commit if you need stability.

## What this project promises about its own behaviour

These are security properties, not features — a regression in any of them is a vulnerability, and
worth reporting as one. They come out of [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

- **Secret material is never read or stored.** Collectors read metadata only. The AWS IAM policy
  deliberately excludes `secretsmanager:GetSecretValue` and `kms:Decrypt`; the repo scanner records
  *where* a credential was found (path, line, pattern, a SHA-256 fingerprint) and never the value.
- **No standing target-cloud credentials.** Cross-account access uses short-lived STS assume-role
  sessions gated by an `ExternalId`, and GCP uses workload identity federation. Nothing long-lived
  is persisted.
- **Collection is read-only.** Every documented target policy grants only `Get*` / `List*` /
  `Describe*` and `cloudtrail:LookupEvents`. NHIID never mutates a target account.
- **Collector activity is auditable.** Collection appears in the target's own CloudTrail, and
  `collector_runs` records provenance for reconciliation.

Reports that a deployment violates one of these — for example a code path that persists a secret
value, writes to a target account, or leaks credentials into logs — are exactly what this policy is
for.

## Known-by-design behaviours (not vulnerabilities)

Please don't report these; they are documented deliberate choices.

- **`auth.mode: off` is the default**, which leaves the API unauthenticated. It exists so the local
  demo works with zero configuration. Token and OIDC/JWT modes with roles ship in the box — see
  [docs/AUTH.md](docs/AUTH.md) — and **any deployment beyond a local demo should enable one.** The
  Helm chart's production example does.
- **The demo dataset is deliberately vulnerable.** `fixtures/` describes leaked keys, condition-less
  assume-role trust, and over-privileged identities on purpose; the values are synthetic.
- **`deploy/terraform/demo-estate/` intentionally provisions insecure AWS resources** — that is its
  entire purpose. It is prefixed, tagged, and disposable, and its README says to use a throwaway
  account. The access key it emits can do nothing but assume the demo role.
- **The IAM policy analyzer is not a complete policy evaluator.** It analyzes `Allow` statements and
  does not resolve `NotAction`, conditions, or cross-statement deny precedence, so it can be
  over-inclusive about what a principal can reach. This is a documented analysis limitation, not a
  security flaw.

## Hardening a deployment

If you run this against real accounts, at minimum: enable authentication (`config.auth.mode`), keep
the collector role read-only with an `ExternalId`, supply the DB DSN and JWT secret from a secret
store rather than the config file, and terminate TLS in front of the API.
[docs/RUNBOOK.md](docs/RUNBOOK.md) and [deploy/helm/README.md](deploy/helm/README.md) cover the
production posture; `deploy/helm/values-prod.example.yaml` is a worked example.
