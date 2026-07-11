# Repository Secret Scanner

The `repo` collector turns repository secrets into normalized **repositories** + **exposures**, so
the `secret_exposed_in_repo` detector fires on real repositories — not just the demo fixture. It has
two sources:

1. **Built-in live scanner** (`--scan-path`) — walks a checked-out working tree directly with a
   curated set of high-confidence provider patterns (AWS AKIA, GitHub PAT, GCP SA key, PEM private
   key, Slack/Google/JWT) plus an **entropy-guarded** generic `key = value` rule. Skips VCS/vendored
   dirs and binary files; the matched value is examined for entropy then **discarded, never stored**.

   ```bash
   go run ./cmd/collector --provider repo --scan-path ./checkout --repo acme/widgets
   # or via the API (admin): {"provider":"repo","scan_path":"/path","repo":"acme/widgets"}
   ```

2. **SecretSweep report ingest** (`--report`) — composes with
   **[SecretSweep](https://github.com/utpalbalse/SecretSweep)** (a Python scanner: 36 patterns +
   entropy over source, git history, K8s/Terraform, archives, notebooks, CI configs) by ingesting
   its JSON/SARIF report, so that richer scanner can run where it belongs (CI) without embedding a
   Python runtime in NHIID's Go image.

Both produce the identical normalized exposures. Implementation:
[internal/collectors/repo/](../internal/collectors/repo/) (`scan.go` for the live scanner).

---

## Flow

```
secretsweep ./checkout --json out.json        # your tool (or --sarif out.sarif)
        │
        ▼  report (JSON or SARIF 2.1.0)
nhiid repo collector  ──►  repositories + exposures (location + fingerprint only, never the value)
        │
        ▼
worker  ──►  secret_exposed_in_repo findings (critical for aws/gcp/private-key patterns)
```

The collector auto-detects the report format (SecretSweep JSON array `{file,line,name,severity,…}`
or SARIF 2.1.0 `runs[].results[]`). Each finding becomes an exposure with a stable fingerprint
(`sha256(repo|file|line|rule)`), so re-scanning is idempotent (migration 0005 dedupes by
fingerprint).

**No secret material is stored.** SecretSweep does not emit secret values, and neither does NHIID —
exposures carry repo + path + line + pattern + fingerprint only (threat-model rule).

## Usage

```bash
# 1) scan with SecretSweep (your tool)
secretsweep ./acme-billing --json report.json     # or: --sarif report.sarif

# 2) ingest into NHIID
go run ./cmd/collector --provider repo \
  --report report.json \
  --repo acme/billing --repo-provider github --repo-visibility private

# 3) detect (or let the worker do it on its cycle)
go run ./cmd/worker --once --job detect
```

Or via the API / job queue (admin role):

```bash
curl -X POST localhost:8080/api/v1/collect -H 'Content-Type: application/json' \
  -d '{"provider":"repo","report":"fixtures/secretsweep_report.json","repo":"acme/billing"}'
```

A sample report ships at [fixtures/secretsweep_report.json](../fixtures/secretsweep_report.json).

## Identity correlation

SecretSweep reports the secret *type* (e.g. "AWS Access Key") but not the value, so exposures attach
to the **repository** and raise repository-scoped findings. When a future enrichment can recover a
key identifier (e.g. an `AKIA…` id from an unredacted finding), the exposure links to the owning
identity and the finding gains that identity's blast-radius context — the
[`secret_exposed_in_repo`](DETECTIONS.md) detector already supports both forms.

## Severity

`secret_exposed_in_repo` is **critical** when the pattern indicates a high-value credential
(`aws`, `gcp`, `azure`, `private_key`, `service_account`, `ssh`, `token`, …) or the exposure is
verified-live; otherwise **high**.
