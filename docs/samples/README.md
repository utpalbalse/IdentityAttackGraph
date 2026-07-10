# Sample outputs

Real artifacts produced by `make demo` against the synthetic fixtures — so you can see what
IdentityAttackGraph emits without running it. Regenerate any time with the commands below.

| File | What it is | Regenerate |
|------|-----------|------------|
| [`attack_simulation.txt`](attack_simulation.txt) | Narrated attacker walkthrough (terminal) | `simulate --no-color` |
| [`attack_simulation.json`](attack_simulation.json) | Same scenarios, machine-readable | `simulate --json` |
| [`findings.sarif`](findings.sarif) | SARIF 2.1.0 findings (GitHub code scanning / IDEs) | `GET /api/v1/export/findings?format=sarif` |
| [`findings.json`](findings.json) | Findings with evidence + narrative | `GET /api/v1/export/findings?format=json` |
| [`inventory.csv`](inventory.csv) | Identity inventory with risk scores | `GET /api/v1/export/inventory?format=csv` |

These carry **no secret material** — exposures record location + fingerprint only (threat-model rule).
