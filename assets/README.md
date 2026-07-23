# README visuals

**Real captures** of the running IdentityAttackGraph web console, taken against the synthetic demo
environment (`make dev && make demo`). These are the actual UI: the "SUBSTRATE" design system in
[`web/src/index.css`](../web/src/index.css), not mockups or renderings.

Stills are captured at `deviceScaleFactor: 2` and downscaled, so they stay crisp on HiDPI displays.

| File | Shows |
|------|-------|
| [`dashboard.png`](dashboard.png) | The **Overview** console: inventory stat readouts, risk distribution, and the risk-ranked top-risk queue |
| [`attack-graph.png`](attack-graph.png) | The **Attack Graph**: a hierarchical (dagre) kill-chain projection flowing exposed entry point → identity → role → crown jewel |
| [`attack-graph-zoom.png`](attack-graph-zoom.png) | The same graph filtered to **crown-jewel paths only**: five distinct routes to a crown jewel across AWS, GCP, and Kubernetes |
| [`hover-attack-path.gif`](hover-attack-path.gif) | Hovering the exposed entry point `svc-billing-export`: traces its 2-hop path to the `s3:prod-billing` crown jewel (`0 upstream · 2 downstream`) |
| [`hover-blast-radius.gif`](hover-blast-radius.gif) | Hovering the Kubernetes identity `prod/deployer`: upstream workload in rose, 4-node blast radius in amber (`1 upstream · 4 downstream`) |
| [`triage.png`](triage.png) | The **Triage queue**: findings ranked by severity then confidence, with SARIF/CSV/JSON export |
| [`risk-breakdown.png`](risk-breakdown.png) | An identity's **explainable 6-factor risk breakdown**: the gauge plus per-factor scores and the signals behind them (privilege 100, blast-radius 70, exposure 85, trust 40, usage 0, freshness 15 → composite 62) |

Everything shown is the live `make demo` dataset, computed end-to-end by the collector → graph →
score → detect pipeline. The graph layout is deterministic (the API orders its node/edge reads), so
a re-capture reproduces the same arrangement. To reproduce: `make dev && make demo`, then open
<http://localhost:5173>.
