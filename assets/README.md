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
| [`hover-attack-path.gif`](hover-attack-path.gif) | The kill chain igniting: the `svc-billing-export → billing-admin → s3:prod-billing` crown-jewel path lights up as the graph dims around it |
| [`hover-blast-radius.gif`](hover-blast-radius.gif) | Hovering the exposed entry point `svc-billing-export`: the HUD reads `0 upstream · 2 downstream — blast radius`, with the 2-hop reach to the crown jewel in amber |
| [`attack-paths.png`](attack-paths.png) | An identity's **attack-path panel**: the ranked crown-jewel paths (`assumes → binds_to`) plus the open findings and their one-click remediations with risk deltas |
| [`triage.png`](triage.png) | The **Triage queue**: findings ranked by severity then confidence, with SARIF/CSV/JSON export |
| [`risk-breakdown.png`](risk-breakdown.png) | An identity's **explainable 6-factor risk breakdown**: the gauge plus per-factor scores and the signals behind them (privilege 100, blast-radius 70, exposure 85, trust 40, usage 0, freshness 15 → composite 62) |
| [`attack-simulation.png`](attack-simulation.png) | The `simulate` CLI narrating the worst path end-to-end: foothold → hops → crown jewel, the detections that caught it, and the single fix that severs it (risk 62→24) |

Everything shown is the live `make demo` dataset, computed end-to-end by the collector → graph →
score → detect pipeline. The graph layout is deterministic (the API orders its node/edge reads), so
a re-capture reproduces the same arrangement. To reproduce: `make dev && make demo`, then open
<http://localhost:5173>.
