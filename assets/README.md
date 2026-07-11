# README visuals

Hand-authored **SVG renderings** of the IdentityAttackGraph product, used in the top-level README.
They are drawn with the dashboard's actual design system (the `web/src/index.css` tokens and the
Cytoscape node/edge palette from `web/src/GraphView.tsx`) and populated with the real synthetic-demo
data (`make demo`), so they faithfully represent what the running app shows — but they are diagrams,
not screenshots.

| File | Renders |
|------|---------|
| [`dashboard.svg`](dashboard.svg) | The Overview console — sidebar, stat cards, findings-by-severity distribution, and the risk-ranked triage queue |
| [`attack-graph.svg`](attack-graph.svg) | The attack-graph view — capability edges connecting footholds to crown jewels across AWS, an AI agent, and a Kubernetes IRSA path |
| [`risk-breakdown.svg`](risk-breakdown.svg) | An identity's explainable 6-factor risk breakdown (risk ring + weighted factors + signals) |

To see the live UI, run `make dev && make demo` and open <http://localhost:5173>.
