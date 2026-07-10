#!/usr/bin/env bash
# Seed the synthetic AWS+GCP+K8s demo and print the narrated attack-path simulation.
# Equivalent to `make demo`, for environments without make. Requires the stack to be up
# (`docker compose -f deploy/docker-compose.yml up -d`).
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f deploy/docker-compose.yml)

"${COMPOSE[@]}" exec -T api collector --provider fixture --fixture fixtures/demo_env.json
"${COMPOSE[@]}" exec -T api collector --provider k8s --cluster demo --k8s-export fixtures/k8s_cluster.json
"${COMPOSE[@]}" exec -T api worker --once --job all
echo
"${COMPOSE[@]}" exec api simulate
