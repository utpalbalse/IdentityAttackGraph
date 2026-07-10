# Seed the synthetic AWS+GCP+K8s demo and print the narrated attack-path simulation.
# Equivalent to `make demo`, for Windows without make. Requires the stack to be up
# (docker compose -f deploy/docker-compose.yml up -d).
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$file = 'deploy/docker-compose.yml'

docker compose -f $file exec -T api collector --provider fixture --fixture fixtures/demo_env.json
docker compose -f $file exec -T api collector --provider k8s --cluster demo --k8s-export fixtures/k8s_cluster.json
docker compose -f $file exec -T api worker --once --job all
Write-Host ''
docker compose -f $file exec api simulate
