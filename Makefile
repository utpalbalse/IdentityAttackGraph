.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose -f deploy/docker-compose.yml

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: dev
dev: ## Bring up the full local stack (pg, nats, redis, migrate, api, worker, web)
	$(COMPOSE) up --build -d
	@echo "Waiting for API..." && sleep 3
	@echo "API:  http://localhost:8080/healthz"
	@echo "Web:  http://localhost:5173"

.PHONY: down
down: ## Tear down the local stack
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail stack logs
	$(COMPOSE) logs -f --tail=100

.PHONY: migrate
migrate: ## Apply DB migrations (also runs automatically as a service in `make dev`)
	$(COMPOSE) run --rm migrate

.PHONY: seed
seed: ## Load synthetic AWS+GCP+K8s fixtures and run graph/score/detect (in-container, no local Go)
	$(COMPOSE) exec -T api collector --provider fixture --fixture fixtures/demo_env.json
	$(COMPOSE) exec -T api collector --provider k8s --cluster demo --k8s-export fixtures/k8s_cluster.json
	$(COMPOSE) exec -T api worker --once --job all
	@echo "Seeded. Open http://localhost:5173"

.PHONY: demo
demo: seed ## Seed the demo dataset then print the narrated attack-path simulation
	@echo
	$(COMPOSE) exec api simulate
	@echo "UI: http://localhost:5173"

.PHONY: sim
sim: ## Print the attack-path simulation for the currently-loaded data
	$(COMPOSE) exec api simulate

.PHONY: build
build: ## Build all Go binaries
	go build -o bin/ ./cmd/...

.PHONY: test
test: ## Run unit tests
	go test ./... -count=1

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format Go code
	gofmt -s -w .

.PHONY: vuln
vuln: ## Vulnerability scan
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: web
web: ## Run the web dev server
	cd web && npm install && npm run dev
