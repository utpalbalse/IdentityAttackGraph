.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose -f deploy/docker-compose.yml

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: dev
dev: ## Bring up the full local stack (pg, nats, redis, api, worker, web)
	$(COMPOSE) up --build -d
	@echo "API:  http://localhost:8080/healthz"
	@echo "Web:  http://localhost:5173"

.PHONY: down
down: ## Tear down the local stack
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail stack logs
	$(COMPOSE) logs -f --tail=100

.PHONY: migrate
migrate: ## Apply DB migrations
	go run ./cmd/migrate up

.PHONY: seed
seed: ## Load synthetic AWS+GCP fixture (no cloud creds needed)
	go run ./cmd/collector --provider fixture --fixture fixtures/demo_env.json
	go run ./cmd/worker --once --job graph
	go run ./cmd/worker --once --job score
	go run ./cmd/worker --once --job detect

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
