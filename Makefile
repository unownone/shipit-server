# ShipIt Server Makefile

.PHONY: help build run test clean docker-up docker-down docker-logs deps lint format

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development
deps: ## Install dependencies
	go mod tidy
	go mod download

build: ## Build the server binary
	go build -o bin/shipit-server cmd/server/main.go

build-linux: ## Build for Linux (useful for deployment)
	GOOS=linux GOARCH=amd64 go build -o bin/shipit-server-linux cmd/server/main.go

run: ## Run the server in development mode
	go run cmd/server/main.go

test: test-unit ## Run all tests

test-unit: ## Run unit tests with testcontainers
	@echo "Running unit tests with testcontainers..."
	@echo "Testcontainers will automatically start PostgreSQL containers"
	go test -v ./test/... -count=1

test-integration: test-unit ## Run integration tests (alias for test-unit with testcontainers)

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage using testcontainers..."
	go test -v ./test/... -coverprofile=coverage.out -covermode=atomic -coverpkg=./...
	go tool cover -func=coverage.out -o=coverage.txt
	go tool cover -html=coverage.out -o=coverage.html
	@echo "Coverage report generated: coverage.html"
	@echo "Coverage summary:"
	@go tool cover -func=coverage.out | grep total

test-clean: ## Clean test artifacts
	@echo "Cleaning test artifacts..."
	rm -f coverage.out coverage.html coverage.txt coverage.json coverage.xml

lint: ## Run linter
	golangci-lint run

format: ## Format code
	go fmt ./...
	goimports -w .

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html coverage.txt coverage.json coverage.xml

# Docker
docker-up: ## Start database services only
	docker-compose up -d postgres redis

docker-up-all: ## Start all services including server
	docker-compose up -d

docker-down: ## Stop all services
	docker-compose down

docker-logs: ## Show all service logs
	docker-compose logs -f

docker-logs-server: ## Show only server logs
	docker-compose logs -f shipit-server

docker-clean: ## Clean up Docker containers and volumes
	docker-compose down -v
	docker system prune -f

docker-build: ## Build the server Docker image
	docker-compose build shipit-server

docker-restart: ## Restart the server container
	docker-compose restart shipit-server

# Database
db-migrate: ## Run database migrations
	@echo "Migrations are run automatically when the server starts"

db-reset: ## Reset database (WARNING: destroys all data)
	docker-compose down -v postgres
	docker-compose up -d postgres
	@echo "Database reset complete. Restart the server to run migrations."

db-shell: ## Connect to database shell
	docker-compose exec postgres psql -U shipit_user -d shipit

# Atlas ORM
atlas-install: ## Install Atlas CLI
	@if command -v atlas > /dev/null 2>&1; then \
		echo "✅ Atlas CLI is already installed"; \
		atlas version; \
	else \
		echo "📦 Installing Atlas CLI..."; \
		if [ "$$(uname)" = "Darwin" ]; then \
			if command -v brew > /dev/null 2>&1; then \
				brew install ariga/tap/atlas; \
			else \
				echo "❌ Homebrew not found. Please install it first or use manual installation:"; \
				echo "   curl -sSf https://atlasgo.sh | sh"; \
				exit 1; \
			fi; \
		else \
			curl -sSf https://atlasgo.sh | sh; \
		fi; \
	fi

atlas-migrate-apply: ## Apply Atlas migrations to development database
	docker-compose up -d postgres
	@echo "Waiting for database to be ready..."
	@sleep 3
	atlas migrate apply --env dev

atlas-migrate-status: ## Check Atlas migration status
	atlas migrate status --env dev

atlas-migrate-new: ## Create a new Atlas migration (usage: make atlas-migrate-new NAME=description)
	@if [ -z "$(NAME)" ]; then \
		echo "❌ NAME is required. Usage: make atlas-migrate-new NAME=description"; \
		exit 1; \
	fi
	atlas migrate diff $(NAME) --env dev

atlas-schema-apply: ## Apply schema changes and generate migration
	atlas schema apply --env dev --auto-approve

atlas-validate: ## Validate Atlas configuration and migrations
	atlas migrate validate --env dev

# Development helpers
dev: env-init docker-up deps ## Setup development environment
	@echo "Development environment ready!"
	@echo "Run 'make run' to start the server locally"
	@echo "Or run 'make docker-up-all' to start everything in Docker"
	@echo "Atlas CLI tools are available via 'make atlas-*' targets"

env-init: ## Initialize .env file from example
	@if [ ! -f .env ]; then \
		cp .env.example .env && \
		echo "✅ .env file created from .env.example"; \
		echo "📝 Edit .env to customize your configuration"; \
	else \
		echo "⚠️  .env file already exists"; \
	fi

env-prod-init: ## Initialize .env file for production
	@if [ ! -f .env ]; then \
		cp .env.production.example .env && \
		echo "✅ Production .env file created"; \
		echo "🔐 IMPORTANT: Update all CHANGE_ME values in .env!"; \
	else \
		echo "⚠️  .env file already exists"; \
	fi

env-validate: ## Validate required environment variables
	@echo "🔍 Validating environment variables..."
	@if [ -f .env ]; then \
		if grep -q "CHANGE_ME" .env; then \
			echo "❌ Found CHANGE_ME values in .env - update these!"; \
			grep "CHANGE_ME" .env; \
			exit 1; \
		else \
			echo "✅ Environment variables look good"; \
		fi; \
	else \
		echo "❌ .env file not found - run 'make env-init' first"; \
		exit 1; \
	fi

secrets-generate: ## Generate secure secrets for production
	@echo "🔐 Generating secure secrets..."
	@echo "Database password: $(shell openssl rand -base64 32)"
	@echo "JWT secret: $(shell openssl rand -hex 32)"
	@echo "Refresh secret: $(shell openssl rand -hex 32)"
	@echo "Rate limit secret: $(shell openssl rand -base64 24)"
	@echo "Webhook secret: $(shell openssl rand -base64 24)"
	@echo ""
	@echo "💡 Copy these to your .env file"

logs: ## Show application logs (when running with docker-compose)
	docker-compose logs -f app

# Production
release: clean deps test build-linux ## Build release binary

docker-prod-secrets: ## Generate production secrets
	./scripts/create-prod-secrets.sh

docker-prod-deploy: env-validate ## Deploy to production with Docker
	@echo "Deploying to production..."
	@echo "Using domain: $$(grep SHIPIT_SERVER_DOMAIN .env | cut -d'=' -f2)"
	docker-compose -f docker-compose.prod.yml up -d --build

docker-prod-logs: ## Show production logs
	docker-compose -f docker-compose.prod.yml logs -f

docker-prod-down: ## Stop production deployment
	docker-compose -f docker-compose.prod.yml down

# API testing (requires server to be running)
test-health: ## Test health endpoint
	curl -s http://localhost:8080/health | jq

test-register: ## Test user registration
	curl -X POST http://localhost:8080/api/v1/users/register \
		-H "Content-Type: application/json" \
		-d '{"email":"test@example.com","password":"password123","name":"Test User"}' | jq

# Configuration
config-check: ## Validate configuration
	@go run cmd/server/main.go -config-check 2>/dev/null || echo "Config validation not implemented yet"

# Documentation
swagger: docs ## Generate swagger documentation

docs: ## Generate API documentation
	@echo "Generating Swagger documentation..."
	go run github.com/swaggo/swag/cmd/swag init -g cmd/server/main.go -o docs
	@echo "Swagger docs generated at docs/"
	@echo "View at: http://localhost:8080/swagger/index.html (when server is running)"

# Git hooks
install-hooks: ## Install git hooks
	@echo "Installing pre-commit hook..."
	@echo '#!/bin/sh\nmake format lint test' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed!"

# Benchmarks
bench: ## Run benchmarks
	go test -bench=. -benchmem ./...

# Security
security-scan: ## Run security scan
	govulncheck ./... 

# Test targets
.PHONY: test test-unit test-integration test-coverage test-clean swagger docs

# Development helpers
.PHONY: test-status test-logs

test-status: ## Check if Docker is running (required for testcontainers)
	@echo "Checking Docker status..."
	@docker info > /dev/null 2>&1 && echo "✓ Docker is running" || echo "✗ Docker is not running. Please start Docker to run tests."

test-logs: ## Show recent test logs (useful for debugging)
	@echo "Recent testcontainers logs:"
	@docker ps -a --filter "name=testcontainers" --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}"

# Complete test pipeline for CI/CD
.PHONY: ci-test

ci-test: test-status test test-coverage ## Complete CI test pipeline with testcontainers 