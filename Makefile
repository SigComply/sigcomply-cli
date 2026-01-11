# TraceVault CLI Makefile
# Run 'make help' for available targets

# Variables
BINARY_NAME := tracevault
BUILD_DIR := bin
COVERAGE_DIR := coverage
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Default target
.DEFAULT_GOAL := help

##@ Development

.PHONY: build
build: ## Build the binary
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

.PHONY: build-all
build-all: ## Build for all platforms
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

.PHONY: install
install: build ## Install binary to GOPATH/bin
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -f coverage.out coverage.html

##@ Testing

.PHONY: test
test: test-unit test-policy ## Run all fast tests (unit + policy)

.PHONY: test-unit
test-unit: ## Run unit tests
	$(GOTEST) -short -race -v ./...

.PHONY: test-coverage
test-coverage: ## Run unit tests with coverage report
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -short -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out | tail -1
	@echo "Coverage report: $(COVERAGE_DIR)/coverage.html"

.PHONY: test-policy
test-policy: ## Run OPA policy tests
	@if [ -d "internal/policy/policies" ]; then \
		opa test internal/policy/policies/ -v; \
	else \
		echo "No policies directory found yet - skipping"; \
	fi

.PHONY: test-integration
test-integration: ## Run integration tests (requires LocalStack)
	@echo "Starting LocalStack..."
	docker-compose up -d localstack
	@echo "Waiting for LocalStack to be ready..."
	@timeout 60 bash -c 'until curl -s http://localhost:4566/_localstack/health | grep -q "running"; do sleep 2; done' || (docker-compose logs localstack && exit 1)
	@echo "Running integration tests..."
	AWS_ENDPOINT_URL=http://localhost:4566 \
	AWS_ACCESS_KEY_ID=test \
	AWS_SECRET_ACCESS_KEY=test \
	AWS_DEFAULT_REGION=us-east-1 \
	$(GOTEST) -tags=integration -race -v ./...
	@echo "Stopping LocalStack..."
	docker-compose down

.PHONY: test-e2e
test-e2e: ## Run E2E tests (requires real AWS credentials)
	$(GOTEST) -tags=e2e -v ./test/e2e/...

.PHONY: test-all
test-all: test-unit test-policy test-integration ## Run all tests including integration

##@ Code Quality

.PHONY: lint
lint: ## Run linter
	$(GOLINT) run ./...

.PHONY: lint-fix
lint-fix: ## Run linter and fix issues
	$(GOLINT) run --fix ./...

.PHONY: fmt
fmt: ## Format code
	$(GOFMT) -s -w .

.PHONY: fmt-check
fmt-check: ## Check code formatting
	@test -z "$$($(GOFMT) -l .)" || (echo "Code not formatted. Run 'make fmt'" && exit 1)

.PHONY: vet
vet: ## Run go vet
	$(GOCMD) vet ./...

.PHONY: tidy
tidy: ## Tidy go modules
	$(GOMOD) tidy

.PHONY: verify
verify: ## Verify dependencies
	$(GOMOD) verify

##@ Security

.PHONY: security
security: security-deps security-code ## Run all security checks

.PHONY: security-deps
security-deps: ## Check dependencies for vulnerabilities
	@echo "Running govulncheck..."
	govulncheck ./...
	@echo "Running nancy..."
	$(GOCMD) list -json -deps ./... | nancy sleuth

.PHONY: security-code
security-code: ## Run security scanner on code
	@echo "Running gosec..."
	gosec -quiet ./...

.PHONY: security-secrets
security-secrets: ## Scan for secrets in code
	@echo "Running gitleaks..."
	gitleaks detect --source . --verbose

##@ Dependencies

.PHONY: deps
deps: ## Download dependencies
	$(GOMOD) download

.PHONY: deps-update
deps-update: ## Update dependencies
	$(GOMOD) tidy
	$(GOCMD) get -u ./...
	$(GOMOD) tidy

.PHONY: tools
tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/sonatype-nexus-community/nancy@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install github.com/anchore/syft/cmd/syft@latest

##@ CI/CD

.PHONY: ci
ci: deps lint test build ## Run CI pipeline locally

.PHONY: pre-commit
pre-commit: fmt-check vet lint test-unit test-policy ## Run pre-commit checks

##@ Release

.PHONY: release-dry-run
release-dry-run: ## Dry run of release
	goreleaser release --snapshot --clean

.PHONY: sbom
sbom: ## Generate Software Bill of Materials
	syft . -o spdx-json > sbom.spdx.json

##@ Help

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
