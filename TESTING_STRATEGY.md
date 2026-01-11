# TraceVault CLI - Testing Strategy

**Version**: 1.0
**Date**: 2026-01-08

---

## Overview

This document defines the testing strategy for TraceVault CLI. Every code change requires appropriate tests. This is non-negotiable for security and reliability.

---

## Test Pyramid

```
                    ┌─────────────┐
                    │   E2E       │  External repos (GitHub/GitLab)
                    │   Tests     │  Real AWS, real CI/CD
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │    Integration Tests    │  LocalStack
              │    (CI with Docker)     │  Weekly in CI
              └────────────┬────────────┘
                           │
    ┌──────────────────────┴──────────────────────┐
    │              Unit Tests                      │  Every commit
    │         (Fast, mocked, >80% coverage)        │  Required for PR
    └─────────────────────────────────────────────┘

External E2E Testing Repositories:
- GitHub: https://github.com/Trace-Vault/tracevault-cli-testing-github
- GitLab: https://gitlab.com/tracevault/tracevault-cli-testing-gitlab
```

---

## Test Types

### 1. Unit Tests (Required for Every PR)

**Location**: Same directory as source code (`*_test.go`)
**Run**: `make test-unit` or `go test -short ./...`
**Speed**: < 10 seconds total
**Coverage**: > 80% for new code

#### Rules

1. **Mock all external calls** (AWS, HTTP, filesystem)
2. **Use table-driven tests** for comprehensive coverage
3. **Test error paths**, not just happy paths
4. **No network calls** in unit tests
5. **No filesystem access** except in `testdata/`

#### Example: Table-Driven Test

```go
// internal/aws/iam_test.go
package aws

import (
    "context"
    "testing"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/iam"
    "github.com/aws/aws-sdk-go-v2/service/iam/types"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestCollectIAMUsers(t *testing.T) {
    tests := []struct {
        name        string
        mockUsers   []types.User
        mockMFA     map[string][]types.MFADevice
        wantCount   int
        wantMFAMap  map[string]bool
        wantErr     bool
    }{
        {
            name:      "empty account returns empty list",
            mockUsers: []types.User{},
            wantCount: 0,
        },
        {
            name: "single user with MFA",
            mockUsers: []types.User{
                {UserName: aws.String("alice"), UserId: aws.String("AIDA123")},
            },
            mockMFA: map[string][]types.MFADevice{
                "alice": {{SerialNumber: aws.String("arn:aws:iam::123:mfa/alice")}},
            },
            wantCount:  1,
            wantMFAMap: map[string]bool{"alice": true},
        },
        {
            name: "user without MFA",
            mockUsers: []types.User{
                {UserName: aws.String("bob"), UserId: aws.String("AIDA456")},
            },
            mockMFA:    map[string][]types.MFADevice{},
            wantCount:  1,
            wantMFAMap: map[string]bool{"bob": false},
        },
        {
            name: "mixed users",
            mockUsers: []types.User{
                {UserName: aws.String("alice"), UserId: aws.String("AIDA123")},
                {UserName: aws.String("bob"), UserId: aws.String("AIDA456")},
                {UserName: aws.String("charlie"), UserId: aws.String("AIDA789")},
            },
            mockMFA: map[string][]types.MFADevice{
                "alice":   {{SerialNumber: aws.String("arn:...")}},
                "charlie": {{SerialNumber: aws.String("arn:...")}},
            },
            wantCount:  3,
            wantMFAMap: map[string]bool{"alice": true, "bob": false, "charlie": true},
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Arrange
            mock := &mockIAMClient{
                users:      tt.mockUsers,
                mfaDevices: tt.mockMFA,
            }
            collector := &Collector{iamClient: mock}

            // Act
            evidence, err := collector.collectIAMUsers(context.Background())

            // Assert
            if tt.wantErr {
                require.Error(t, err)
                return
            }

            require.NoError(t, err)
            assert.Len(t, evidence, tt.wantCount)

            for _, ev := range evidence {
                data := ev.Data.(map[string]interface{})
                userName := data["user_name"].(string)
                expectedMFA := tt.wantMFAMap[userName]
                assert.Equal(t, expectedMFA, data["mfa_enabled"],
                    "MFA status mismatch for user %s", userName)
            }
        })
    }
}
```

#### Mock Pattern

```go
// internal/aws/mock_test.go
package aws

import (
    "context"

    "github.com/aws/aws-sdk-go-v2/service/iam"
    "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAMClient interface for mocking
type IAMClient interface {
    ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
    ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
}

// mockIAMClient implements IAMClient for testing
type mockIAMClient struct {
    users      []types.User
    mfaDevices map[string][]types.MFADevice
    err        error
}

func (m *mockIAMClient) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
    if m.err != nil {
        return nil, m.err
    }
    return &iam.ListUsersOutput{Users: m.users}, nil
}

func (m *mockIAMClient) ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
    if m.err != nil {
        return nil, m.err
    }
    devices := m.mfaDevices[*params.UserName]
    return &iam.ListMFADevicesOutput{MFADevices: devices}, nil
}
```

---

### 2. Policy Tests (Required for Every Policy)

**Location**: Same directory as policy (`*_test.rego`)
**Run**: `make test-policy` or `opa test internal/policy/policies/ -v`
**Speed**: < 5 seconds total

#### Rules

1. **Every policy must have a test file**
2. **Test both passing and failing cases**
3. **Test edge cases** (empty input, missing fields)
4. **Test that unrelated resources are ignored**

#### Example: Policy Test

```rego
# internal/policy/policies/soc2_cc6_1_mfa_test.rego
package tracevault.soc2.cc6_1

# Test: User without MFA should trigger violation
test_user_without_mfa_violates {
    result := violations with input as {
        "resource_type": "aws:iam:user",
        "resource_id": "arn:aws:iam::123456789012:user/alice",
        "data": {
            "user_name": "alice",
            "user_id": "AIDA123",
            "mfa_enabled": false,
        }
    }
    count(result) == 1
    result[0].control_id == "CC6.1"
    contains(result[0].message, "alice")
}

# Test: User with MFA should pass
test_user_with_mfa_passes {
    result := violations with input as {
        "resource_type": "aws:iam:user",
        "resource_id": "arn:aws:iam::123456789012:user/bob",
        "data": {
            "user_name": "bob",
            "user_id": "AIDA456",
            "mfa_enabled": true,
        }
    }
    count(result) == 0
}

# Test: Non-IAM resources should be ignored
test_non_iam_resource_ignored {
    result := violations with input as {
        "resource_type": "aws:s3:bucket",
        "resource_id": "my-bucket",
        "data": {
            "name": "my-bucket",
        }
    }
    count(result) == 0
}

# Test: Empty data should not crash
test_empty_data_safe {
    result := violations with input as {
        "resource_type": "aws:iam:user",
        "resource_id": "arn:...",
        "data": {}
    }
    # Should either have violation or gracefully handle missing field
    true
}
```

---

### 3. Integration Tests (CI with LocalStack)

**Location**: `*_integration_test.go` with build tag
**Run**: `make test-integration`
**Speed**: < 2 minutes
**When**: Weekly CI run, pre-release

#### Setup

```yaml
# docker-compose.yml
version: '3.8'
services:
  localstack:
    image: localstack/localstack:3.0
    ports:
      - "4566:4566"
    environment:
      - SERVICES=iam,s3,sts,cloudtrail
      - DEFAULT_REGION=us-east-1
```

#### Example: Integration Test

```go
//go:build integration

// internal/aws/collector_integration_test.go
package aws

import (
    "context"
    "os"
    "testing"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestCollector_Integration(t *testing.T) {
    // Skip if LocalStack not running
    endpoint := os.Getenv("AWS_ENDPOINT_URL")
    if endpoint == "" {
        endpoint = "http://localhost:4566"
    }

    // Configure for LocalStack
    cfg, err := config.LoadDefaultConfig(context.Background(),
        config.WithRegion("us-east-1"),
        config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
            "test", "test", "test",
        )),
        config.WithEndpointResolverWithOptions(
            localstackResolver(endpoint),
        ),
    )
    if err != nil {
        t.Skip("LocalStack not available:", err)
    }

    // Create test resources
    setupTestResources(t, cfg)

    // Test collector
    collector := NewCollector(cfg)
    evidence, err := collector.Collect(context.Background())

    require.NoError(t, err)
    assert.NotEmpty(t, evidence)

    // Verify IAM users collected
    var iamUsers []Evidence
    for _, ev := range evidence {
        if ev.ResourceType == "aws:iam:user" {
            iamUsers = append(iamUsers, ev)
        }
    }
    assert.NotEmpty(t, iamUsers, "Should collect IAM users")
}

func setupTestResources(t *testing.T, cfg aws.Config) {
    // Create test IAM user
    iamClient := iam.NewFromConfig(cfg)
    _, err := iamClient.CreateUser(context.Background(), &iam.CreateUserInput{
        UserName: aws.String("test-user"),
    })
    if err != nil {
        t.Log("User may already exist:", err)
    }
}

func localstackResolver(endpoint string) aws.EndpointResolverWithOptionsFunc {
    return func(service, region string, options ...interface{}) (aws.Endpoint, error) {
        return aws.Endpoint{
            URL:               endpoint,
            HostnameImmutable: true,
        }, nil
    }
}
```

---

### 4. E2E Tests (Pre-Release)

**Location**: `test/e2e/`
**Run**: `make test-e2e` (requires real AWS account)
**When**: Before each release, manual

#### Example: E2E Test

```go
//go:build e2e

// test/e2e/check_test.go
package e2e

import (
    "bytes"
    "os/exec"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestCheckCommand_RealAWS(t *testing.T) {
    // This test runs against a real AWS account
    // Requires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

    cmd := exec.Command("tracevault", "check", "--format", "json")
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    err := cmd.Run()

    // Should complete (pass or fail based on compliance)
    assert.NotEqual(t, 2, cmd.ProcessState.ExitCode(),
        "Exit code 2 indicates error, not compliance failure")

    // Should produce valid JSON
    output := stdout.String()
    assert.Contains(t, output, "framework")
    assert.Contains(t, output, "controls")
}

func TestCheckCommand_JSONOutput(t *testing.T) {
    cmd := exec.Command("tracevault", "check", "--format", "json")
    var stdout bytes.Buffer
    cmd.Stdout = &stdout

    cmd.Run()

    // Parse JSON output
    var result struct {
        Framework string `json:"framework"`
        Controls  []struct {
            ID     string `json:"id"`
            Status string `json:"status"`
        } `json:"controls"`
    }

    err := json.Unmarshal(stdout.Bytes(), &result)
    require.NoError(t, err)

    assert.Equal(t, "soc2", result.Framework)
    assert.NotEmpty(t, result.Controls)
}
```

---

### 5. E2E Testing Repositories (External)

TraceVault maintains dedicated external repositories for E2E testing in real CI/CD environments. These repositories validate complete CLI workflows against real infrastructure.

#### GitHub Actions Testing

**Repository**: [tracevault-cli-testing-github](https://github.com/Trace-Vault/tracevault-cli-testing-github)

**Purpose**: Validates TraceVault CLI in GitHub Actions CI environment.

**Validates**:
- CLI installation via GitHub Actions
- Real AWS API evidence collection (IAM, S3, CloudTrail)
- Compliance policy evaluation (SOC 2)
- Attestation generation with OIDC signing
- Submission to TraceVault Cloud API (paid tier)

**Required Secrets**:
| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS credentials for evidence collection |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials for evidence collection |
| `AWS_REGION` | AWS region (e.g., `us-east-1`) |
| `TRACEVAULT_API_KEY` | TraceVault Cloud API key |
| `TRACEVAULT_API_ENDPOINT` | TraceVault Cloud API URL |

**Exit Codes Tested**:
- `0` - Success, all checks passed
- `1` - Compliance violations found
- `2` - Execution error

#### GitLab CI Testing

**Repository**: [tracevault-cli-testing-gitlab](https://gitlab.com/tracevault/tracevault-cli-testing-gitlab)

**Purpose**: Validates TraceVault CLI in GitLab CI environment.

**Validates**:
- CLI installation in GitLab CI
- Real AWS API evidence collection
- GitLab OIDC token integration (`$CI_JOB_JWT_V2`)
- Multiple framework evaluation (SOC 2, HIPAA, ISO 27001)
- Multiple output formats (JSON, text, SARIF)
- Cloud API submission with GitLab OIDC

**GitLab-Specific Features**:
- OIDC token integration
- Environment variable handling
- Artifact management
- Runner compatibility

**Required CI/CD Variables**:
| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS credentials |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials |
| `AWS_REGION` | AWS region |
| `TRACEVAULT_API_KEY` | Cloud API key |
| `TRACEVAULT_API_ENDPOINT` | Cloud API URL |

#### Key Differences Between Test Repos

| Aspect | GitHub | GitLab |
|--------|--------|--------|
| OIDC Source | `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | `CI_JOB_JWT_V2` |
| Workflow Format | YAML with `uses:` | YAML with `include:` |
| Artifact Handling | `actions/upload-artifact` | `artifacts:` directive |
| Status | Active | Documentation phase |

#### Running E2E Tests Locally

The external repos test against real infrastructure. For local testing:

```bash
# Run E2E tests against real AWS (requires credentials)
make test-e2e

# Or run specific E2E test
go test -tags=e2e -v ./test/e2e/...
```

---

## CI Configuration

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  unit:
    name: Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Run unit tests
        run: make test-unit

      - name: Check coverage
        run: |
          make test-coverage
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "Coverage $COVERAGE% is below 80%"
            exit 1
          fi

  policy:
    name: Policy Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa
          sudo mv opa /usr/local/bin/

      - name: Run policy tests
        run: make test-policy

  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: golangci-lint
        uses: golangci/golangci-lint-action@v4
        with:
          version: v1.55

  integration:
    name: Integration Tests
    runs-on: ubuntu-latest
    # Only run on main branch, not PRs
    if: github.event_name == 'push'
    services:
      localstack:
        image: localstack/localstack:3.0
        ports:
          - 4566:4566
        env:
          SERVICES: iam,s3,sts,cloudtrail
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Run integration tests
        env:
          AWS_ENDPOINT_URL: http://localhost:4566
        run: make test-integration
```

---

## Makefile Targets

```makefile
.PHONY: test test-unit test-policy test-integration test-e2e test-coverage lint

# Run all fast tests (every commit)
test: test-unit test-policy

# Unit tests only
test-unit:
	go test -short -race ./...

# Unit tests with coverage
test-coverage:
	go test -short -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Policy tests only
test-policy:
	opa test internal/policy/policies/ -v

# Integration tests (requires LocalStack)
test-integration:
	docker-compose up -d localstack
	sleep 5
	go test -tags=integration -race ./...
	docker-compose down

# E2E tests (requires real AWS)
test-e2e:
	go test -tags=e2e -v ./test/e2e/...

# Lint
lint:
	golangci-lint run ./...

# Run all tests
test-all: test-unit test-policy test-integration
```

---

## Test Data

### Location

```
internal/aws/
├── collector.go
├── collector_test.go
└── testdata/
    ├── iam_users.json
    ├── s3_buckets.json
    └── cloudtrails.json
```

### Example Test Data

```json
// internal/aws/testdata/iam_users.json
{
  "users": [
    {
      "user_name": "alice",
      "user_id": "AIDA123456789EXAMPLE",
      "arn": "arn:aws:iam::123456789012:user/alice",
      "create_date": "2024-01-15T10:30:00Z",
      "mfa_enabled": true
    },
    {
      "user_name": "bob",
      "user_id": "AIDA987654321EXAMPLE",
      "arn": "arn:aws:iam::123456789012:user/bob",
      "create_date": "2024-02-20T14:45:00Z",
      "mfa_enabled": false
    }
  ]
}
```

---

## Coverage Requirements

| Package | Minimum Coverage |
|---------|-----------------|
| `internal/aws/*` | 80% |
| `internal/policy/*` | 80% |
| `internal/scanner/*` | 90% |
| `internal/attestation/*` | 90% |
| `internal/output/*` | 70% |
| `cmd/*` | 60% |

---

## Test Checklist for PRs

Before submitting a PR, ensure:

- [ ] All existing tests pass (`make test`)
- [ ] New code has unit tests (>80% coverage)
- [ ] New policies have Rego tests
- [ ] Tests are table-driven where applicable
- [ ] Error paths are tested
- [ ] No network calls in unit tests
- [ ] CI passes

---

## Debugging Tests

### Verbose Output

```bash
# See all test output
go test -v ./internal/aws/...

# See specific test
go test -v -run TestCollectIAMUsers ./internal/aws/
```

### Policy Debugging

```bash
# Trace policy evaluation
opa test internal/policy/policies/ -v --explain full

# Test specific policy
opa test internal/policy/policies/soc2_cc6_1_mfa.rego \
         internal/policy/policies/soc2_cc6_1_mfa_test.rego -v
```

### Coverage Analysis

```bash
# Generate HTML coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
open coverage.html
```

---

## API Contract Testing

TraceVault integrates with hundreds of third-party APIs (AWS, GitHub, GCP, etc.). Contract testing ensures these integrations remain stable as APIs evolve.

### Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    API Contract Testing                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │   Contract   │     │  Mock Server │     │   Contract   │    │
│  │  Definition  │────▶│  (Unit Tests)│     │  Validation  │    │
│  │  (JSON)      │     │              │     │  (Weekly CI) │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│         │                    │                    │             │
│         │                    │                    │             │
│         ▼                    ▼                    ▼             │
│  contracts/aws/iam.json   Unit tests use    Hits real APIs     │
│  contracts/github/...     mock responses    Validates schema   │
│                           NO real API calls  Detects drift     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Contract Files

Location: `contracts/<provider>/<service>.json`

```json
{
  "provider": "aws",
  "service": "iam",
  "version": "2010-05-08",
  "interactions": [
    {
      "name": "ListUsers",
      "request": {
        "method": "POST",
        "path": "/",
        "headers": {"X-Amz-Target": "AWSIdentityManagementService.ListUsers"}
      },
      "response": {
        "status": 200,
        "body": {
          "Users": [{"UserName": "alice", "UserId": "AIDA..."}]
        },
        "schema": {"$ref": "#/definitions/ListUsersResponse"}
      }
    }
  ],
  "definitions": {
    "ListUsersResponse": {
      "type": "object",
      "required": ["Users"],
      "properties": {
        "Users": {"type": "array"}
      }
    }
  }
}
```

### Unit Tests with Contracts

Unit tests use the mock server which serves contract responses:

```go
package aws

import (
    "testing"
    "github.com/tracevault/tracevault-cli/internal/testutil"
)

func TestCollectIAMUsers(t *testing.T) {
    // Create mock server from contract
    server := testutil.MustNewMockServerFromPath("aws/iam")
    defer server.Close()

    // Point collector at mock server
    collector := NewCollector(WithEndpoint(server.URL))

    // Test - NO real API calls made
    users, err := collector.CollectIAMUsers(context.Background())

    assert.NoError(t, err)
    assert.Len(t, users, 2)  // Matches contract response

    // Verify request was made correctly
    assert.Equal(t, 1, server.RequestCount())
}
```

### Contract Validation Tests

These tests run weekly against real APIs:

```go
//go:build contract

package aws

import (
    "testing"
    "github.com/tracevault/tracevault-cli/internal/testutil"
)

func TestIAMContract_ListUsers(t *testing.T) {
    testutil.SkipIfNoContractValidation(t)

    // Uses real AWS credentials from environment
    cfg, _ := config.LoadDefaultConfig(ctx)
    client := iam.NewFromConfig(cfg)

    // Make real API call
    resp, err := client.ListUsers(ctx, &iam.ListUsersInput{})
    require.NoError(t, err)

    // Validate response matches contract schema
    contract := testutil.MustLoadContract("aws/iam")
    err = contract.ValidateResponse("ListUsers", toMap(resp))

    assert.NoError(t, err, "API response doesn't match contract - possible API drift")
}
```

### Adding a New API Integration

1. **Create contract file**: `contracts/<provider>/<service>.json`

2. **Define interactions**: Document all API operations you depend on

3. **Create unit tests**: Use mock server
   ```go
   server := testutil.MustNewMockServerFromPath("<provider>/<service>")
   ```

4. **Create validation test**: `contracts/<provider>/<service>_validation_test.go`
   ```go
   //go:build contract
   func Test<Service>Contract_<Operation>(t *testing.T) {
       testutil.SkipIfNoContractValidation(t)
       // ... hit real API and validate
   }
   ```

5. **Document credentials**: Update `contracts/CREDENTIALS.md`

6. **Add secrets to GitHub**: `<PROVIDER>_SANDBOX_*` secrets

### Sandbox Credentials

Each integration requires sandbox credentials for contract validation:

| Provider | Required Secrets |
|----------|-----------------|
| AWS | `AWS_SANDBOX_ACCESS_KEY_ID`, `AWS_SANDBOX_SECRET_ACCESS_KEY` |
| GitHub | `GITHUB_SANDBOX_TOKEN`, `GITHUB_SANDBOX_ORG` |
| GCP | `GCP_SANDBOX_SERVICE_ACCOUNT`, `GCP_SANDBOX_PROJECT_ID` |
| Azure | `AZURE_SANDBOX_CLIENT_ID`, `AZURE_SANDBOX_CLIENT_SECRET`, `AZURE_SANDBOX_TENANT_ID` |

See `contracts/CREDENTIALS.md` for complete setup instructions.

### Running Contract Validation

```bash
# Run locally (requires credentials)
CONTRACT_VALIDATION=1 go test -tags=contract ./contracts/aws/...

# Run all contract validations
CONTRACT_VALIDATION=1 go test -tags=contract ./contracts/...
```

### Weekly CI Job

The `contract-validation.yml` workflow runs every Sunday:

1. Hits real APIs with sandbox credentials
2. Validates responses match contract schemas
3. Creates GitHub issue if drift detected
4. Alerts maintainers to update contracts or code

### Test Utilities

```go
// Load a contract
contract := testutil.MustLoadContract("aws/iam")

// Create mock server
server := testutil.NewMockServer(contract)
defer server.Close()

// Get interaction response
body := contract.MustResponseBody("ListUsers")

// Validate response against schema
err := contract.ValidateResponse("ListUsers", actualResponse)

// Check if validation is enabled
if testutil.ContractValidationEnabled() {
    // Run real API tests
}
```

### Benefits

1. **Unit tests are fast**: No network calls, consistent responses
2. **Drift detection**: Weekly validation catches API changes
3. **Documentation**: Contracts document API dependencies
4. **Confidence**: Real API validation before releases

---

## Summary

1. **Unit tests**: Required for every PR, >80% coverage
2. **Policy tests**: Required for every policy
3. **Contract tests**: Required for every API integration
4. **Integration tests**: Run in CI with LocalStack
5. **Contract validation**: Run weekly against real APIs
6. **E2E tests**: Run before releases

Testing is not optional. It's a core part of the development process.
