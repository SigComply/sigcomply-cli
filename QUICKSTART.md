# SigComply CLI - Developer Quickstart

**Time to first PR**: 30 minutes

---

## Prerequisites

- Go 1.22+
- AWS CLI configured (`aws configure`)
- Git

```bash
# Verify prerequisites
go version      # go version go1.22.x
aws sts get-caller-identity  # Should return your account info
```

---

## Setup (5 minutes)

```bash
# Clone the repository
git clone https://github.com/sigcomply/sigcomply-cli.git
cd sigcomply-cli

# Install dependencies
go mod download

# Build
make build

# Verify
./bin/sigcomply version
```

---

## Run Tests (2 minutes)

```bash
# Run all fast tests
make test

# Run with verbose output
make test-unit

# Run policy tests
make test-policy
```

---

## Project Structure

```
sigcomply-cli/
├── cmd/                    # CLI commands (Cobra)
│   ├── root.go            # Entry point
│   ├── check.go           # Main compliance check
│   └── version.go         # Version info
│
├── internal/              # Application code
│   ├── aws/              # AWS evidence collector
│   ├── policy/           # OPA engine + embedded policies
│   ├── scanner/          # Secret scanner
│   ├── storage/          # S3 storage
│   ├── attestation/      # HMAC signing
│   └── output/           # Formatters
│
├── test/                  # E2E tests
└── Makefile              # Build commands
```

---

## Common Tasks

### Add a new AWS resource collector

1. Add collection function to `internal/aws/`:

```go
// internal/aws/rds.go
package aws

import (
    "context"
    "github.com/aws/aws-sdk-go-v2/service/rds"
)

func (c *Collector) collectRDSInstances(ctx context.Context) ([]Evidence, error) {
    output, err := c.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
    if err != nil {
        return nil, err
    }

    var evidence []Evidence
    for _, db := range output.DBInstances {
        evidence = append(evidence, Evidence{
            ID:           uuid.NewString(),
            Collector:    "aws",
            ResourceType: "aws:rds:instance",
            ResourceID:   *db.DBInstanceArn,
            Data: map[string]interface{}{
                "identifier":          *db.DBInstanceIdentifier,
                "engine":              *db.Engine,
                "storage_encrypted":   db.StorageEncrypted,
                "publicly_accessible": db.PubliclyAccessible,
            },
        })
    }
    return evidence, nil
}
```

2. Add test:

```go
// internal/aws/rds_test.go
func TestCollectRDSInstances(t *testing.T) {
    tests := []struct {
        name    string
        dbs     []types.DBInstance
        want    int
    }{
        {"no instances", []types.DBInstance{}, 0},
        {"one instance", []types.DBInstance{{...}}, 1},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mock := &mockRDSClient{instances: tt.dbs}
            collector := &Collector{rdsClient: mock}
            evidence, err := collector.collectRDSInstances(context.Background())
            assert.NoError(t, err)
            assert.Len(t, evidence, tt.want)
        })
    }
}
```

3. Wire into collector:

```go
// internal/aws/collector.go
func (c *Collector) Collect(ctx context.Context) ([]Evidence, error) {
    // ... existing code ...

    if rds, err := c.collectRDSInstances(ctx); err != nil {
        errors = append(errors, err)
    } else {
        evidence = append(evidence, rds...)
    }

    return evidence, nil
}
```

### Add a new policy

1. Create policy file:

```rego
# internal/policy/policies/soc2_cc6_3_rds_encryption.rego
package sigcomply.soc2.cc6_3

import future.keywords.if

default violations = []

violations = result if {
    input.resource_type == "aws:rds:instance"
    not input.data.storage_encrypted

    result := [{
        "control_id": "CC6.3",
        "control_name": "RDS Encryption Required",
        "resource_id": input.resource_id,
        "severity": "high",
        "message": sprintf("RDS instance %s does not have storage encryption enabled",
                          [input.data.identifier]),
        "remediation": "Enable encryption when creating new RDS instances",
    }]
}
```

2. Create test file:

```rego
# internal/policy/policies/soc2_cc6_3_rds_encryption_test.rego
package sigcomply.soc2.cc6_3

test_unencrypted_rds_fails {
    result := violations with input as {
        "resource_type": "aws:rds:instance",
        "resource_id": "arn:aws:rds:...",
        "data": {
            "identifier": "my-database",
            "storage_encrypted": false,
        }
    }
    count(result) == 1
}

test_encrypted_rds_passes {
    result := violations with input as {
        "resource_type": "aws:rds:instance",
        "resource_id": "arn:aws:rds:...",
        "data": {
            "identifier": "my-database",
            "storage_encrypted": true,
        }
    }
    count(result) == 0
}
```

3. Run tests:

```bash
make test-policy
```

That's it! Policy is automatically embedded in the next build.

---

## Make Commands

```bash
make build          # Build binary to ./bin/sigcomply
make test           # Run unit + policy tests
make test-unit      # Run unit tests only
make test-policy    # Run policy tests only
make test-coverage  # Generate coverage report
make lint           # Run linter
make clean          # Clean build artifacts
```

---

## Development Workflow

```bash
# 1. Create feature branch
git checkout -b feature/add-rds-collector

# 2. Make changes
# ... edit files ...

# 3. Run tests
make test

# 4. Run linter
make lint

# 5. Commit
git add .
git commit -m "Add RDS instance collector and encryption policy"

# 6. Push and create PR
git push origin feature/add-rds-collector
```

---

## Key Files to Know

| File | Purpose |
|------|---------|
| `cmd/sigcomply/main.go` | CLI entry point |
| `internal/aws/collector.go` | AWS evidence collection |
| `internal/policy/engine.go` | OPA policy evaluation |
| `internal/policy/policies/*.rego` | Compliance policies |
| `Makefile` | Build commands |

---

## Getting Help

- Architecture: [ARCHITECTURE.md](./ARCHITECTURE.md)
- Testing: [TESTING_STRATEGY.md](./TESTING_STRATEGY.md)
- Implementation: [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)

---

## First PR Ideas

1. **Add a new AWS resource collector** (EC2, RDS, Lambda)
2. **Add a new policy** (check existing resource types)
3. **Improve test coverage** (add test cases)
4. **Fix a bug** (check issues)
5. **Improve documentation** (clarify confusing sections)

---

Good luck and happy coding!
