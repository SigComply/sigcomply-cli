# SigComply CLI - Architecture

**Version**: 2.0 | **Status**: Ready for Implementation

For terminology, see [GLOSSARY.md](./GLOSSARY.md).

---

## Design Principles

| Principle | Implementation |
|-----------|----------------|
| Zero-config | `sigcomply check` works immediately with AWS defaults |
| Fail-safe | Partial success OK; missing permissions show warnings, not errors |
| Embedded policies | Rego policies compiled into binary via `go:embed` |
| Framework-specific | Each framework has its own policies (no shared abstractions) |
| Minimal abstractions | No interfaces until 2+ implementations needed |

---

## Architecture Overview

### Execution Flow

```
sigcomply check
       │
       ▼
┌─────────────────┐
│  CONFIGURATION  │  Auto-detect AWS, region, framework (SOC 2 default)
└────────┬────────┘
         ▼
┌─────────────────┐
│    COLLECT      │  AWS Collector → []Evidence (IAM, S3, CloudTrail)
└────────┬────────┘
         ▼
┌─────────────────┐
│    EVALUATE     │  OPA engine evaluates embedded Rego policies
└────────┬────────┘
         ▼
┌─────────────────┐
│     OUTPUT      │  Text/JSON/SARIF → Exit code (0=pass, 1=fail)
└────────┬────────┘
         │
    (if --store)
         ▼
┌─────────────────┐
│     STORAGE     │  Raw evidence + results → Customer's S3/GCS/local
└────────┬────────┘
         ▼
┌─────────────────┐
│   ATTESTATION   │  SHA-256 hashes + signature → Customer's storage
└────────┬────────┘
         │
    (paid tier, auto in CI when OIDC available)
         ▼
┌─────────────────┐
│   CLOUD API     │  POST /api/v1/cli/runs (unified endpoint)
└─────────────────┘  CheckResult + Attestation → SigComply Cloud
                     (NOT raw evidence - stays with customer)
```

### What Goes Where

| Data | Customer Storage | SigComply Cloud |
|------|------------------|------------------|
| Raw evidence (API responses) | ✓ | ✗ |
| Policy inputs (OPA input) | ✓ | ✗ |
| CheckResult (all violations) | ✓ | ✓ |
| Attestation (hashes + signature) | ✓ | ✓ |
| Evidence location reference | - | ✓ |

---

## Directory Structure

```
internal/
├── compliance_frameworks/      # Compliance logic
│   ├── engine/                 # OPA evaluation
│   │   ├── engine.go
│   │   └── registry.go
│   ├── shared/lib.rego         # Shared Rego helpers
│   ├── soc2/
│   │   ├── framework.go        # Framework interface
│   │   ├── controls.go         # Control mappings
│   │   └── policies/*.rego     # Embedded policies
│   ├── hipaa/
│   └── iso27001/
│
├── data_sources/               # Evidence collection
│   └── apis/
│       ├── aws/
│       │   ├── collector.go    # Auth + orchestration
│       │   ├── iam.go
│       │   ├── s3.go
│       │   └── cloudtrail.go
│       └── github/             # Future
│
└── core/                       # Shared utilities
    ├── evidence/               # Evidence, Result, Violation types
    ├── config/                 # Configuration loading
    ├── output/                 # Text, JSON, SARIF formatters
    ├── storage/                # S3, GCS, local backends
    ├── attestation/            # Signing (HMAC, OIDC, ECDSA)
    └── cloud/                  # SigComply Cloud client
```

---

## Core Types

### Type Safety

Status and severity use typed constants to prevent invalid values:

```go
// ResultStatus represents the outcome of a policy evaluation.
type ResultStatus string

const (
    StatusPass  ResultStatus = "pass"
    StatusFail  ResultStatus = "fail"
    StatusSkip  ResultStatus = "skip"
    StatusError ResultStatus = "error"
)

// Severity indicates the importance of a policy or violation.
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
)
```

### Evidence (Raw API Data)

```go
type Evidence struct {
    ID           string          `json:"id"`            // UUID
    Collector    string          `json:"collector"`     // "aws", "github"
    ResourceType string          `json:"resource_type"` // "aws:iam:user"
    ResourceID   string          `json:"resource_id"`   // ARN or unique ID
    Data         json.RawMessage `json:"data"`          // Raw API response
    Hash         string          `json:"hash"`          // SHA-256 of Data
    CollectedAt  time.Time       `json:"collected_at"`
    Metadata     Metadata        `json:"metadata"`
}

type Metadata struct {
    AccountID        string            `json:"account_id,omitempty"`
    Region           string            `json:"region,omitempty"`
    Tags             map[string]string `json:"tags,omitempty"`
    CollectorVersion string            `json:"collector_version,omitempty"`
}
```

### PolicyResult

```go
type PolicyResult struct {
    PolicyID           string       `json:"policy_id"`             // "soc2-cc6.1-mfa"
    ControlID          string       `json:"control_id"`            // "CC6.1"
    Status             ResultStatus `json:"status"`                // pass, fail, skip, error
    Severity           Severity     `json:"severity"`              // critical, high, medium, low
    Message            string       `json:"message"`               // Human-readable description
    Remediation        string       `json:"remediation,omitempty"` // How to fix violations
    ResourcesEvaluated int          `json:"resources_evaluated"`
    ResourcesFailed    int          `json:"resources_failed"`
    Violations         []Violation  `json:"violations,omitempty"`
}

type Violation struct {
    ResourceID   string                 `json:"resource_id"`             // "arn:aws:iam::123:user/alice"
    ResourceType string                 `json:"resource_type"`           // "aws:iam:user"
    Reason       string                 `json:"reason"`                  // "MFA is not enabled"
    Details      map[string]interface{} `json:"details,omitempty"`       // Additional context
}
```

### CheckResult (Complete Run Output)

```go
type CheckResult struct {
    RunID         string          `json:"run_id"`
    Framework     string          `json:"framework"`
    Timestamp     time.Time       `json:"timestamp"`
    PolicyResults []PolicyResult  `json:"policy_results"`
    Summary       CheckSummary    `json:"summary"`
    Environment   RunEnvironment  `json:"environment"`
}

type CheckSummary struct {
    TotalPolicies   int     `json:"total_policies"`
    PassedPolicies  int     `json:"passed_policies"`
    FailedPolicies  int     `json:"failed_policies"`
    SkippedPolicies int     `json:"skipped_policies"`
    ComplianceScore float64 `json:"compliance_score"` // 0.0 to 1.0
}

type RunEnvironment struct {
    CI         bool   `json:"ci"`                    // Running in CI/CD
    CIProvider string `json:"ci_provider,omitempty"` // "github-actions", "gitlab-ci"
    Repository string `json:"repository,omitempty"`  // "org/repo"
    Branch     string `json:"branch,omitempty"`
    CommitSHA  string `json:"commit_sha,omitempty"`
}
```

### Attestation

```go
type Attestation struct {
    ID              string            `json:"id"`
    RunID           string            `json:"run_id"`
    Framework       string            `json:"framework"`
    Timestamp       time.Time         `json:"timestamp"`
    Hashes          EvidenceHashes    `json:"hashes"`
    Signature       Signature         `json:"signature"`
    Environment     Environment       `json:"environment"`
    StorageLocation StorageLocation   `json:"storage_location"`  // NOT signed (see below)
    CLIVersion      string            `json:"cli_version,omitempty"`
    PolicyVersions  map[string]string `json:"policy_versions,omitempty"`
}

type EvidenceHashes struct {
    CheckResult string            `json:"check_result"` // SHA-256 of CheckResult JSON
    Evidence    map[string]string `json:"evidence"`     // Evidence ID → SHA-256 hash
    Manifest    string            `json:"manifest,omitempty"`
    Combined    string            `json:"combined"`     // Single hash of all above
}

type Signature struct {
    Algorithm   string `json:"algorithm"`   // hmac-sha256, oidc-jwt
    Value       string `json:"value"`       // Base64-encoded signature
    KeyID       string `json:"key_id,omitempty"`
    Certificate string `json:"certificate,omitempty"` // For OIDC
}

type Environment struct {
    CI           bool   `json:"ci"`
    Provider     string `json:"provider,omitempty"`     // github-actions, gitlab-ci
    Repository   string `json:"repository,omitempty"`
    Branch       string `json:"branch,omitempty"`
    CommitSHA    string `json:"commit_sha,omitempty"`
    WorkflowName string `json:"workflow_name,omitempty"`
    RunID        string `json:"run_id,omitempty"`
    Actor        string `json:"actor,omitempty"`
}

type StorageLocation struct {
    Backend      string `json:"backend"`       // local, s3, gcs
    Bucket       string `json:"bucket,omitempty"`
    Path         string `json:"path,omitempty"`
    ManifestPath string `json:"manifest_path,omitempty"`
    Encrypted    bool   `json:"encrypted,omitempty"`
}

const (
    AlgorithmHMACSHA256 = "hmac-sha256"
    AlgorithmOIDCJWT    = "oidc-jwt"
)
```

#### Attestation Design Decisions

**What's Signed vs What's Not:**

The attestation signature covers these fields:
- `ID`, `RunID`, `Framework`, `Timestamp`
- `Hashes` (evidence integrity)
- `Environment` (execution context)
- `CLIVersion`, `PolicyVersions` (reproducibility)

**`StorageLocation` is intentionally NOT signed** because:
- It's operational metadata that may change (e.g., evidence migration to different bucket)
- Changing storage location should not invalidate the cryptographic proof of evidence integrity
- The evidence hashes themselves prove integrity, regardless of where evidence is stored

**Canonical JSON Serialization:**

All hashing uses canonical JSON serialization (sorted map keys) to ensure deterministic output. This is critical because:
- Go's `map` iteration order is randomized
- `Violation.Details` is `map[string]interface{}`
- `Evidence.Metadata.Tags` is `map[string]string`
- Without canonical serialization, identical data could produce different hashes

**Version Information:**

`CLIVersion` and `PolicyVersions` enable:
- Reproducibility: auditors can verify which tools/policies were used
- Debugging: identify behavior differences between versions
- Compliance: prove consistent policy application over time

---

## Policy Evaluation

### Two Modes

| Mode | Use When | Input |
|------|----------|-------|
| **Individual** (default) | Check applies to each resource independently | Single resource |
| **Batched** | Check needs aggregate view | All matching resources |

**Individual**: "Does this user have MFA?" - evaluate per user
**Batched**: "At least one trail must be multi-region" - need all trails

### Policy Structure

```rego
# internal/compliance_frameworks/soc2/policies/cc6_1_mfa.rego
package sigcomply.soc2.cc6_1

metadata := {
    "id": "soc2-cc6.1-mfa",
    "name": "MFA Required for All Users",
    "framework": "soc2",
    "control": "CC6.1",
    "severity": "high",
    "evaluation_mode": "individual",
    "resource_types": ["aws:iam:user"],
}

violations[violation] if {
    input.resource_type == "aws:iam:user"
    not input.data.mfa_enabled
    violation := {
        "resource_id": input.resource_id,
        "resource_type": input.resource_type,
        "reason": sprintf("User %s does not have MFA enabled", [input.data.user_name]),
    }
}
```

---

## CLI Interface

### Commands

| Command | Description |
|---------|-------------|
| `sigcomply check` | Main: collect → evaluate → store → cloud submit |
| `sigcomply init` | Initialize config file |
| `sigcomply init-ci` | Generate CI/CD workflow files |
| `sigcomply collect` | Collect evidence only |
| `sigcomply evaluate` | Evaluate policies against stored evidence |
| `sigcomply report` | Generate compliance reports |

### Key Flags (check)

```
--framework string    Compliance framework (default: soc2)
--collector strings   Collectors to use (default: auto-detect)
-o, --output string   Output format: text, json, sarif
--fail-on-violation   Exit 1 on violations (default in CI)
--cloud / --no-cloud  Force/disable cloud submission
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Violations found |
| 2 | Execution error |
| 3 | Configuration error |

---

## Configuration

### Precedence (highest to lowest)

1. CLI flags
2. Environment variables (`SIGCOMPLY_*`)
3. Config file (`.sigcomply.yaml`)
4. Built-in defaults

### Minimal Config

```yaml
# .sigcomply.yaml - all settings optional
frameworks:
  - soc2

collectors:
  aws:
    regions:
      - us-east-1

storage:
  backend: local
  local:
    path: ./.sigcomply/evidence
```

### Key Environment Variables

```bash
SIGCOMPLY_FRAMEWORK        # Default framework
SIGCOMPLY_STORAGE_BACKEND  # local, s3, gcs
SIGCOMPLY_STORAGE_BUCKET   # S3/GCS bucket name
```

### Cloud Authentication & Submission

Cloud submission uses OIDC authentication exclusively:

- **OIDC tokens** are automatically detected in GitHub Actions and GitLab CI.
- Cloud submission is **auto-enabled** when OIDC is available — no configuration needed.
- Use `--cloud` to force cloud submission, `--no-cloud` to disable it.
- The CLI submits a single unified payload via `POST /api/v1/cli/runs` containing both the `CheckResult` and `Attestation`.
- The Rails app extracts derived data (hashes, scores, individual policy results) and discards resource-specific details (ARNs, repo names).

---

## Storage Layout

```
{bucket}/{prefix}/{framework}/{year}/{month}/{day}/{run_id}/
├── manifest.json           # Index with all file hashes
├── evidence/               # Raw API responses
│   ├── aws_iam_users.json
│   └── aws_s3_buckets.json
├── results/
│   └── check_result.json   # Full CheckResult
└── attestation.json        # Signed attestation
```

---

## Signing Methods

| Method | Environment | How |
|--------|-------------|-----|
| `none` | Local dev | No signature |
| `hmac-sha256` | Local/CI | `SIGCOMPLY_SIGNING_SECRET` env var |
| `oidc` | CI/CD | GitHub Actions / GitLab CI OIDC token |
| `ecdsa-p256` | Enterprise | Customer private key |

---

## Free vs Paid Features

| Feature | Free | Paid |
|---------|------|------|
| Evidence collection | ✓ | ✓ |
| Policy evaluation | ✓ | ✓ |
| Local/S3/GCS storage | ✓ | ✓ |
| Attestation generation | ✓ | ✓ |
| Drift detection | - | ✓ |
| Resource tracking | - | ✓ |
| Compliance trends | - | ✓ |
| Auditor portal | - | ✓ |

---

## Adding Components

### New Collector

1. Create `internal/data_sources/apis/<service>/`
2. Implement `Collect(ctx) ([]evidence.Evidence, error)`
3. Use fail-safe pattern (partial success OK)
4. Add unit tests with mocked client

### New Policy

1. Create `internal/compliance_frameworks/<framework>/policies/<control>.rego`
2. Include metadata with id, framework, control, severity, evaluation_mode
3. Create `_test.rego` file
4. Policy auto-embedded on build

### New Framework

1. Create `internal/compliance_frameworks/<framework>/`
2. Implement `framework.go` with Framework interface
3. Create `controls.go` with control mappings
4. Create `policies/` with at least one policy
5. Register in `engine/registry.go`

---

## Testing

```bash
make test           # Unit tests + policy tests
make test-policy    # OPA policy tests only
make test-integration  # Requires LocalStack
```

**Mock pattern**: Define interface for AWS SDK methods you use, inject mock in tests.

---

## CI/CD Integration

### GitHub Actions (Customer Usage)

```yaml
# .github/workflows/compliance.yml
name: Compliance
on: [push, pull_request]

jobs:
  check:
    uses: sigcomply/sigcomply-cli/.github/workflows/compliance.yml@v1
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

Uses OIDC for AWS authentication (no long-lived secrets).
