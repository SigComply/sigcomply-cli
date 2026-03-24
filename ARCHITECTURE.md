# SigComply CLI - Architecture

**Version**: 2.1 | **Status**: Active Development

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
│   ATTESTATION   │  Generate ephemeral Ed25519 keypair
│                 │  Sign SHA-256 hashes of evidence
│                 │  Discard private key immediately
└────────┬────────┘
         ▼
┌─────────────────┐
│     STORAGE     │  Raw evidence + full results + public key + signature
│                 │  → Customer's S3/GCS/local   [everything stays here]
└────────┬────────┘
         │
    (paid tier, auto in CI when OIDC available)
         ▼
┌─────────────────────────────────────────┐
│   AGGREGATE     │  Reduce violations to counts (no resource IDs)
└────────┬────────┘  Aggregation boundary: resource identifiers discarded here
         ▼
┌─────────────────┐
│   CLOUD API     │  POST /api/v1/cli/runs (unified endpoint)
└─────────────────┘  Aggregated policy results → SigComply Cloud
                     Per-policy: pass/fail + resource counts (no ARNs, no usernames)
```

### What Goes Where

| Data | Customer Storage | SigComply Cloud |
|------|------------------|------------------|
| Raw evidence (API responses) | ✓ | ✗ |
| Policy inputs (OPA input) | ✓ | ✗ |
| Full CheckResult with all violation details (resource IDs, ARNs) | ✓ | ✗ |
| Ephemeral public key | ✓ | ✗ |
| Attestation signature | ✓ | ✗ |
| Per-policy results (pass/fail + severity + resource counts) | ✓ | ✓ |
| Compliance scores (aggregated) | ✓ | ✓ |
| Resource identifiers (ARNs, usernames, emails) | ✓ (S3 only) | ✗ (never) |

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
│       │   ├── iam.go, s3.go, cloudtrail.go
│       │   ├── ec2.go, ecr.go, rds.go, kms.go
│       │   └── guardduty.go, configservice.go, cloudwatch.go
│       ├── github/
│       │   ├── collector.go, repos.go, members.go
│       └── gcp/
│           ├── collector.go, iam.go, storage.go
│           ├── compute.go, sql.go
│
└── core/                       # Shared utilities
    ├── evidence/               # Evidence, Result, Violation types
    ├── config/                 # Configuration loading
    ├── output/                 # Text, JSON, SARIF formatters
    ├── storage/                # S3, GCS, local backends
    ├── attestation/            # Signing (ephemeral Ed25519), hashing, OIDC token providers
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

The attestation is stored entirely in the customer's S3 bucket. It is never sent to the SigComply Cloud API.

```go
type Attestation struct {
    ID             string            `json:"id"`
    RunID          string            `json:"run_id"`
    Framework      string            `json:"framework"`
    Timestamp      time.Time         `json:"timestamp"`
    Hashes         EvidenceHashes    `json:"hashes"`
    Signature      Signature         `json:"signature"`
    PublicKey      string            `json:"public_key"`     // Base64-encoded Ed25519 public key
    Environment    Environment       `json:"environment"`
    CLIVersion     string            `json:"cli_version,omitempty"`
    PolicyVersions map[string]string `json:"policy_versions,omitempty"`
}

type EvidenceHashes struct {
    CheckResult string            `json:"check_result"` // SHA-256 of CheckResult JSON
    Evidence    map[string]string `json:"evidence"`     // Evidence ID → SHA-256 hash
    Manifest    string            `json:"manifest,omitempty"`
    Combined    string            `json:"combined"`     // Single hash of all above
}

type Signature struct {
    Algorithm string `json:"algorithm"`  // ed25519
    Value     string `json:"value"`      // Base64-encoded Ed25519 signature over Combined hash
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

const (
    AlgorithmEd25519 = "ed25519"
)
```

#### Attestation Design Decisions

**Ephemeral keypair — no key management:**
- CLI generates a fresh Ed25519 keypair for every single run using Go stdlib (`crypto/ed25519`)
- Private key signs the `Combined` hash (canonical JSON of all evidence hashes), then is immediately discarded
- Public key is embedded in `attestation.json` stored in the customer's S3 bucket
- No secrets to distribute, rotate, or manage

**Purpose — auditor spot-checks only:**
- An auditor randomly selects a handful of evidence files to verify
- Auditor requests those files directly from the customer (out of band)
- Auditor verifies: hash the file → matches the hash in attestation → signature over hashes verifies with the embedded public key
- Confirms the evidence was not accidentally modified since collection
- This is not part of the core compliance workflow

**Threat model:**
- Protects against accidental corruption and unintentional evidence drift
- Does not attempt to prevent a determined customer from fabricating evidence (that is fraud — a legal matter, not a technical one, and out of scope for all compliance tools)

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
--policies string     Comma-separated policy names to run (e.g., cc6_1_mfa,cc6_1_github_mfa)
--controls string     Comma-separated control IDs to run (e.g., CC6.1,CC7.1)
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
SIGCOMPLY_POLICIES         # Comma-separated policy names to run
SIGCOMPLY_CONTROLS         # Comma-separated control IDs to run
SIGCOMPLY_STORAGE_BACKEND  # local, s3, gcs
SIGCOMPLY_STORAGE_BUCKET   # S3/GCS bucket name
```

### Cloud Authentication & Submission

Cloud submission uses OIDC authentication exclusively:

- **OIDC tokens** are automatically detected in GitHub Actions and GitLab CI.
- Cloud submission is **auto-enabled** when OIDC is available — no configuration needed.
- Use `--cloud` to force cloud submission, `--no-cloud` to disable it.
- The CLI submits a single unified payload via `POST /api/v1/cli/runs` containing aggregated policy results only.
- No attestation or evidence location is sent to the Rails app — those stay entirely in customer S3.
- The aggregation happens in the CLI before the API call: violations are reduced to counts, resource identifiers are discarded.

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

## Signing Method

Attestations are signed using **ephemeral Ed25519** keypairs. No pre-shared secrets or key management required.

```
keypair = ed25519.GenerateKey()               // fresh keypair every run
payload = CanonicalJSON(evidence_hashes)      // deterministic serialization
signature = ed25519.Sign(private_key, payload)
private_key.Discard()                         // immediately, never stored
attestation.json = { hashes, signature, public_key, ... }  → customer S3
```

**OIDC is authentication only** — the OIDC JWT token is sent in the `Authorization: Bearer` header to authenticate the CLI with the SigComply Cloud API. It is not used for signing attestations.

| Concern | Mechanism |
|---------|-----------|
| Attestation signing | Ephemeral Ed25519 keypair (private key discarded after signing) |
| Cloud API authentication | OIDC JWT in `Authorization: Bearer` header |
| Evidence privacy | Aggregation in CLI — counts sent to cloud, resource IDs stay in S3 |

---

## Free vs Paid Features

| Feature | Free | Paid |
|---------|------|------|
| Evidence collection | ✓ | ✓ |
| Policy evaluation | ✓ | ✓ |
| Local/S3/GCS storage | ✓ | ✓ |
| Attestation signing (ephemeral Ed25519) | ✓ | ✓ |
| Compliance dashboard (cloud) | - | ✓ |
| Drift detection (policy-level) | - | ✓ |
| Compliance score trends | - | ✓ |
| Auditor reports portal | - | ✓ |

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

### Release Automation

- **Auto-release** (`.github/workflows/auto-release.yml`): On every merge to main, analyzes conventional commit prefixes (`feat:` = minor, `fix:` = patch, `BREAKING CHANGE` = major), bumps the version tag, and runs GoReleaser.
- **Manual release** (`.github/workflows/release.yml`): Triggered via `workflow_dispatch` with a version input (e.g., `v0.2.0`). Creates tag and runs GoReleaser, then verifies installation on Ubuntu and macOS.
- **GoReleaser**: Builds cross-platform binaries. Uses `main.version`, `main.commit`, `main.buildTime` ldflags. Entry point is `.` (root `main.go`).
