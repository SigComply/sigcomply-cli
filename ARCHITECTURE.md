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
│     OUTPUT      │  Text/JSON/JUnit → Exit code (0=pass, 1=fail)
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
    ├── output/                 # Text, JSON, JUnit formatters
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
    Organization     string            `json:"organization,omitempty"`
    Tags             map[string]string `json:"tags,omitempty"`
    CollectorVersion string            `json:"collector_version,omitempty"`
}
```

### PolicyResult

```go
type PolicyResult struct {
    PolicyID           string       `json:"policy_id"`              // "soc2-cc6.1-mfa"
    ControlID          string       `json:"control_id"`             // "CC6.1"
    Name               string       `json:"name"`                   // Human-readable policy name
    Status             ResultStatus `json:"status"`                 // pass, fail, skip, error
    Severity           Severity     `json:"severity"`               // critical, high, medium, low
    Message            string       `json:"message"`                // Human-readable description
    Remediation        string       `json:"remediation,omitempty"`  // How to fix violations
    ResourcesEvaluated int          `json:"resources_evaluated"`
    ResourcesFailed    int          `json:"resources_failed"`
    Violations         []Violation  `json:"violations,omitempty"`
    ResourceTypes      []string     `json:"resource_types,omitempty"` // e.g. ["aws:iam:user"]
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
    CI         bool   `json:"ci"`                     // Running in CI/CD
    CIProvider string `json:"ci_provider,omitempty"`  // "github-actions", "gitlab-ci"
    Repository string `json:"repository,omitempty"`   // "org/repo"
    Branch     string `json:"branch,omitempty"`
    CommitSHA  string `json:"commit_sha,omitempty"`
    CLIVersion string `json:"cli_version,omitempty"`  // Version of the CLI
}
```

### EvidenceEnvelope

Each evidence file stored in the customer's S3 bucket is a self-contained signed envelope. It is never sent to the SigComply Cloud API.

```go
// EvidenceEnvelope is the file format for every evidence file stored in S3.
// Each file is independently verifiable — an auditor can pick any single file
// and verify its integrity without needing any other file or contacting SigComply.
type EvidenceEnvelope struct {
    // Signed is the payload covered by the cryptographic signature.
    // Only this field is included when computing the signature.
    Signed SignedPayload `json:"signed"`

    // PublicKey is the base64-encoded Ed25519 public key used to sign this file.
    // The corresponding private key was discarded immediately after signing.
    PublicKey string `json:"public_key"`

    // Signature contains the cryptographic signature over Signed.
    Signature Signature `json:"signature"`
}

// SignedPayload is the tamper-evident core of an EvidenceEnvelope.
// Adding or removing fields here changes what is covered by the signature.
type SignedPayload struct {
    // Timestamp is when the evidence was collected.
    // Enables an auditor to confirm the evidence falls within the audit period.
    // S3 object mtimes can be modified; this field cannot be changed without
    // invalidating the signature.
    Timestamp time.Time       `json:"timestamp"`

    // Evidence is the raw API response data collected from the source service.
    Evidence  json.RawMessage `json:"evidence"`
}

type Signature struct {
    Algorithm string `json:"algorithm"` // "ed25519"
    Value     string `json:"value"`     // Base64-encoded Ed25519 signature
}

const AlgorithmEd25519 = "ed25519"
```

**On-disk format examples**:

`evidence/aws-iam-users.json` (automated — `evidence` is the raw API response):

```json
{
  "signed": {
    "timestamp": "2026-03-25T10:00:00Z",
    "evidence": { "users": [...], "mfa_devices": [...] }
  },
  "public_key": "base64encodedEd25519PublicKey==",
  "signature": {
    "algorithm": "ed25519",
    "value": "base64encodedSignatureBytes=="
  }
}
```

`evidence/manual-employee_nda.json` (manual — `evidence` is the manifest; the PDF is the sibling file at `file_path`):

```json
{
  "signed": {
    "timestamp": "2026-03-25T10:00:00Z",
    "evidence": {
      "evidence_id": "employee_nda",
      "framework":   "soc2",
      "period":      "2026",
      "file_path":   "manual_attachments/employee_nda/evidence.pdf",
      "file_hash":   "9a1b2c3d4e5f...sha256hex"
    }
  },
  "public_key": "base64encodedEd25519PublicKey==",
  "signature": {
    "algorithm": "ed25519",
    "value": "base64encodedSignatureBytes=="
  }
}
```

### PolicyRunResult

Stored as `result.json` in each policy run folder. Contains the full policy evaluation output including violation details with resource identifiers. Never sent to the SigComply Cloud API — stays entirely in customer storage.

```go
// PolicyRunResult is stored as result.json for each policy run in customer S3.
// It contains the complete evaluation output. The cloud API receives only the
// aggregated counts (resources_evaluated, resources_failed) — never the violations.
type PolicyRunResult struct {
    PolicyID           string       `json:"policy_id"`           // "cc6_1_mfa"
    ControlID          string       `json:"control_id"`          // "CC6.1"
    Framework          string       `json:"framework"`           // "soc2"
    RunID              string       `json:"run_id"`              // UUID shared across all policies in one run
    Timestamp          time.Time    `json:"timestamp"`
    Status             ResultStatus `json:"status"`              // pass, fail, skip, error
    Severity           Severity     `json:"severity"`
    ResourcesEvaluated int          `json:"resources_evaluated"`
    ResourcesFailed    int          `json:"resources_failed"`
    Violations         []Violation  `json:"violations,omitempty"` // Full resource IDs — never leave S3
    EvidenceFiles      []string     `json:"evidence_files"`       // Relative paths: ["evidence/aws-iam-users.json"]
    CLIVersion         string       `json:"cli_version"`          // e.g., "1.2.3"
    CLISHA             string       `json:"cli_sha"`              // Git SHA of the CLI binary
    RepoSHA            string       `json:"repo_sha"`             // Git SHA of the customer's repository
}
```

**On-disk format example** (`result.json`):

```json
{
  "policy_id": "cc6_1_mfa",
  "control_id": "CC6.1",
  "framework": "soc2",
  "run_id": "a3f8b2c1-...",
  "timestamp": "2026-03-25T10:00:00Z",
  "status": "fail",
  "severity": "high",
  "resources_evaluated": 42,
  "resources_failed": 3,
  "violations": [
    { "resource_id": "arn:aws:iam::123456789:user/alice", "resource_type": "aws:iam:user", "reason": "MFA not enabled" },
    { "resource_id": "arn:aws:iam::123456789:user/bob",   "resource_type": "aws:iam:user", "reason": "MFA not enabled" }
  ],
  "evidence_files": ["evidence/aws-iam-users.json", "evidence/github-members.json"],
  "cli_version": "1.2.3",
  "cli_sha": "abc123def456",
  "repo_sha": "789abc012def"
}
```

#### Attestation Design Decisions

**Per-file envelope signing — not a single run-level attestation:**
- Each evidence file is independently wrapped in a signed envelope (`EvidenceEnvelope`)
- A fresh ephemeral Ed25519 keypair is generated per evidence file; private key discarded immediately after signing
- The public key and signature travel with the file — no separate `attestation.json` manifest needed
- An auditor can pick any single evidence file and verify it independently without needing any other artifact

**Why not one signature over all files combined:**
- A combined hash would require a separate manifest listing all files in the run
- It would also require the auditor to obtain the full manifest to verify a single file
- Per-file signing is simpler, self-contained, and maps naturally to the policy-first folder structure where each policy folder is independently auditable

**Threat model:**
- Protects against accidental corruption and unintentional evidence drift
- The `timestamp` in `SignedPayload` proves when evidence was collected — S3 object mtimes can be modified, but the signed timestamp cannot be changed without invalidating the signature
- Does not attempt to prevent a determined customer from fabricating evidence (that is fraud — a legal matter, not a technical one, and out of scope for all compliance tools)

**Canonical JSON for deterministic signing:**
The `evidence` field is `json.RawMessage` (raw API response). When serializing `SignedPayload` for signing, canonical JSON (sorted map keys) is used to ensure the same data always produces the same bytes regardless of Go map iteration order. This is required for the verifier to reproduce the same bytes and confirm the signature.

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

**Automated policy** — consumes structured JSON from an API collector:

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
    "evidence_type": "automated",
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

**Manual policy** — checks PDF presence within the temporal window. The body delegates to the shared `manual.presence_violation` helper; per-policy text-extraction rules layer on top in the future.

```rego
# internal/compliance_frameworks/soc2/policies/manual/cc1_1_employee_nda.rego
package sigcomply.soc2.cc1_1_employee_nda

import data.sigcomply.lib.manual

metadata := {
    "id":              "soc2-cc1.1-employee-nda",
    "name":            "Employee NDA Acknowledgment",
    "framework":       "soc2",
    "control":         "CC1.1",
    "severity":        "high",
    "evaluation_mode": "individual",
    "resource_types":  ["manual:employee_nda"],
    "evidence_type":   "manual",
}

violations contains v if {
    input.resource_type == "manual:employee_nda"
    v := manual.presence_violation(input)
}
```

**`evidence_type`**: every policy declares this (`automated` or `manual`). The engine extracts the value from `metadata` at load time and uses it to route the right evidence flow. During the migration, missing values default to `automated` with a one-time warning; once all policies are tagged, the default is removed and a missing `evidence_type` becomes a load-time error.

---

## CLI Interface

### Commands

| Command | Description | Status |
|---------|-------------|--------|
| `sigcomply check` | Main: collect → evaluate → store → cloud submit | Implemented |
| `sigcomply version` | Print version information | Implemented |
| `sigcomply init` | Initialize config file | Planned |
| `sigcomply init-ci` | Generate CI/CD workflow files | Planned |
| `sigcomply collect` | Collect evidence only | Planned |
| `sigcomply evaluate` | Evaluate policies against stored evidence | Planned |
| `sigcomply report` | Generate compliance reports | Planned |

### Key Flags (check)

```
--framework string    Compliance framework (default: soc2)
--collector strings   Collectors to use (default: auto-detect)
--policies string     Comma-separated policy names to run (e.g., cc6_1_mfa,cc6_1_github_mfa)
--controls string     Comma-separated control IDs to run (e.g., CC6.1,CC7.1)
-o, --output string   Output format: text, json, junit
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

Evidence is organized **policy-first**: each policy has its own folder with a chronological history of runs. This maps directly to how auditors work — they review one policy at a time across the audit period.

```
{bucket}/
└── {framework}/                                      # e.g., soc2
    ├── summary.json                                  # framework snapshot — last run, totals, per-policy state
    ├── execution-state.json                          # manual evidence ledger (per-period status, file_hash)
    └── {policy_id}/                                  # e.g., cc6_1_mfa
        └── {timestamp}_{run_id_8chars}/              # e.g., 20260325T100000Z_a3f8b2c1
            ├── evidence/
            │   ├── aws-iam-users.json                # EvidenceEnvelope (signed, automated)
            │   ├── github-members.json               # EvidenceEnvelope (signed, automated)
            │   └── manual-{evidence_id}.json         # EvidenceEnvelope wrapping the manual manifest
            ├── manual_attachments/                   # only for policies with evidence_type: manual
            │   └── {evidence_id}/
            │       └── evidence.pdf                  # SPA-generated or user-supplied PDF (sole evidence artifact)
            └── result.json                           # PolicyRunResult (full violations — stays in S3)
```

### Key Design Decisions

**Policy-first hierarchy** — navigating to `soc2/cc6_1_mfa/` gives a chronological history of every MFA check run. An auditor can inspect all evidence and results for a policy across the entire audit period without any cross-referencing.

**Run folder naming** — `{ISO8601_basic_timestamp}_{first_8_chars_of_run_uuid}`. Basic ISO 8601 (no colons, e.g. `20260325T100000Z`) is used instead of extended format to avoid path issues in some S3-compatible tools. The run UUID suffix eliminates collision risk if the check runs twice in the same second.

**Evidence duplication** — The same raw evidence (e.g., IAM users) is stored independently in every policy folder that uses it, each with its own signed envelope and ephemeral keypair. The API call to collect the data happens once per run; the data is then written to each relevant policy folder. This makes each policy folder fully self-contained: an auditor verifying CC6.1 has everything they need without cross-referencing other policy folders.

**No manifest file** — There is no top-level `manifest.json`. Each evidence file carries its own cryptographic proof (see `EvidenceEnvelope`). The `result.json` lists which evidence files were used for the policy evaluation via `evidence_files`.

**Manual evidence sidecars** — When a policy with `evidence_type: manual` runs, the user-supplied `evidence.pdf` is mirrored from the manual-evidence bucket into the policy's run folder under `manual_attachments/{evidence_id}/evidence.pdf`. The matching `EvidenceEnvelope` inside `evidence/` (named `manual-{evidence_id}.json`) wraps a small manifest `{evidence_id, file_hash, file_path, period, framework}` — the PDF is the sibling, never base64-embedded inside the envelope. The same PDF may be duplicated across policy folders — auditors verify each policy from a single self-contained folder rather than cross-referencing the manual bucket.

**Framework summary** — `{framework}/summary.json` is a per-policy snapshot showing, in one file, which policies passed and what evidence backed each result. Built after every `StoreRun`. Policies are split into `automated` and `manual` based on the policy's `evidence_type` metadata. For manual policies the snapshot records `file_hash` and `file_path` of the PDF that backed the result. Writes merge with the existing summary so policies skipped by `--policies` / `--controls` filters keep their last-known state instead of being erased.

> **TODO**: Add a `check_runs_history/` root folder inside each framework folder containing:
> - A `run_history.json` tracking all historical runs (run_id, timestamp, policies evaluated, overall status)
> - A `policy_frequency.json` defining how often each policy should run (e.g., daily, weekly, monthly)
> The CLI will read `policy_frequency.json` and `run_history.json` to skip policies that have already run within their configured frequency window. This enables mixed-cadence compliance checks where some policies run daily and others monthly, all within a single `sigcomply check` invocation.

---

## Signing Method

Evidence files are signed using **ephemeral Ed25519** keypairs — one fresh keypair per evidence file. No pre-shared secrets or key management required.

```
// For each evidence file collected (automated or manual):
keypair = ed25519.GenerateKey()                    // fresh keypair, never reused
payload = CanonicalJSON({ timestamp, evidence })   // deterministic serialization
                                                    // automated → evidence is the API response
                                                    // manual    → evidence is { evidence_id,
                                                    //             file_hash, file_path,
                                                    //             period, framework }
signature = ed25519.Sign(private_key, payload)
private_key.Discard()                              // immediately, never stored

evidence_file.json = {
    signed:     { timestamp, evidence },           // the signed payload
    public_key: base64(public_key),               // stays with the file
    signature:  { algorithm: "ed25519",
                  value: base64(signature) },
} → customer S3

// For manual evidence, the PDF lives as a sibling file at
// manual_attachments/{evidence_id}/evidence.pdf. The envelope's `file_hash`
// is sha256(PDF bytes); the auditor recomputes that hash and compares.
```

**Verification** (auditor, out of band):
```
envelope = read(evidence_file.json)
payload  = CanonicalJSON(envelope.signed)
ed25519.Verify(decode(envelope.public_key), payload, decode(envelope.signature.value))
// → true: file is intact since collection

// For manual evidence, additionally:
pdf_bytes = read(envelope.signed.evidence.file_path)
sha256(pdf_bytes) == envelope.signed.evidence.file_hash
// → true: PDF is the one this envelope references
```

**OIDC is authentication only** — the OIDC JWT token is sent in the `Authorization: Bearer` header to authenticate the CLI with the SigComply Cloud API. It is not used for signing evidence files.

| Concern | Mechanism |
|---------|-----------|
| Evidence signing | Ephemeral Ed25519 keypair per file (private key discarded after signing) |
| Cloud API authentication | OIDC JWT in `Authorization: Bearer` header |
| Evidence privacy | Aggregation in CLI — counts sent to cloud, resource IDs stay in S3 |

---

## Free vs Paid Features

| Feature | Free | Paid |
|---------|------|------|
| Evidence collection | ✓ | ✓ |
| Policy evaluation | ✓ | ✓ |
| Local/S3/GCS storage | ✓ | ✓ |
| Evidence signing (ephemeral Ed25519 per file) | ✓ | ✓ |
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

1. **Automated**: create `internal/compliance_frameworks/<framework>/policies/<control>.rego`. Set `"evidence_type": "automated"` in `metadata`. Body reads `input.data.*` fields from the collector's JSON.
2. **Manual**: create `internal/compliance_frameworks/<framework>/policies/manual/<control>.rego`. Set `"evidence_type": "manual"` in `metadata`, with `"resource_types": ["manual:<evidence_id>"]`. Body delegates to `data.sigcomply.lib.manual.presence_violation(input)` (presence + temporal-window check). Add a corresponding catalog entry in `internal/core/manual/catalogs/<framework>.yaml`.
3. Always include in `metadata`: `id`, `name`, `framework`, `control`, `severity`, `evaluation_mode`, `resource_types`, `evidence_type`.
4. Create a `_test.rego` file. Manual tests cover three cases: overdue+not_uploaded, uploaded, and wrong-resource-type.
5. Policy auto-embedded on build.

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
