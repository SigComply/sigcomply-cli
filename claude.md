# SigComply CLI - Claude Context

This document provides context for AI assistants (like Claude) working on the SigComply CLI project.

---

## IMPORTANT: Check for Local Instructions

**Before starting any work, check if `CLAUDE.local.md` exists in the repository root.**

If present, read it first and follow its instructions. The local file contains:
- Private integration references not suitable for public documentation
- Additional context for maintaining consistency with external systems
- Instructions that override or supplement this public document

The local file is gitignored and will not be present in all environments.

---

## Documentation

Key documents for development:

1. **[ARCHITECTURE.md](./ARCHITECTURE.md)** - System architecture, types, and design
2. **[docs/configuration.md](./docs/configuration.md)** - Configuration guide (config file, env vars, CLI flags)
3. **[docs/claude/auth.md](./docs/claude/auth.md)** - OIDC authentication details
4. **[docs/claude/recipes.md](./docs/claude/recipes.md)** - Step-by-step guides for common tasks

---

## CRITICAL: Development Rules for AI Agents

**These rules MUST be followed when implementing any feature or sub-component.**

### Guiding Principle: Ship Working Code

**Working, tested code is the primary measure of progress.**

Documentation exists to enable shipping, not as an end in itself. Apply these guidelines:

1. **Don't over-document** - Docs should be minimal viable, not comprehensive. Ask: "Would another AI session actually need this information?"

2. **Only update docs when architecture changes** - Bug fixes, small features, and refactors rarely need doc updates. Only update when:
   - New components/patterns are introduced
   - Existing design decisions change
   - The implementation deviates from documented architecture

3. **Time check** - If you're spending more than 10-15% of a session on documentation, something is wrong. Pause and ask.

4. **"Good enough" over "perfect"** - A working feature with minimal docs beats a documented feature that doesn't exist.

5. **Code is documentation** - Well-written code with clear names and simple tests often needs no additional docs.

### Rule 1: Test-Driven Development (TDD)

For each new feature or sub-component:

1. **Write unit tests first** - Define expected behavior through tests before writing implementation
2. **Write a basic integration test** - Create the simplest possible integration test that verifies components connect correctly (happy path only, avoid complexity)
3. **Implement the code** - Write the minimum code needed to make tests pass
4. **Verify all tests pass** - Run the full test suite to ensure no regressions
5. **Update documentation** - After the feature is complete, revise and update relevant documentation files (ARCHITECTURE.md, CLAUDE.md as needed)

```bash
# TDD workflow
make test          # Run unit tests
make test-integration  # Run integration tests (if applicable)
make lint          # Ensure code quality
```

### Rule 2: Architecture-First Implementation

Before starting any implementation:

1. **Read existing documentation** - Review ARCHITECTURE.md and relevant sections of CLAUDE.md to understand the full context
2. **Create an implementation plan** - Outline the specific files to create/modify, types needed, and how the feature fits into existing architecture
3. **Evaluate complexity** - If the existing architecture makes implementation overly complicated or convoluted:
   - **STOP and ask the user** to explain the complexity
   - Present your concerns clearly: "The current design requires X, Y, Z which seems overly complex because..."
   - Wait for guidance before proceeding—the design may need to be re-evaluated
4. **Proceed only when the path is clear** - Implementation should feel straightforward given good architecture. Difficulty is a signal to pause.

**Why this matters**: Detailed architecture documentation exists so you have full end-to-end context. If that context makes things harder rather than easier, something is wrong.

### Rule 3: Small, Atomic Commits

Each feature or sub-component should result in small, working, tested commits:

1. **One logical change per commit** - Don't bundle unrelated changes
2. **Each commit should pass all tests** - Never commit broken code
3. **Commit message format**:
   ```
   <type>: <short description>

   <detailed explanation if needed>

   Co-Authored-By: Claude <model> <noreply@anthropic.com>
   ```
   Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

4. **Commit frequently** - Don't build large features in one go without intermediate checkpoints
5. **Push after completing each feature** - Keep remote in sync

**Why this matters**:
- Creates natural rollback points if something goes wrong
- Forces incremental verification
- Makes code review manageable
- Prevents "big bang" integration failures

### Rule 4: Never Break the Main Branch

**The main branch must ALWAYS have a green CI pipeline. A broken main build is unacceptable.**

Before every commit and push, follow this mandatory workflow:

1. **Run all local checks before committing**:
   ```bash
   make test              # All unit tests must pass
   make test-integration  # All integration tests must pass (if applicable)
   make lint              # All linting checks must pass
   ```
   Do NOT commit if any of these fail. Fix the issue first.

2. **After pushing, verify the GitHub Actions pipeline**:
   - Push the commit to the remote
   - Wait 2-3 minutes for the GitHub Actions pipeline to start and complete
   - Use `gh run list --branch <branch> --limit 5` to check the pipeline status
   - Use `gh run view <run-id>` to inspect details if needed

3. **If the pipeline fails**:
   - Immediately investigate the failure: `gh run view <run-id> --log-failed`
   - Identify the root cause (test failure, lint error, build error, etc.)
   - Fix the issue locally
   - Run all local checks again (`make test && make lint`)
   - Commit the fix and push
   - Wait and verify the pipeline is green again
   - Repeat until the pipeline is fully green

4. **Do NOT move on to the next task until the pipeline is green**. The current unit of work is not complete until CI is passing.

**Why this matters**:
- A broken main branch blocks all other contributors
- CI failures compound — fixing them later is harder than fixing them now
- Green CI is the team's contract for code quality
- Every commit on main should be deployable

### Summary Checklist

Before implementing any feature, verify:

- [ ] I have read the relevant architecture documentation
- [ ] I have a clear implementation plan
- [ ] The design doesn't feel overly complicated (if it does, STOP and ask)
- [ ] I will write tests before implementation
- [ ] I will make small, atomic commits
- [ ] Before each commit: `make test && make lint` pass locally
- [ ] After each push: GitHub Actions pipeline is green (verified via `gh run list`)
- [ ] If CI fails: fix, push, and verify green before moving on
- [ ] I will update documentation after completion

---

## Project Purpose

SigComply CLI is an open-source compliance automation engine that enables organizations to achieve SOC 2, ISO 27001, and HIPAA readiness without granting third-party vendors access to their production infrastructure.

**Core Philosophy**: "Evidence without Access" - a non-custodial approach to compliance automation.

---

## Technical Stack

- **Language**: Go (Golang)
- **Policy Engine**: Open Policy Agent (OPA) with Rego policies
- **Authentication**: OIDC tokens for authenticating with the SigComply Cloud API and third-party services (AWS, GCP, Azure, etc.). Fallback to traditional credentials when OIDC unavailable.
- **Attestation Signing**: Ephemeral Ed25519 keypair generated per run. Private key is discarded immediately after signing. Public key + signature + raw evidence are all stored in the customer's S3 bucket. Purpose: auditor spot-checks (verify evidence not accidentally tampered with). Not part of the core workflow.
- **Cryptography**: SHA-256 hashing for evidence integrity, Ed25519 for attestation signing
- **Configuration**: YAML-based configuration files
- **Distribution**: Single binary executable
- **CI/CD**: GitHub Actions reusable workflows, GitLab CI components

---

## Architecture Overview

### 1. The 2-Repo Architecture

SigComply uses a two-repository architecture that balances transparency with business security:

**Repo 1: sigcomply-cli (This Repository - PUBLIC)**
- The "Front-of-House" / Distribution Layer
- Contains the Go CLI source code
- Open-source compliance policies (YAML/Rego)
- GitHub Reusable Workflows (`.github/workflows/`)
- GitLab CI/CD Components (using `spec:inputs`)
- Installation scripts (`curl | sh` setup)
- Complete transparency for security-conscious teams

**Repo 2: sigcomply-cloud (PRIVATE)**
- The "Compliance Dashboard" layer
- Rails-based backend application
- Stores only aggregated policy results (counts, scores, per-policy pass/fail)
- Handles billing and subscription management
- Provides auditor portal and compliance reporting
- Never stores raw evidence, resource identifiers, or PII

This separation ensures:
- Compliance logic remains open and auditable
- Business logic and customer data remain secure
- Customers can inspect exactly what runs in their environment
- SigComply can iterate on backend features independently

### 2. CLI Execution Flow

```
User Environment
    ↓
[SigComply CLI]
    ↓
    ├─> Fetch data from Service APIs (AWS, GitHub, etc.)
    │   Each evidence file collected is immediately wrapped in a signed envelope:
    │   { signed: { timestamp, evidence }, public_key, signature }
    │   Private key discarded immediately after signing.
    │
    ├─> Execute OPA/Rego policies against collected evidence locally
    ├─> Generate PolicyRunResult per policy (with full violations + resource IDs)
    │
    ├─> Store to customer's storage (S3, GCS, local):   [ALL stays with customer]
    │   Per policy, per run:
    │   ├─> evidence/aws-iam-users.json    (EvidenceEnvelope — signed, self-contained)
    │   ├─> evidence/github-members.json  (EvidenceEnvelope — signed, self-contained)
    │   └─> result.json                   (PolicyRunResult — full violations + cli_sha + repo_sha)
    │
    └─> Send to SigComply Cloud API (paid tier):        [Aggregated only, no PII]
        ├─> Per-policy results: policy_id + pass/fail + severity
        ├─> Aggregated counts: resources_evaluated, resources_failed
        └─> Compliance scores: overall + per-control (no individual resource details)
```

**Aggregation boundary**: The CLI aggregates raw results into counts before sending anything to the Cloud API. Resource identifiers (ARNs, usernames, email addresses, account IDs) never leave the customer's environment.

**Example**: "3 users without MFA" is sent to Rails. The list of which users never leaves customer S3.

### 3. Key Components

#### Evidence Collection
- CLI connects to various service APIs using customer's local credentials
- Fetches infrastructure state, configuration, logs, user data, etc.
- Each collected evidence file is immediately wrapped in a signed `EvidenceEnvelope`
- No credentials are sent to SigComply servers

#### Policy Evaluation
- OPA/Rego policies define compliance rules
- Policies are open-source and inspectable
- Policies evaluate fetched data locally
- Results indicate pass/fail for each control

#### Evidence Storage (Sovereign Vault)
- Evidence stored in a policy-first folder structure: `{framework}/{policy_id}/{timestamp}_{run_id}/`
- Each evidence file is a self-contained signed envelope with its own ephemeral keypair
- Each policy run produces a `result.json` with full violation details (resource IDs stay in S3)
- Customer chooses: S3 bucket, GCS, local
- SigComply never has access to raw evidence or violation details
- Customer maintains complete data sovereignty

#### Evidence Signing (per file)
- A fresh ephemeral Ed25519 keypair is generated per evidence file — never reused across files
- The signed payload is `{ timestamp, evidence }` serialized as canonical JSON
- Private key is discarded immediately after signing — never stored anywhere
- Public key + signature are embedded inside the evidence file itself (`EvidenceEnvelope`)
- Purpose: auditor spot-checks — pick any evidence file, verify it independently without contacting SigComply
- This is out-of-band verification, not part of the core compliance workflow

#### Cloud Reporting (Paid Tier)
- CLI sends **aggregated policy results** to SigComply Cloud API — no raw evidence, no resource identifiers, no PII:
  1. **Per-policy results**: policy_id + pass/fail + severity + counts (resources_evaluated, resources_failed)
  2. **Compliance scores**: overall framework score + per-control scores
  3. No violations with resource IDs, no user names, no ARNs, no account IDs
- This enables:
  - **Compliance dashboards**: overall score and per-control status over time
  - **Drift detection**: "CC6.1 failed last week, passing now"
  - **Trend analysis**: compliance score improving or degrading
  - **Auditor reports**: framework readiness at a glance
- Cloud API is a separate private Rails application
- Raw evidence, full violation details, and all identifiers stay in customer S3
- The aggregation happens client-side in the CLI before any data leaves the customer's environment

### 4. External Systems

**SigComply Cloud API** (Separate Rails Application - Private Repository):
- Receives aggregated policy results from CLI (paid tier):
  - Per-policy: policy_id, pass/fail status, severity, resource counts
  - Overall: compliance scores, framework summary
- Stores results to power compliance dashboards and auditor reports
- Enables:
  - Drift detection (per-policy pass/fail changing over time)
  - Compliance trend analysis and score history
  - Cross-environment comparison (staging vs production)
  - Auditor-ready reports and framework readiness views
- Provides web portal for compliance dashboards and auditor reports
- Auditor evidence verification is handled out-of-band: auditor requests raw evidence directly from customer, verifies signature using public key from customer's S3
- **Does NOT receive**: Raw evidence, resource identifiers (ARNs, usernames, emails, account IDs), full violation details, or any PII

---

## The "Seamless Integration" Blueprint

To ensure developers can integrate SigComply into their CI/CD pipelines in under 60 seconds, the CLI follows these design rules:

### 1. The `init-ci` Command

Instead of requiring developers to copy/paste YAML configuration files manually, they simply run:

```bash
sigcomply init-ci
```

The CLI will:
- Auto-detect if it's running in a GitHub Actions or GitLab CI environment
- Scaffold the minimal "caller" YAML file automatically in the correct location
- Validate that required environment variables (API keys, OIDC tokens) are present
- Provide clear next steps for configuration

### 2. "Thin" CI/CD Configuration

The developer's repository contains only a few lines of YAML that reference SigComply's reusable workflows:

**GitHub Actions Example:**
```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    permissions:
      id-token: write  # Required for OIDC authentication
      contents: read
    uses: sigcomply/sigcomply-cli/.github/workflows/compliance.yml@v1
    with:
      framework: soc2
```

**GitLab CI Example:**
```yaml
# .gitlab-ci.yml
include:
  - component: sigcomply/sigcomply-cli/compliance@v1
    inputs:
      framework: soc2
```

**Benefits:**
- Customer's configuration file is tiny (3-10 lines)
- SigComply can update the underlying logic by updating the reusable workflow
- Customers never need to change their code when SigComply improves features
- Standardized across all customer implementations

### 3. OIDC Authentication

SigComply uses ephemeral OIDC tokens for dual-purpose authentication:
1. **CLI → SigComply Cloud API**: Eliminates long-lived API keys
2. **CLI → Third-party services** (AWS, GCP, Azure): Preferred over static credentials

**Key principle**: OIDC first, fall back to environment variables/secrets when unavailable.

> **Full details**: See [docs/claude/auth.md](./docs/claude/auth.md) when implementing auth flows.

---

## Design Principles

### Security-First
- Zero-trust architecture
- No long-lived credentials stored
- Ephemeral OIDC authentication for both SigComply API and third-party services
- Prefer OIDC over long-lived API keys whenever possible (AWS, GCP, Azure, etc.)
- Cryptographic proof over data transfer
- Open-source transparency
- Principle of least privilege with scoped IAM roles

### Developer Ergonomics
- Terminal-first design
- CI/CD native (GitHub Actions, GitLab CI)
- "Compliance as Code" - fails builds when controls violated
- Single binary - no dependencies
- Clear, actionable error messages

### Data Sovereignty
- Customer owns all raw evidence
- Customer controls storage location
- SigComply never sees production data, raw evidence, or resource-level details
- Attestation signing artifacts (public key + signature) stay in customer's S3 alongside the evidence they protect
- Only aggregated compliance data leaves customer environment:
  - Per-policy pass/fail results with resource counts (not identities)
  - Compliance scores (aggregated percentages)
- Aggregation is the CLI's responsibility — it happens before any data leaves the customer environment

### Open Compliance
- All policies written in open Rego language
- No "black box" compliance checks
- Community can audit, improve, and customize policies
- Transparency builds trust

---

## Key Workflows

### 1. Initial Setup (Local Development)
```bash
sigcomply init
# Creates .sigcomply.yaml config file
# Prompts for storage backend (S3, GCS, etc.)
# Prompts for SigComply Cloud API credentials
```

### 2. CI/CD Integration Setup
```bash
sigcomply init-ci
# Auto-detects GitHub Actions or GitLab CI
# Scaffolds minimal caller YAML file
# Validates environment variables
# Provides next steps for configuration
```

This generates (for GitHub):
```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    permissions:
      id-token: write  # Required for OIDC authentication
      contents: read
    uses: sigcomply/sigcomply-cli/.github/workflows/compliance.yml@v1
    with:
      framework: soc2
```

Or (for GitLab):
```yaml
# .gitlab-ci.yml
include:
  - component: sigcomply/sigcomply-cli/compliance@v1
    inputs:
      framework: soc2
```

### 3. Running Compliance Checks (Local)
```bash
sigcomply check --framework soc2
# Fetches current infrastructure state
# Evaluates OPA policies locally
# Wraps each evidence file in a signed envelope (ephemeral Ed25519 keypair per file, private key discarded immediately)
# Stores signed evidence envelopes + policy result files in customer's vault (S3/local)
# Authenticates via OIDC token in CI
# Sends aggregated policy results to Cloud API (counts only, no resource IDs)
# Outputs pass/fail results
```

### 4. CI/CD Execution (Automatic)
When the workflow runs:
1. CI/CD platform generates ephemeral OIDC token
2. SigComply CLI is installed via reusable workflow
3. CLI fetches infrastructure data using repository secrets
4. Policies are evaluated locally — full violations (with resource IDs) computed in memory
5. Each collected evidence file is wrapped in a signed EvidenceEnvelope (fresh ephemeral Ed25519 keypair per file, private key discarded immediately)
6. Signed evidence envelopes + PolicyRunResult files stored in customer's S3 vault under policy-first folder structure
7. CLI aggregates results (resource counts, policy-level pass/fail) — resource identifiers discarded
8. Aggregated compliance data sent to Rails API with OIDC token (no resource IDs, no PII)
9. Build passes/fails based on compliance status

### 5. Audit Preparation
```bash
sigcomply report --framework soc2 --format pdf
# Generates audit-ready report from policy results stored in Cloud API
# Auditor reviews compliance dashboard and framework readiness summary
```

**Evidence spot-check (out-of-band):**
```
Auditor selects a handful of evidence files to verify
  → Requests the raw evidence files directly from the customer
  → Customer provides the files and the corresponding attestation.json from their S3 bucket
  → Auditor hashes the evidence files and verifies the signature using the public key in attestation.json
  → Match confirms the evidence is intact and unmodified since collection
```

---

## File Structure Conventions

The codebase follows a domain-driven organization with three main areas:

```
sigcomply-cli/
├── main.go                              # CLI entry point
├── cmd/sigcomply/                       # CLI commands
│
├── internal/
│   ├── compliance_frameworks/           # Everything about compliance
│   │   ├── engine/                      # Core OPA evaluation logic
│   │   │   ├── engine.go
│   │   │   └── registry.go              # Framework registration
│   │   │
│   │   ├── shared/                      # Shared Rego helpers
│   │   │   └── lib.rego
│   │   │
│   │   ├── soc2/                        # SOC 2 framework
│   │   │   ├── framework.go             # Framework metadata & config
│   │   │   ├── controls.go              # Control hierarchy/mappings
│   │   │   └── policies/                # Rego policy files
│   │   │       ├── cc6_1_mfa.rego
│   │   │       └── cc6_2_encryption.rego
│   │   │
│   │   ├── hipaa/                       # HIPAA framework
│   │   │   ├── framework.go
│   │   │   ├── controls.go
│   │   │   └── policies/
│   │   │
│   │   └── iso27001/                    # ISO 27001 framework
│   │       ├── framework.go
│   │       ├── controls.go
│   │       └── policies/
│   │
│   ├── data_sources/                    # Evidence collection
│   │   └── apis/                        # API-based collectors
│   │       ├── aws/
│   │       │   ├── collector.go         # Auth, config, orchestration
│   │       │   ├── iam.go, s3.go, cloudtrail.go
│   │       │   ├── ec2.go, ecr.go, rds.go, kms.go
│   │       │   └── guardduty.go, configservice.go, cloudwatch.go
│   │       │
│   │       ├── github/
│   │       │   ├── collector.go, repos.go, members.go
│   │       │
│   │       └── gcp/
│   │           ├── collector.go, iam.go, storage.go
│   │           └── compute.go, sql.go
│   │
│   ├── core/                            # Shared types & utilities
│   │   ├── evidence/                    # Evidence, Result, Violation types
│   │   ├── config/                      # Configuration loading
│   │   ├── output/                      # Output formatting
│   │   ├── storage/                     # Evidence storage (S3, local)
│   │   ├── attestation/                 # Attestation signing & hashing
│   │   └── cloud/                       # SigComply Cloud client
│   │
│   └── testutil/                        # Test helpers
│
├── contracts/                           # Contract tests
├── examples/                            # CI/CD workflow examples
├── .github/workflows/                   # GitHub Actions workflows (CI, release automation)
├── scripts/                             # Build and development scripts
└── CLAUDE.md                            # This file - AI assistant context
```

### Key Organizational Principles

1. **compliance_frameworks/**: Each compliance framework (SOC2, HIPAA, ISO27001) has its own package with framework-specific logic, control mappings, and policies.

2. **data_sources/**: Separates "where we get data" from "what we check". The `apis/` subfolder contains service collectors (AWS, GitHub), each split by service (iam.go, s3.go).

3. **core/**: Shared types and utilities used across the codebase.

---

## CLI Interface

**Reference**: See [CLI Interface Design](./ARCHITECTURE.md#cli-interface-design) for complete specification.

### Commands

| Command | Description |
|---------|-------------|
| `sigcomply check` | Main command: collect + evaluate + store + (optionally) cloud submit |
| `sigcomply init` | Initialize configuration file |
| `sigcomply init-ci` | Generate CI/CD workflow files |
| `sigcomply collect` | Collect evidence only (no evaluation) |
| `sigcomply evaluate` | Evaluate policies against stored evidence |
| `sigcomply report` | Generate compliance reports |
| `sigcomply config` | View/validate/set configuration |
| `sigcomply version` | Show version information |

### Key Flags for `sigcomply check`

```bash
--framework string    # Compliance framework (default: "soc2")
--collector strings   # Collectors to use (default: auto-detect)
--service strings     # Limit to specific services
--policies string     # Comma-separated policy names to run (e.g., cc6_1_mfa,cc6_1_github_mfa)
--controls string     # Comma-separated control IDs to run (e.g., CC6.1,CC7.1)
-o, --output string   # Output format: text, json, sarif
-v, --verbose         # Verbose output
-q, --quiet           # Minimal output
--cloud               # Force cloud submission
--no-cloud            # Disable cloud submission
--fail-on-violation   # Exit code 1 on violations (default in CI)
--fail-severity       # Minimum severity to fail: low, medium, high, critical
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - all checks passed |
| 1 | Violations found |
| 2 | Execution error |
| 3 | Configuration error |

### Auto-Detection

The CLI automatically detects:
- **Collectors**: Based on available credentials (AWS_*, GITHUB_TOKEN, etc.)
- **CI Environment**: GITHUB_ACTIONS, GITLAB_CI, CI environment variables
- **Cloud Mode**: Auto-enabled when OIDC is available in CI (GitHub Actions, GitLab CI)

---

## Configuration

**Reference**: See [Configuration Design](./ARCHITECTURE.md#configuration-design) for complete specification.

### Configuration File

Default file: `.sigcomply.yaml`

```yaml
# Minimal example
frameworks:
  - soc2

collectors:
  aws:
    regions:
      - us-east-1

# Policy filtering (optional — run all policies by default)
policies:                        # Specific policy names to run
  - cc6_1_mfa
  - cc6_1_github_mfa
controls:                        # Or filter by control IDs
  - CC6.1

storage:
  backend: local
  local:
    path: ./.sigcomply/evidence

# Cloud settings (auto-enabled when OIDC is available in CI)
cloud:
  enabled: false  # Auto-enabled when OIDC is available in CI
```

### Configuration Sources (Precedence)

1. **CLI flags** (highest priority)
2. **Environment variables** (SIGCOMPLY_*)
3. **Config file** (.sigcomply.yaml)
4. **Built-in defaults** (lowest priority)

### Key Environment Variables

```bash
SIGCOMPLY_FRAMEWORK        # Default framework
SIGCOMPLY_POLICIES         # Comma-separated policy names to run
SIGCOMPLY_CONTROLS         # Comma-separated control IDs to run
SIGCOMPLY_STORAGE_BACKEND  # Storage backend: local, s3, gcs
SIGCOMPLY_STORAGE_BUCKET   # S3/GCS bucket name
SIGCOMPLY_OUTPUT_FORMAT    # Output format: text, json, sarif
```

### Configuration Sections

| Section | Purpose |
|---------|---------|
| `collectors` | AWS, GitHub, GCP collector settings |
| `frameworks` | Which compliance frameworks to evaluate |
| `policies` | Filter to specific policy names (e.g., `cc6_1_mfa`) |
| `controls` | Filter to specific control IDs (e.g., `CC6.1`) |
| `storage` | Storage backend and artifact settings |
| `cloud` | SigComply Cloud API settings |
| `output` | Format, verbosity, color settings |
| `ci` | CI/CD behavior (fail_on_violation, fail_severity) |

---

## Integration Points

### Service Integrations (Collectors)
- Each integration fetches data from a specific service
- **Authentication Priority**:
  1. OIDC tokens (preferred in CI/CD environments)
  2. IAM roles / Workload Identity (for cloud environments)
  3. Environment variables (fallback for local development)
  4. Config files (last resort)
- Returns structured data for policy evaluation
- Examples: AWS (IAM, S3, CloudTrail), GitHub (repos, users, branch protection)
- **Important**: Each collector must implement multi-method authentication with OIDC as preferred method

### Storage Backends
- Pluggable storage system
- Interface allows adding new backends easily
- Current priority: S3, Google Drive
- Stores raw evidence JSON/logs/screenshots

### Policy Engine
- OPA integration for policy evaluation
- Rego policies organized by framework (SOC 2, ISO 27001)
- Policies take fetched data as input
- Return violations/passes with detailed messages

### Cloud API Client
- HTTP client for SigComply Cloud API (paid tier)
- Authenticates with OIDC tokens
- Sends **aggregated policy results only** via `POST /api/v1/cli/runs` — no raw evidence, no violations, no attestation, no resource identifiers:
  - Per-policy: `policy_id`, `control_id`, pass/fail status, severity, `resources_evaluated`, `resources_failed` counts
  - Overall: aggregated compliance scores and policy counts
  - Run metadata: CI provider, repository, branch, CLI version (no resource IDs)
- Raw evidence, full `CheckResult` with violation details, and attestation all stay in customer S3 — never sent to SigComply
- The aggregation happens in the CLI before the API call: violations are reduced to counts, resource identifiers are discarded
- Enables drift detection, compliance score trends, and auditor reports

---

## Development Guidelines

### Code Style
- Follow standard Go conventions
- Use `gofmt` for formatting
- Clear variable names over brevity
- Comments for public APIs and complex logic

### Testing
- Unit tests for all core logic
- Integration tests for service collectors
- Mock external APIs in tests
- Policy tests using OPA's testing framework

### Error Handling
- Descriptive error messages
- Wrap errors with context
- Fail fast on critical errors
- Graceful degradation where appropriate

### Logging
- Structured logging (JSON format)
- Clear log levels (debug, info, warn, error)
- Sensitive data never logged (credentials, PII)
- Verbose mode for debugging

---

## Compliance Frameworks

Each framework is a self-contained package in `internal/compliance_frameworks/`:

### SOC 2 Type II
- Focus on Trust Service Criteria (Security, Availability, Confidentiality)
- Key controls: Access control, encryption, monitoring, incident response
- Location: `internal/compliance_frameworks/soc2/`
  - `framework.go` - Framework metadata and interface implementation
  - `controls.go` - Trust Service Criteria mappings
  - `policies/` - Rego policy files (cc6_1_mfa.rego, etc.)

### ISO 27001
- Information security management system (ISMS)
- 114 controls across 14 domains
- Location: `internal/compliance_frameworks/iso27001/`
  - `framework.go` - Framework metadata
  - `controls.go` - Annex A control mappings
  - `policies/` - Rego policy files

### HIPAA
- Healthcare data protection
- Focus on PHI (Protected Health Information)
- Location: `internal/compliance_frameworks/hipaa/`
  - `framework.go` - Framework metadata
  - `controls.go` - Security Rule section mappings (164.308, 164.310, 164.312)
  - `policies/` - Rego policy files

---

## Security Considerations

### Credentials Management
- Never store long-lived credentials
- Use environment variables or IAM roles
- Support ephemeral OIDC tokens for cloud auth
- Warn users about credential exposure

### Data Handling
- Encrypt evidence at rest in customer's vault
- TLS for all API communications
- Hash evidence before transmission
- Clear sensitive data from memory after use

### Auditor Access
- Auditors never receive credentials from CLI
- Auditors use SigComply portal to verify evidence
- Portal allows drag-and-drop verification (upload evidence, check hash)
- Immutable audit trail in Cloud API

---

## Common Tasks

> See [docs/claude/recipes.md](./docs/claude/recipes.md) for step-by-step guides on:
> - Adding a new service integration (data source)
> - Adding a new compliance policy
> - Adding a new compliance framework
> - Adding a new storage backend
> - Creating CI/CD reusable workflows

---

## Current Status

**Project Stage**: Active development (Phase 1 mostly complete)

**Architecture**: See [ARCHITECTURE.md](./ARCHITECTURE.md)

**Completed**:
- Zero-config `sigcomply check` with AWS + SOC 2
- AWS collector (IAM, S3, CloudTrail, EC2, ECR, RDS, KMS, GuardDuty, Config, CloudWatch)
- GCP collector (IAM, Storage, Compute, SQL)
- GitHub collector (repos, members)
- OPA engine with 30+ embedded SOC 2 policies + ISO 27001 policies
- Text, JSON, JUnit output formatters
- Evidence storage (S3, local)
- Attestation signing (ephemeral Ed25519 keypair, public key + signature stored in customer S3)
- SigComply Cloud API client (unified `POST /api/v1/cli/runs`)
- OIDC authentication (GitHub Actions, GitLab CI)
- Canonical JSON for deterministic hashing
- Policy filtering (`--policies`, `--controls` flags, env vars, config file)
- Release automation (auto-release via conventional commits, manual release, GoReleaser)
- GitHub Actions reusable workflow, GitLab CI component
- E2E test framework (config-driven scenarios)

**Remaining**:
- Secret scanner
- init and init-ci commands
- SARIF output formatter
- Public README

**Key Design Decisions**:
- Zero-config by default (auto-detect AWS)
- Embedded policies (no filesystem dependency)
- Domain-driven structure (compliance_frameworks/, data_sources/, core/)
- Each compliance framework is self-contained with its own policies
- Data sources split by service (aws/iam.go, aws/s3.go)
- Table-driven tests with mocked AWS SDK
- Fail-safe collection (partial success OK)

---

## Notes for AI Assistants

- This is an early-stage project - be prepared to make architectural decisions
- Prioritize security and data privacy in all implementations
- Follow Go best practices and idiomatic patterns
- Keep the CLI simple and developer-friendly
- Think "compliance as code" - make it feel like testing
- When in doubt about design decisions, favor security over convenience
- **Key architectural decision - What stays with customer vs goes to cloud**:

  **Stays with Customer (in their S3 vault)**:
  - Raw evidence (actual API responses) — wrapped in signed `EvidenceEnvelope` files
  - Full `PolicyRunResult` per policy per run — includes all `Violation` details with resource IDs, ARNs, etc.
  - Ephemeral Ed25519 public key — embedded inside each `EvidenceEnvelope` file
  - Cryptographic signature — embedded inside each `EvidenceEnvelope` file

  **Goes to SigComply Cloud (paid tier) — aggregated only, no PII**:
  - Per-policy results: policy_id + pass/fail + severity + resource counts
  - Compliance scores (aggregated percentages)
  - No resource identifiers, no usernames, no ARNs, no email addresses

  This enables compliance dashboards and trend analysis while maintaining strict data privacy.

- **Why this is "Evidence without Access"**: SigComply never receives credentials, raw API responses, or any data that would identify specific resources or people. We only receive aggregate counts ("3 resources failed this policy") not identities.

- **The aggregation boundary is sacred**: The CLI is responsible for reducing violations to counts before sending anything to the Cloud API. This is a hard architectural boundary — never add code that would send resource identifiers to the cloud client.

- **Evidence signing design (EvidenceEnvelope)**:
  - Each evidence file is independently wrapped in a signed envelope: `{signed: {timestamp, evidence}, public_key, signature}`
  - A fresh ephemeral Ed25519 keypair is generated per evidence file — private key discarded immediately after signing
  - The same raw evidence data (e.g., IAM users) may appear in multiple policy folders — each copy has its own independent keypair and signature
  - Signing uses canonical JSON (sorted map keys) so the same data always produces the same bytes for signing/verification
  - Purpose: auditor spot-checks — pick any evidence file, verify its signature independently without contacting SigComply
  - No separate `attestation.json` manifest — proof travels with each individual file
  - No Rails involvement in verification — entirely customer-side

- **Threat model for evidence signing**: We protect against accidental corruption and unintentional evidence drift. The `timestamp` inside the signed payload proves when evidence was collected (S3 mtimes can be modified; the signed timestamp cannot). We do not attempt to prevent a determined customer from fabricating evidence — that would be fraud, a legal matter, and is out of scope for all compliance tools.

---

## Resources

- Open Policy Agent: https://www.openpolicyagent.org/
- Rego Language: https://www.openpolicyagent.org/docs/latest/policy-language/
- SOC 2 Framework: https://www.aicpa.org/soc
- ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
- HIPAA: https://www.hhs.gov/hipaa/

---

Last Updated: 2026-03-24
