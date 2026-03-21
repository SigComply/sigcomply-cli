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
- **Authentication**: Dual OIDC approach
  - OIDC tokens for SigComply Cloud API authentication
  - OIDC tokens for third-party service authentication (AWS, GCP, Azure, etc.)
  - Fallback to traditional credentials when OIDC unavailable
- **Cryptography**: SHA-256 hashing for evidence attestation
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
- The "Intelligence/Storage Layer" / Attestation Ledger
- Rails-based backend application
- Stores attestation history and metadata
- Handles billing and subscription management
- Manages proprietary verification workflows
- Provides auditor portal and reporting

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
    ├─> Execute OPA/Rego policies against fetched data
    ├─> Generate CheckResult with PolicyResults and Violations
    ├─> Store to customer's storage (S3, GCS, local):
    │   ├─> Raw evidence (API responses)
    │   ├─> Policy inputs (what OPA evaluated)
    │   ├─> Check results (evaluation outcomes)
    │   └─> Signed attestation
    │
    └─> Send to SigComply Cloud API (paid tier):
        ├─> Full CheckResult (all policy results with violations)
        ├─> Signed attestation (hashes + signature)
        └─> Evidence location reference (where raw evidence is stored)
```

**Important**: Raw evidence (API responses) and policy inputs stay in customer's storage. The Cloud API receives full compliance check results (including violation details) but never the underlying raw data.

### 3. Key Components

#### Evidence Collection
- CLI connects to various service APIs using customer's local credentials
- Fetches infrastructure state, configuration, logs, user data, etc.
- No credentials are sent to SigComply servers

#### Policy Evaluation
- OPA/Rego policies define compliance rules
- Policies are open-source and inspectable
- Policies evaluate fetched data locally
- Results indicate pass/fail for each control

#### Evidence Storage (Sovereign Vault)
- Raw evidence sent to customer-controlled storage
- Customer chooses: S3 bucket, Google Drive, Azure Blob, etc.
- SigComply never has access to raw evidence
- Customer maintains complete data sovereignty

#### Attestation Generation
- CLI generates SHA-256 hash of every piece of evidence
- Hash acts as cryptographic proof of evidence
- Hash + metadata (timestamp, status, control ID) form attestation

#### Cloud Reporting (Paid Tier)
- CLI sends **full compliance check results** to SigComply Cloud API:
  1. **CheckResult**: Complete policy evaluation results including all violations with resource details
  2. **Attestation**: Cryptographic proof with evidence hashes and signature
  3. **Evidence Location**: Reference to where raw evidence is stored (not the evidence itself)
- This enables:
  - **Drift detection**: "CC6.1 failed last week, passing now"
  - **Resource tracking**: "User alice has had MFA violations 3 times"
  - **Intelligent alerting**: "3 new violations since last check"
  - **Historical compliance analysis** with full context
- Cloud API is a separate private Rails application
- Creates immutable audit trail for compliance history
- Enables auditor verification portal
- **Raw evidence (API responses) stays with customer** - maintains non-custodial architecture
- See [ARCHITECTURE.md - Free vs Paid Tier Data Flow](./ARCHITECTURE.md#free-vs-paid-tier-data-flow) for details

### 4. External Systems

**SigComply Cloud API** (Separate Rails Application - Private Repository):
- Receives compliance check results from CLI (paid tier):
  - Full CheckResult with all PolicyResults and Violations
  - Signed Attestation with evidence hashes
  - Evidence storage location reference
- Stores results in immutable ledger for audit trail
- Enables:
  - Drift detection (compare violations over time)
  - Resource-level compliance tracking
  - Compliance trend analysis and dashboards
  - Intelligent alerting on compliance changes
  - Cross-environment comparison (staging vs production)
- Provides web portal for audit reports
- Enables auditor verification workflow
- **Does NOT receive**: Raw evidence (API responses), policy inputs

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
- SigComply never sees production data or raw evidence
- Only derived compliance data leaves customer environment:
  - Cryptographic proofs (SHA-256 hashes)
  - Aggregated evaluation results (pass/fail counts, scores)

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
# Evaluates OPA policies
# Stores evidence in customer's vault
# Authenticates via OIDC token in CI
# Sends signed attestations to Cloud API
# Outputs pass/fail results
```

### 4. CI/CD Execution (Automatic)
When the workflow runs:
1. CI/CD platform generates ephemeral OIDC token
2. SigComply CLI is installed via reusable workflow
3. CLI fetches infrastructure data using repository secrets
4. Policies are evaluated locally
5. Evidence stored in customer's sovereign vault
6. Derived compliance data sent to Rails API with OIDC token:
   - Attestations (hashes + metadata)
   - Evaluation summaries (pass/fail counts, compliance scores)
7. Build passes/fails based on compliance status

### 5. Audit Preparation
```bash
sigcomply report --framework soc2 --format pdf
# Generates audit-ready report
# Auditor can verify evidence via SigComply portal
# Portal compares raw evidence against stored hashes
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
- Sends full compliance check results (no raw evidence):
  - Full `CheckResult` with all `PolicyResult` entries and `Violations`
  - Signed `Attestation` with evidence hashes
  - `EvidenceLocation` reference (where raw evidence is stored)
- Raw evidence (API responses) and policy inputs stay in customer storage
- Receives audit report metadata
- Enables drift detection, resource tracking, and compliance trends
- See [ARCHITECTURE.md - Cloud API Payload](./ARCHITECTURE.md#cloud-api-payload-paid-tier) for schema

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
- Attestation signing (HMAC, OIDC)
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

  **Stays with Customer (in their storage)**:
  - Raw evidence (actual API responses)
  - Policy inputs (data sent to OPA)

  **Goes to SigComply Cloud (paid tier)**:
  - Full `CheckResult` with all `PolicyResult` entries
  - All `Violation` details (resource IDs, types, reasons)
  - Signed `Attestation` with evidence hashes
  - `EvidenceLocation` reference

  This enables drift detection, resource tracking, and compliance trends while maintaining non-custodial architecture (no API credentials, no raw infrastructure data).

- **Why this is still "Evidence without Access"**: SigComply never gets credentials to customer infrastructure and never receives raw API responses. We only see compliance evaluation results (which controls passed/failed and why).
- **Attestation design decisions**:
  - `StorageLocation` is NOT signed (operational metadata that may change)
  - `CLIVersion` and `PolicyVersions` ARE signed (for reproducibility)
  - All hashing uses canonical JSON (sorted map keys) for deterministic output
  - This ensures customers can migrate evidence storage without invalidating attestations
- Reference the comprehensive type definitions in [ARCHITECTURE.md - Post-Execution Architecture](./ARCHITECTURE.md#post-execution-architecture)

---

## Resources

- Open Policy Agent: https://www.openpolicyagent.org/
- Rego Language: https://www.openpolicyagent.org/docs/latest/policy-language/
- SOC 2 Framework: https://www.aicpa.org/soc
- ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
- HIPAA: https://www.hhs.gov/hipaa/

---

Last Updated: 2026-03-15
