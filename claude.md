# TraceVault CLI - Claude Context

This document provides context for AI assistants (like Claude) working on the TraceVault CLI project.

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

1. **[ARCHITECTURE.md](./ARCHITECTURE.md)** - System architecture and design
2. **[IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)** - MVP implementation roadmap
3. **[TESTING_STRATEGY.md](./TESTING_STRATEGY.md)** - Testing requirements
4. **[QUICKSTART.md](./QUICKSTART.md)** - Developer onboarding
5. **[GLOSSARY.md](./GLOSSARY.md)** - Key terms and concepts

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
5. **Update documentation** - After the feature is complete, revise and update relevant documentation files (ARCHITECTURE.md, IMPLEMENTATION_PLAN.md, CLAUDE.md as needed)

```bash
# TDD workflow
make test          # Run unit tests
make test-integration  # Run integration tests (if applicable)
make lint          # Ensure code quality
```

### Rule 2: Architecture-First Implementation

Before starting any implementation:

1. **Read existing documentation** - Review ARCHITECTURE.md, IMPLEMENTATION_PLAN.md, and relevant sections of CLAUDE.md to understand the full context
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

### Summary Checklist

Before implementing any feature, verify:

- [ ] I have read the relevant architecture documentation
- [ ] I have a clear implementation plan
- [ ] The design doesn't feel overly complicated (if it does, STOP and ask)
- [ ] I will write tests before implementation
- [ ] I will make small, atomic commits
- [ ] I will update documentation after completion

---

## Project Purpose

TraceVault CLI is an open-source compliance automation engine that enables organizations to achieve SOC 2, ISO 27001, and HIPAA readiness without granting third-party vendors access to their production infrastructure.

**Core Philosophy**: "Evidence without Access" - a non-custodial approach to compliance automation.

---

## Technical Stack

- **Language**: Go (Golang)
- **Policy Engine**: Open Policy Agent (OPA) with Rego policies
- **Authentication**: Dual OIDC approach
  - OIDC tokens for TraceVault Cloud API authentication
  - OIDC tokens for third-party service authentication (AWS, GCP, Azure, etc.)
  - Fallback to traditional credentials when OIDC unavailable
- **Cryptography**: SHA-256 hashing for evidence attestation
- **Configuration**: YAML-based configuration files
- **Distribution**: Single binary executable
- **CI/CD**: GitHub Actions reusable workflows, GitLab CI components

---

## Architecture Overview

### 1. The 2-Repo Architecture

TraceVault uses a two-repository architecture that balances transparency with business security:

**Repo 1: tracevault-cli (This Repository - PUBLIC)**
- The "Front-of-House" / Distribution Layer
- Contains the Go CLI source code
- Open-source compliance policies (YAML/Rego)
- GitHub Reusable Workflows (`.github/workflows/`)
- GitLab CI/CD Components (using `spec:inputs`)
- Installation scripts (`curl | sh` setup)
- Complete transparency for security-conscious teams

**Repo 2: tracevault-cloud (PRIVATE)**
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
- TraceVault can iterate on backend features independently

### 2. CLI Execution Flow

```
User Environment
    ↓
[TraceVault CLI]
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
    └─> Send to TraceVault Cloud API (paid tier):
        ├─> Full CheckResult (all policy results with violations)
        ├─> Signed attestation (hashes + signature)
        └─> Evidence location reference (where raw evidence is stored)
```

**Important**: Raw evidence (API responses) and policy inputs stay in customer's storage. The Cloud API receives full compliance check results (including violation details) but never the underlying raw data.

### 3. Key Components

#### Evidence Collection
- CLI connects to various service APIs using customer's local credentials
- Fetches infrastructure state, configuration, logs, user data, etc.
- No credentials are sent to TraceVault servers

#### Policy Evaluation
- OPA/Rego policies define compliance rules
- Policies are open-source and inspectable
- Policies evaluate fetched data locally
- Results indicate pass/fail for each control

#### Evidence Storage (Sovereign Vault)
- Raw evidence sent to customer-controlled storage
- Customer chooses: S3 bucket, Google Drive, Azure Blob, etc.
- TraceVault never has access to raw evidence
- Customer maintains complete data sovereignty

#### Attestation Generation
- CLI generates SHA-256 hash of every piece of evidence
- Hash acts as cryptographic proof of evidence
- Hash + metadata (timestamp, status, control ID) form attestation

#### Cloud Reporting (Paid Tier)
- CLI sends **full compliance check results** to TraceVault Cloud API:
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

**TraceVault Cloud API** (Separate Rails Application - Private Repository):
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

To ensure developers can integrate TraceVault into their CI/CD pipelines in under 60 seconds, the CLI follows these design rules:

### 1. The `init-ci` Command

Instead of requiring developers to copy/paste YAML configuration files manually, they simply run:

```bash
tracevault init-ci
```

The CLI will:
- Auto-detect if it's running in a GitHub Actions or GitLab CI environment
- Scaffold the minimal "caller" YAML file automatically in the correct location
- Validate that required environment variables (API keys, OIDC tokens) are present
- Provide clear next steps for configuration

### 2. "Thin" CI/CD Configuration

The developer's repository contains only a few lines of YAML that reference TraceVault's reusable workflows:

**GitHub Actions Example:**
```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    uses: tracevault/tracevault-cli/.github/workflows/compliance.yml@v1
    with:
      framework: soc2
    secrets:
      TRACEVAULT_API_TOKEN: ${{ secrets.TRACEVAULT_API_TOKEN }}
```

**GitLab CI Example:**
```yaml
# .gitlab-ci.yml
include:
  - component: tracevault/tracevault-cli/compliance@v1
    inputs:
      framework: soc2
```

**Benefits:**
- Customer's configuration file is tiny (3-10 lines)
- TraceVault can update the underlying logic by updating the reusable workflow
- Customers never need to change their code when TraceVault improves features
- Standardized across all customer implementations

### 3. OIDC Authentication

TraceVault uses ephemeral OIDC tokens for dual-purpose authentication:
1. **CLI → TraceVault Cloud API**: Eliminates long-lived API keys
2. **CLI → Third-party services** (AWS, GCP, Azure): Preferred over static credentials

**Key principle**: OIDC first, fall back to environment variables/secrets when unavailable.

> **Full details**: See [docs/claude/auth.md](./docs/claude/auth.md) when implementing auth flows.

---

## Design Principles

### Security-First
- Zero-trust architecture
- No long-lived credentials stored
- Ephemeral OIDC authentication for both TraceVault API and third-party services
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
- TraceVault never sees production data or raw evidence
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
tracevault init
# Creates .tracevault.yaml config file
# Prompts for storage backend (S3, GCS, etc.)
# Prompts for TraceVault Cloud API credentials
```

### 2. CI/CD Integration Setup
```bash
tracevault init-ci
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
    uses: tracevault/tracevault-cli/.github/workflows/compliance.yml@v1
    with:
      framework: soc2
```

Or (for GitLab):
```yaml
# .gitlab-ci.yml
include:
  - component: tracevault/tracevault-cli/compliance@v1
    inputs:
      framework: soc2
```

### 3. Running Compliance Checks (Local)
```bash
tracevault check --framework soc2
# Fetches current infrastructure state
# Evaluates OPA policies
# Stores evidence in customer's vault
# Generates OIDC token (or uses API token locally)
# Sends signed attestations to Cloud API
# Outputs pass/fail results
```

### 4. CI/CD Execution (Automatic)
When the workflow runs:
1. CI/CD platform generates ephemeral OIDC token
2. TraceVault CLI is installed via reusable workflow
3. CLI fetches infrastructure data using repository secrets
4. Policies are evaluated locally
5. Evidence stored in customer's sovereign vault
6. Derived compliance data sent to Rails API with OIDC token:
   - Attestations (hashes + metadata)
   - Evaluation summaries (pass/fail counts, compliance scores)
7. Build passes/fails based on compliance status

### 5. Audit Preparation
```bash
tracevault report --framework soc2 --format pdf
# Generates audit-ready report
# Auditor can verify evidence via TraceVault portal
# Portal compares raw evidence against stored hashes
```

---

## File Structure Conventions

The codebase follows a domain-driven organization with three main areas:

```
tracevault-cli/
├── cmd/tracevault/                      # CLI entry point
│   └── main.go
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
│   │   ├── apis/                        # API-based collectors
│   │   │   ├── aws/
│   │   │   │   ├── collector.go         # Auth, config, orchestration
│   │   │   │   ├── iam.go               # IAM collection
│   │   │   │   ├── s3.go                # S3 collection
│   │   │   │   └── cloudtrail.go        # CloudTrail collection
│   │   │   │
│   │   │   ├── github/                  # GitHub collector (future)
│   │   │   └── gcp/                     # GCP collector (future)
│   │   │
│   │   └── others/                      # Non-API data sources (future)
│   │
│   ├── core/                            # Shared types & utilities
│   │   ├── evidence/                    # Evidence, Result, Violation types
│   │   ├── config/                      # Configuration loading
│   │   ├── output/                      # Output formatting
│   │   ├── scanner/                     # Secret scanner
│   │   ├── storage/                     # Evidence storage (future)
│   │   ├── attestation/                 # Attestation signing & hashing
│   │   └── cloud/                       # TraceVault Cloud client (future)
│   │
│   └── testutil/                        # Test helpers
│
├── contracts/                           # Contract tests
├── examples/                            # CI/CD workflow examples
├── .github/workflows/                   # GitHub Actions workflows
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
| `tracevault check` | Main command: collect + evaluate + store + (optionally) cloud submit |
| `tracevault init` | Initialize configuration file |
| `tracevault init-ci` | Generate CI/CD workflow files |
| `tracevault collect` | Collect evidence only (no evaluation) |
| `tracevault evaluate` | Evaluate policies against stored evidence |
| `tracevault report` | Generate compliance reports |
| `tracevault config` | View/validate/set configuration |
| `tracevault version` | Show version information |

### Key Flags for `tracevault check`

```bash
--framework string    # Compliance framework (default: "soc2")
--collector strings   # Collectors to use (default: auto-detect)
--service strings     # Limit to specific services
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
- **Cloud Mode**: Enabled if TRACEVAULT_API_TOKEN is set

---

## Configuration

**Reference**: See [Configuration Design](./ARCHITECTURE.md#configuration-design) for complete specification.

### Configuration File

Default file: `.tracevault.yaml`

```yaml
# Minimal example
frameworks:
  - soc2

collectors:
  aws:
    regions:
      - us-east-1

storage:
  backend: local
  local:
    path: ./.tracevault/evidence

# Cloud settings (optional - for paid features)
cloud:
  enabled: false  # Auto-enabled if TRACEVAULT_API_TOKEN is set
```

### Configuration Sources (Precedence)

1. **CLI flags** (highest priority)
2. **Environment variables** (TRACEVAULT_*)
3. **Config file** (.tracevault.yaml)
4. **Built-in defaults** (lowest priority)

### Key Environment Variables

```bash
TRACEVAULT_API_TOKEN        # Cloud API token (enables cloud mode)
TRACEVAULT_FRAMEWORK        # Default framework
TRACEVAULT_STORAGE_BACKEND  # Storage backend: local, s3, gcs
TRACEVAULT_STORAGE_BUCKET   # S3/GCS bucket name
TRACEVAULT_OUTPUT_FORMAT    # Output format: text, json, sarif
```

### Configuration Sections

| Section | Purpose |
|---------|---------|
| `collectors` | AWS, GitHub, GCP collector settings |
| `frameworks` | Which compliance frameworks to evaluate |
| `policies` | Policy exclusions, inclusions, custom paths |
| `storage` | Storage backend and artifact settings |
| `cloud` | TraceVault Cloud API settings |
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
- HTTP client for TraceVault Cloud API (paid tier)
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
- **E2E Testing Repositories** (external, real CI/CD environments):
  - GitHub Actions: https://github.com/Trace-Vault/tracevault-cli-testing-github
  - GitLab CI: https://gitlab.com/tracevault/tracevault-cli-testing-gitlab

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
- Auditors use TraceVault portal to verify evidence
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

**Project Stage**: Pre-implementation (Architecture finalized)

**Architecture**: See [ARCHITECTURE.md](./ARCHITECTURE.md)

**P0 MVP Priorities** (3-4 weeks):
1. Zero-config `tracevault check` command that works with AWS defaults
2. AWS collector (IAM, S3, CloudTrail)
3. OPA engine with embedded policies (go:embed)
4. 3 SOC 2 policies (MFA, encryption, logging)
5. Text and JSON output formatters
6. GitHub Actions reusable workflow
7. Unit tests (>80% coverage) and policy tests

**Completed (post-P0)**:
- Evidence storage (S3, local)
- Attestation signing (HMAC, OIDC)
- TraceVault Cloud API client
- OIDC authentication (GitHub Actions, GitLab CI)
- GitHub collector
- Canonical JSON for deterministic hashing

**Remaining**:
- Secret scanner
- init and init-ci commands

**Key Design Decisions** (V3):
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

  **Goes to TraceVault Cloud (paid tier)**:
  - Full `CheckResult` with all `PolicyResult` entries
  - All `Violation` details (resource IDs, types, reasons)
  - Signed `Attestation` with evidence hashes
  - `EvidenceLocation` reference

  This enables drift detection, resource tracking, and compliance trends while maintaining non-custodial architecture (no API credentials, no raw infrastructure data).

- **Why this is still "Evidence without Access"**: TraceVault never gets credentials to customer infrastructure and never receives raw API responses. We only see compliance evaluation results (which controls passed/failed and why).
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

### E2E Testing Repositories

- GitHub Actions Testing: https://github.com/Trace-Vault/tracevault-cli-testing-github
- GitLab CI Testing: https://gitlab.com/tracevault/tracevault-cli-testing-gitlab

---

Last Updated: 2026-01-11
