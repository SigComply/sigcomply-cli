# SigComply Glossary

Quick reference for key terms and concepts. For full context, see [CLAUDE.md](./CLAUDE.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Core Philosophy

| Term | Definition |
|------|------------|
| **Evidence without Access** | SigComply's core principle: prove compliance without giving vendors access to production infrastructure or raw data |
| **Non-custodial** | SigComply never holds customer credentials, raw evidence, or production data |
| **Compliance as Code** | Treating compliance checks like automated tests—they run in CI/CD and fail builds when controls are violated |

---

## Architecture

| Term | Definition |
|------|------------|
| **2-Repo Architecture** | Separation of open-source CLI (sigcomply-cli) from private cloud backend (sigcomply-cloud) |
| **SigComply CLI** | Open-source Go binary that collects evidence, evaluates policies, and generates attestations locally |
| **SigComply Cloud** | Private Rails backend that stores compliance results, enables drift detection, and provides auditor portal (paid tier) |
| **Sovereign Vault** | Customer-controlled storage (S3, GCS, local) where raw evidence stays—SigComply never accesses it |

---

## Data Types

| Term | Definition |
|------|------------|
| **Evidence** | Raw data collected from APIs (AWS IAM users, S3 buckets, etc.). Never leaves customer environment. |
| **PolicyInput** | Normalized data sent to OPA for evaluation. Stays in customer storage. |
| **PolicyResult** | Outcome of evaluating one policy (pass/fail, violations, metrics) |
| **Violation** | A specific resource that failed a policy check (resource ID, type, reason) |
| **CheckResult** | Complete results of a compliance run (all PolicyResults, summary, environment info) |
| **Attestation** | Cryptographic proof: SHA-256 hashes of evidence + signature + version info. Proves evidence existed and which tools/policies were used. Uses canonical JSON for deterministic hashing. |
| **EvidenceManifest** | Index file listing all stored evidence with file paths and hashes |

---

## Cryptographic Integrity

| Term | Definition |
|------|------------|
| **Canonical JSON** | JSON serialization with deterministic map key ordering (alphabetically sorted). Required because Go's map iteration is random—without it, identical data could produce different hashes. |
| **EvidenceHashes** | Container for all hashes: `CheckResult` hash, individual `Evidence` hashes, optional `Manifest` hash, and `Combined` (single hash of all) |
| **Combined Hash** | Single SHA-256 hash representing all evidence, computed from concatenation of sorted individual hashes |
| **CLIVersion** | Version of SigComply CLI that created the attestation—enables reproducibility |
| **PolicyVersions** | Map of policy ID to version/hash—proves which exact policies were evaluated |

---

## Collection

| Term | Definition |
|------|------------|
| **Collector** | Component that fetches data from a service API (AWS, GitHub, GCP) |
| **Data Source** | Origin of evidence: API-based (AWS, GitHub) or manual uploads |
| **Fail-safe Collection** | Partial success is OK—collect what you can, warn on missing permissions |

---

## Policy Engine

| Term | Definition |
|------|------------|
| **OPA** | Open Policy Agent—the policy engine that evaluates Rego policies |
| **Rego** | Policy language used by OPA to define compliance rules |
| **Embedded Policies** | Policies compiled into the CLI binary via `go:embed` (no filesystem dependency) |
| **Framework-specific Policies** | Each compliance framework has its own policy files (not shared/mapped across frameworks) |

---

## Compliance Frameworks

| Term | Definition |
|------|------------|
| **Framework** | A compliance standard (SOC 2, HIPAA, ISO 27001) with defined controls |
| **Control** | A specific requirement within a framework (e.g., CC6.1 = MFA required) |
| **SOC 2** | Service Organization Control 2—focuses on Trust Service Criteria (Security, Availability, etc.) |
| **HIPAA** | Health Insurance Portability and Accountability Act—healthcare data protection |
| **ISO 27001** | Information security management system standard with 114 controls |

### SOC 2 Trust Service Criteria

| ID | Name |
|----|------|
| CC6.x | Logical and Physical Access Controls |
| CC7.x | System Operations (monitoring, incident response) |
| CC8.x | Change Management |

---

## Authentication

| Term | Definition |
|------|------------|
| **OIDC** | OpenID Connect—used for ephemeral authentication (no long-lived secrets) |
| **CI/CD OIDC Token** | Short-lived token from GitHub Actions or GitLab CI for authentication |
| **Workload Identity** | Cloud-native OIDC authentication (AWS IAM Roles, GCP Workload Identity Federation) |

---

## Cloud API (Paid Tier)

| Term | Definition |
|------|------------|
| **Cloud Submission** | Sending CheckResult + Attestation to SigComply Cloud (not raw evidence) |
| **Drift Detection** | Tracking compliance changes over time ("CC6.1 failed last week, passing now") |
| **Resource Tracking** | Following individual resources across compliance runs ("alice has had 3 MFA violations") |
| **Evidence Location** | Reference (URI) to where raw evidence is stored—sent to cloud, not the evidence itself |

---

## CLI Concepts

| Term | Definition |
|------|------------|
| **Zero-config** | `sigcomply check` works immediately with AWS defaults, no setup required |
| **Progressive Configuration** | Only configure features when you need them |
| **Auto-detection** | CLI detects collectors (from credentials), CI environment, cloud mode automatically |
| **init-ci** | Command to scaffold minimal CI/CD workflow files |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success—all checks passed |
| 1 | Violations found |
| 2 | Execution error |
| 3 | Configuration error |

---

## Storage

| Term | Definition |
|------|------------|
| **Storage Backend** | Where evidence is stored: local filesystem, S3, GCS |
| **Run Directory** | `{prefix}/{framework}/{year}/{month}/{day}/{run_id}/` structure for organizing evidence |
| **manifest.json** | File listing all evidence with paths and SHA-256 hashes |

---

## Signing Methods

| Method | Use Case |
|--------|----------|
| `oidc-jwt` | CI/CD platform OIDC token (GitHub Actions, GitLab CI) |

### Attestation Payload (What's Signed)

The signature covers: `ID`, `RunID`, `Framework`, `Timestamp`, `Hashes`, `Environment`, `CLIVersion`, `PolicyVersions`

**Not signed:** `StorageLocation` (operational metadata that may change without invalidating evidence integrity)

---

## Key Distinctions

### What stays with customer vs goes to cloud

| Stays with Customer | Goes to SigComply Cloud |
|---------------------|--------------------------|
| Raw evidence (API responses) | Full CheckResult (policy outcomes) |
| Policy inputs (OPA input data) | All Violations (resource IDs, reasons) |
| Credentials | Signed Attestation (hashes) |
| | Evidence location reference |

### Why still "Evidence without Access"

- SigComply never gets customer credentials
- SigComply never receives raw API responses
- SigComply only sees compliance evaluation results (derived metadata)
- Competitors (Vanta, Drata) have full API access—we only see outcomes
