# TraceVault Glossary

Quick reference for key terms and concepts. For full context, see [CLAUDE.md](./CLAUDE.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Core Philosophy

| Term | Definition |
|------|------------|
| **Evidence without Access** | TraceVault's core principle: prove compliance without giving vendors access to production infrastructure or raw data |
| **Non-custodial** | TraceVault never holds customer credentials, raw evidence, or production data |
| **Compliance as Code** | Treating compliance checks like automated tests—they run in CI/CD and fail builds when controls are violated |

---

## Architecture

| Term | Definition |
|------|------------|
| **2-Repo Architecture** | Separation of open-source CLI (tracevault-cli) from private cloud backend (tracevault-cloud) |
| **TraceVault CLI** | Open-source Go binary that collects evidence, evaluates policies, and generates attestations locally |
| **TraceVault Cloud** | Private Rails backend that stores compliance results, enables drift detection, and provides auditor portal (paid tier) |
| **Sovereign Vault** | Customer-controlled storage (S3, GCS, local) where raw evidence stays—TraceVault never accesses it |

---

## Data Types

| Term | Definition |
|------|------------|
| **Evidence** | Raw data collected from APIs (AWS IAM users, S3 buckets, etc.). Never leaves customer environment. |
| **PolicyInput** | Normalized data sent to OPA for evaluation. Stays in customer storage. |
| **PolicyResult** | Outcome of evaluating one policy (pass/fail, violations, metrics) |
| **Violation** | A specific resource that failed a policy check (resource ID, type, reason) |
| **CheckResult** | Complete results of a compliance run (all PolicyResults, summary, environment info) |
| **Attestation** | Cryptographic proof: SHA-256 hashes of evidence + signature. Proves evidence existed without revealing it. |
| **EvidenceManifest** | Index file listing all stored evidence with file paths and hashes |

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
| **Cloud Submission** | Sending CheckResult + Attestation to TraceVault Cloud (not raw evidence) |
| **Drift Detection** | Tracking compliance changes over time ("CC6.1 failed last week, passing now") |
| **Resource Tracking** | Following individual resources across compliance runs ("alice has had 3 MFA violations") |
| **Evidence Location** | Reference (URI) to where raw evidence is stored—sent to cloud, not the evidence itself |

---

## CLI Concepts

| Term | Definition |
|------|------------|
| **Zero-config** | `tracevault check` works immediately with AWS defaults, no setup required |
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
| `none` | Local development (no signature) |
| `hmac-sha256` | Shared secret signing |
| `oidc` | CI/CD platform OIDC token |
| `ecdsa-p256` | Customer private key (enterprise) |

---

## Key Distinctions

### What stays with customer vs goes to cloud

| Stays with Customer | Goes to TraceVault Cloud |
|---------------------|--------------------------|
| Raw evidence (API responses) | Full CheckResult (policy outcomes) |
| Policy inputs (OPA input data) | All Violations (resource IDs, reasons) |
| Credentials | Signed Attestation (hashes) |
| | Evidence location reference |

### Why still "Evidence without Access"

- TraceVault never gets customer credentials
- TraceVault never receives raw API responses
- TraceVault only sees compliance evaluation results (derived metadata)
- Competitors (Vanta, Drata) have full API access—we only see outcomes
