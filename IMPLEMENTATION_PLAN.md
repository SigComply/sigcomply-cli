# TraceVault CLI - Implementation Plan

**Version**: 3.0 | **Date**: 2026-01-10

Architecture: [ARCHITECTURE.md](./ARCHITECTURE.md) | Glossary: [GLOSSARY.md](./GLOSSARY.md)

---

## Overview

- **Zero-config first run** as top priority
- **Test-driven development** from day one
- **Small, atomic commits** per task

---

## Dependencies

```go
require (
    github.com/spf13/cobra v1.8.0
    github.com/aws/aws-sdk-go-v2 v1.24.0
    github.com/aws/aws-sdk-go-v2/config v1.26.0
    github.com/aws/aws-sdk-go-v2/service/iam v1.28.0
    github.com/aws/aws-sdk-go-v2/service/s3 v1.47.0
    github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.35.0
    github.com/aws/aws-sdk-go-v2/service/sts v1.26.0
    github.com/open-policy-agent/opa v0.60.0
)
```

---

## Phase 0: MVP

**Goal**: `tracevault check` with zero config shows compliance results.

### Week 1: Foundation & CLI

| Task | Files | Tests | Done |
|------|-------|-------|------|
| Initialize Go module | `go.mod`, `go.sum` | - | [ ] |
| CLI entry point | `cmd/tracevault/main.go` | - | [ ] |
| Makefile | `Makefile` | - | [ ] |
| golangci-lint config | `.golangci.yml` | - | [ ] |
| GitHub Actions CI | `.github/workflows/test.yml` | - | [ ] |
| AWS config auto-loading | `internal/core/config/config.go` | `config_test.go` | [ ] |
| Account ID detection (STS) | `internal/data_sources/apis/aws/collector.go` | `collector_test.go` | [ ] |
| Check command | `cmd/tracevault/main.go` | - | [ ] |
| Evidence struct | `internal/core/evidence/evidence.go` | `evidence_test.go` | [ ] |

### Week 2: AWS Collector

| Task | Files | Tests | Done |
|------|-------|-------|------|
| IAM client setup | `internal/data_sources/apis/aws/collector.go` | - | [ ] |
| List users with MFA status | `internal/data_sources/apis/aws/iam.go` | `iam_test.go` | [ ] |
| Handle pagination | `internal/data_sources/apis/aws/iam.go` | `iam_test.go` | [ ] |
| List S3 buckets | `internal/data_sources/apis/aws/s3.go` | `s3_test.go` | [ ] |
| Get bucket encryption | `internal/data_sources/apis/aws/s3.go` | `s3_test.go` | [ ] |
| List CloudTrail trails | `internal/data_sources/apis/aws/cloudtrail.go` | `cloudtrail_test.go` | [ ] |
| Get trail status | `internal/data_sources/apis/aws/cloudtrail.go` | `cloudtrail_test.go` | [ ] |
| Collector orchestration | `internal/data_sources/apis/aws/collector.go` | `collector_test.go` | [ ] |
| Fail-safe collection | `internal/data_sources/apis/aws/collector.go` | `collector_test.go` | [ ] |

### Week 3: Policy Engine & Policies

| Task | Files | Tests | Done |
|------|-------|-------|------|
| OPA engine wrapper | `internal/compliance_frameworks/engine/engine.go` | `engine_test.go` | [ ] |
| Framework registry | `internal/compliance_frameworks/engine/registry.go` | - | [ ] |
| SOC2 framework setup | `internal/compliance_frameworks/soc2/framework.go` | - | [ ] |
| SOC2 controls mapping | `internal/compliance_frameworks/soc2/controls.go` | - | [ ] |
| CC6.1 MFA policy | `internal/compliance_frameworks/soc2/policies/cc6_1_mfa.rego` | `*_test.rego` | [ ] |
| CC6.2 Encryption policy | `internal/compliance_frameworks/soc2/policies/cc6_2_encryption.rego` | `*_test.rego` | [ ] |
| CC7.1 Logging policy | `internal/compliance_frameworks/soc2/policies/cc7_1_logging.rego` | `*_test.rego` | [ ] |
| Shared Rego helpers | `internal/compliance_frameworks/shared/lib.rego` | - | [ ] |
| Text output formatter | `internal/core/output/text.go` | `text_test.go` | [ ] |
| Wire engine into check | `cmd/tracevault/main.go` | - | [ ] |

### Week 4: Polish & CI/CD

| Task | Files | Tests | Done |
|------|-------|-------|------|
| JSON output formatter | `internal/core/output/json.go` | `json_test.go` | [ ] |
| JUnit XML formatter | `internal/core/output/junit.go` | `junit_test.go` | [ ] |
| --format flag | `cmd/tracevault/main.go` | - | [ ] |
| Reusable GH workflow | `.github/workflows/compliance.yml` | - | [ ] |
| Example workflow | `examples/github-actions/basic.yml` | - | [ ] |
| Install script | `scripts/install.sh` | - | [ ] |
| GoReleaser config | `.goreleaser.yml` | - | [ ] |
| Release workflow | `.github/workflows/release.yml` | - | [ ] |

---

## Phase 0 Deliverables

**Commands**: `tracevault version`, `tracevault check`, `tracevault check --format json`

**Evidence**: AWS IAM users (MFA), S3 buckets (encryption), CloudTrail trails (status)

**Policies**: CC6.1 (MFA), CC6.2 (S3 encryption), CC7.1 (CloudTrail)

**Output**: Text, JSON, JUnit XML

**CI/CD**: GitHub Actions reusable workflow, install script

**Not in P0**: Storage, attestations, cloud API, OIDC, GitHub collector, secret scanner, init commands

---

## Post-MVP: Documentation

| Task | Files | Done |
|------|-------|------|
| Write public README | `README.md` | [ ] |

---

## Phase 1: Launch

**Goal**: Production-ready with storage, attestations, and cloud integration.

### Storage

| Task | Files | Done |
|------|-------|------|
| Storage interface | `internal/core/storage/storage.go` | [ ] |
| Local backend | `internal/core/storage/local/local.go` | [ ] |
| S3 backend | `internal/core/storage/s3/s3.go` | [ ] |
| Manifest generation | `internal/core/storage/manifest.go` | [ ] |
| --store flag | `cmd/tracevault/main.go` | [ ] |

### Attestation

| Task | Files | Done |
|------|-------|------|
| Attestation types | `internal/core/attestation/types.go` | [ ] |
| Hash computation | `internal/core/attestation/hash.go` | [ ] |
| HMAC signing | `internal/core/attestation/hmac.go` | [ ] |
| OIDC signing | `internal/core/attestation/oidc.go` | [ ] |

### Cloud Integration

| Task | Files | Done |
|------|-------|------|
| Cloud client | `internal/core/cloud/client.go` | [ ] |
| CloudSubmission type | `internal/core/cloud/types.go` | [ ] |
| OIDC auth | `internal/core/cloud/auth.go` | [ ] |
| --cloud flag | `cmd/tracevault/main.go` | [ ] |

### GitHub Collector

| Task | Files | Done |
|------|-------|------|
| GitHub client | `internal/data_sources/apis/github/collector.go` | [ ] |
| Repo collection | `internal/data_sources/apis/github/repos.go` | [ ] |
| Member collection | `internal/data_sources/apis/github/members.go` | [ ] |
| Branch protection policy | `internal/compliance_frameworks/soc2/policies/` | [ ] |

### Additional Components

| Task | Files | Done |
|------|-------|------|
| Secret scanner | `internal/core/scanner/scanner.go` | [ ] |
| Config loader | `internal/core/config/loader.go` | [ ] |
| Config validator | `internal/core/config/validator.go` | [ ] |
| init command | `cmd/tracevault/init.go` | [ ] |
| init-ci command | `cmd/tracevault/init_ci.go` | [ ] |
| collect command | `cmd/tracevault/collect.go` | [ ] |
| evaluate command | `cmd/tracevault/evaluate.go` | [ ] |
| report command | `cmd/tracevault/report.go` | [ ] |
| SARIF formatter | `internal/core/output/sarif.go` | [ ] |

---

## Success Criteria

### P0 MVP

- [ ] `tracevault check` works with zero config
- [ ] Shows 3 SOC 2 control results
- [ ] Unit test coverage >80%
- [ ] Policy tests pass
- [ ] GitHub Actions workflow works
- [ ] First binary release (v0.1.0)

### P1 Launch

- [ ] Local + S3 storage backends
- [ ] Attestation with HMAC + OIDC signing
- [ ] Cloud submission working
- [ ] GitHub collector
- [ ] Secret scanner
- [ ] All CLI commands implemented
- [ ] SARIF output format

---

## Testing

```bash
make test              # Unit + policy tests
make test-coverage     # With coverage report
make test-policy       # OPA policy tests only
make test-integration  # Requires LocalStack
```

Use interface-based mocks for AWS SDK. See ARCHITECTURE.md for mock pattern.
