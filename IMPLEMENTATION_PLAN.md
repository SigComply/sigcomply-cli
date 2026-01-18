# TraceVault CLI - Implementation Plan

**Version**: 3.1 | **Date**: 2026-01-17

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

## Phase 0: MVP (COMPLETED)

**Goal**: `tracevault check` with zero config shows compliance results.

### Week 1: Foundation & CLI

| Task | Files | Tests | Done |
|------|-------|-------|------|
| Initialize Go module | `go.mod`, `go.sum` | - | [x] |
| CLI entry point | `cmd/tracevault/main.go` | - | [x] |
| Makefile | `Makefile` | - | [x] |
| golangci-lint config | `.golangci.yml` | - | [x] |
| GitHub Actions CI | `.github/workflows/test.yml` | - | [x] |
| AWS config auto-loading | `internal/core/config/config.go` | `config_test.go` | [x] |
| Account ID detection (STS) | `internal/data_sources/apis/aws/collector.go` | `collector_test.go` | [x] |
| Check command | `cmd/tracevault/main.go` | - | [x] |
| Evidence struct | `internal/core/evidence/evidence.go` | `evidence_test.go` | [x] |

### Week 2: AWS Collector

| Task | Files | Tests | Done |
|------|-------|-------|------|
| IAM client setup | `internal/data_sources/apis/aws/collector.go` | - | [x] |
| List users with MFA status | `internal/data_sources/apis/aws/iam.go` | `iam_test.go` | [x] |
| Handle pagination | `internal/data_sources/apis/aws/iam.go` | `iam_test.go` | [x] |
| List S3 buckets | `internal/data_sources/apis/aws/s3.go` | `s3_test.go` | [x] |
| Get bucket encryption | `internal/data_sources/apis/aws/s3.go` | `s3_test.go` | [x] |
| List CloudTrail trails | `internal/data_sources/apis/aws/cloudtrail.go` | `cloudtrail_test.go` | [x] |
| Get trail status | `internal/data_sources/apis/aws/cloudtrail.go` | `cloudtrail_test.go` | [x] |
| Collector orchestration | `internal/data_sources/apis/aws/collector.go` | `collector_test.go` | [x] |
| Fail-safe collection | `internal/data_sources/apis/aws/collector.go` | `collector_test.go` | [x] |

### Week 3: Policy Engine & Policies

| Task | Files | Tests | Done |
|------|-------|-------|------|
| OPA engine wrapper | `internal/compliance_frameworks/engine/engine.go` | `engine_test.go` | [x] |
| Framework registry | `internal/compliance_frameworks/engine/registry.go` | - | [x] |
| SOC2 framework setup | `internal/compliance_frameworks/soc2/framework.go` | - | [x] |
| SOC2 controls mapping | `internal/compliance_frameworks/soc2/controls.go` | - | [x] |
| CC6.1 MFA policy | `internal/compliance_frameworks/soc2/policies/cc6_1_mfa.rego` | `*_test.rego` | [x] |
| CC6.2 Encryption policy | `internal/compliance_frameworks/soc2/policies/cc6_2_encryption.rego` | `*_test.rego` | [x] |
| CC7.1 Logging policy | `internal/compliance_frameworks/soc2/policies/cc7_1_logging.rego` | `*_test.rego` | [x] |
| Shared Rego helpers | `internal/compliance_frameworks/shared/lib.rego` | - | [x] |
| Text output formatter | `internal/core/output/text.go` | `text_test.go` | [x] |
| Wire engine into check | `cmd/tracevault/main.go` | - | [x] |

### Week 4: Polish & CI/CD

| Task | Files | Tests | Done |
|------|-------|-------|------|
| JSON output formatter | `internal/core/output/json.go` | `json_test.go` | [x] |
| JUnit XML formatter | `internal/core/output/junit.go` | `junit_test.go` | [x] |
| --format flag | `cmd/tracevault/main.go` | - | [x] |
| Reusable GH workflow | `.github/workflows/compliance.yml` | - | [x] |
| Example workflow | `examples/github-actions/basic.yml` | - | [x] |
| Install script | `scripts/install.sh` | - | [x] |
| GoReleaser config | `.goreleaser.yml` | - | [x] |
| Release workflow | `.github/workflows/release.yml` | - | [x] |

---

## Phase 0 Deliverables (COMPLETED)

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

## Phase 1: Launch (IN PROGRESS)

**Goal**: Production-ready with storage, attestations, and cloud integration.

### Storage (COMPLETED)

| Task | Files | Done |
|------|-------|------|
| Storage interface | `internal/core/storage/storage.go` | [x] |
| Local backend | `internal/core/storage/local.go` | [x] |
| S3 backend | `internal/core/storage/s3.go` | [x] |
| Manifest generation | `internal/core/storage/manifest.go` | [x] |
| --store flag | `cmd/tracevault/check.go` | [x] |

### Attestation (COMPLETED)

| Task | Files | Done |
|------|-------|------|
| Attestation types | `internal/core/attestation/types.go` | [x] |
| Hash computation | `internal/core/attestation/hash.go` | [x] |
| HMAC signing | `internal/core/attestation/hmac.go` | [x] |
| OIDC signing | `internal/core/attestation/oidc.go` | [x] |

### Cloud Integration (COMPLETED)

| Task | Files | Done |
|------|-------|------|
| Cloud client | `internal/core/cloud/client.go` | [x] |
| CloudSubmission type | `internal/core/cloud/types.go` | [x] |
| OIDC auth | `internal/core/cloud/auth.go` | [x] |
| --cloud flag | `cmd/tracevault/check.go` | [x] |

### GitHub Collector (PARTIAL)

| Task | Files | Done |
|------|-------|------|
| GitHub client | `internal/data_sources/apis/github/collector.go` | [x] |
| Repo collection | `internal/data_sources/apis/github/repos.go` | [x] |
| Member collection | `internal/data_sources/apis/github/members.go` | [x] |
| Branch protection policy | `internal/compliance_frameworks/soc2/policies/` | [ ] |

### Additional Components

| Task | Files | Done |
|------|-------|------|
| Secret scanner | `internal/core/scanner/scanner.go` | [ ] |
| Config loader | `internal/core/config/loader.go` | [x] |
| Config validator | `internal/core/config/validator.go` | [ ] |
| init command | `cmd/tracevault/init.go` | [ ] |
| init-ci command | `cmd/tracevault/init_ci.go` | [ ] |
| collect command | `cmd/tracevault/collect.go` | [ ] |
| evaluate command | `cmd/tracevault/evaluate.go` | [ ] |
| report command | `cmd/tracevault/report.go` | [ ] |
| SARIF formatter | `internal/core/output/sarif.go` | [ ] |

---

## Success Criteria

### P0 MVP (COMPLETED)

- [x] `tracevault check` works with zero config
- [x] Shows 3 SOC 2 control results
- [x] Unit test coverage >80%
- [x] Policy tests pass
- [x] GitHub Actions workflow works
- [x] First binary release (v0.1.0)

### P1 Launch

- [x] Local + S3 storage backends
- [x] Attestation with HMAC signing
- [x] Attestation with OIDC signing
- [x] Cloud submission working
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

---

## Current Status

**Tests**: 115 passing | **Linter**: 0 issues

**Last Updated**: 2026-01-17
