# SigComply CLI — Claude Context

This file is the AI-coding context for the CLI repo. It captures the
invariants, decisions, and conventions an agent needs to make safe
changes here. Architecture details live in
[ARCHITECTURE.md](./ARCHITECTURE.md); configuration in
[docs/configuration.md](./docs/configuration.md). Don't restate them here.

## Product Overview

**SigComply** is a zero-trust, non-custodial compliance engine —
"Evidence without Access." Open-source CLI that runs in customer CI/CD,
evaluates OPA/Rego policies against infrastructure, signs the resulting
evidence locally, and (optionally, paid tier) submits aggregated counts
to a private Rails dashboard.

The product spans **4 logical components across 5 sibling repos**.
Full cross-repo architecture: [parent CLAUDE.md](../CLAUDE.md).

| Component | Local path | Remote |
|-----------|-----------|--------|
| **The Engine (CLI)** — this repo, Go | `./` | `git@github.com:SigComply/sigcomply-cli.git` |
| **Compliance Dashboard** — Rails 8.1 / Ruby 3.3 (private) | `../sigcomply/` | `git@github.com:SigComply/sigcomply.git` |
| **Manual Evidence SPA** — React 19 + TS + Vite | `../sigcomply-evidence-spa/` | `git@github.com:SigComply/sigcomply-evidence-spa.git` |
| **CLI E2E (GitHub Actions)** | `../sigcomply-cli-testing-project-github/` | `git@github.com:SigComply/sigcomply-cli-testing-project-github.git` |
| **CLI E2E (GitLab CI)** | `../sigcomply-cli-testing-project-gitlab/` | `git@gitlab-personal:sigcomply/sigcomply-cli-testing-project-gitlab.git` |

**Frameworks shipped today**: SOC 2 (production-ready, 400+ policies);
ISO 27001 (early stage, handful of policies, no manual catalog yet). HIPAA
is a stated future goal — there is no `hipaa/` package, no policies, and no
catalog. `config.go` still lists `"hipaa"` in `SupportedFrameworks`, but
selecting it will fail because no framework registers under that name.

---

## IMPORTANT: Check for Local Instructions

**Before starting any work, check if `CLAUDE.local.md` exists in the repo
root.** If present, read it first and follow its instructions. The local
file contains:

- Private integration references not suitable for public documentation
- Additional context for maintaining consistency with external systems
- Instructions that override or supplement this public document

The local file is gitignored and will not be present in all environments.

---

## Documentation

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — system design, types, storage layout, signing
- **[docs/configuration.md](./docs/configuration.md)** — config file, env vars, flags
- **[docs/claude/auth.md](./docs/claude/auth.md)** — OIDC authentication details
- **[docs/claude/recipes.md](./docs/claude/recipes.md)** — step-by-step guides for common tasks
- **[README.md](./README.md)** — public-facing intro

---

## Development Rules

### Ship Working Code

Working, tested code is the primary measure of progress. Don't
over-document — only update docs when architecture changes. Code with
clear names and tests usually needs no extra docs.

### Test-Driven Development

1. Write unit tests first
2. Write a basic happy-path integration test
3. Implement the minimum code to pass
4. Verify the full suite passes (`make test && make lint`)
5. Update docs only if architecture changed

### Architecture-First

Before implementing: read relevant docs, plan the approach. If the
design feels overly complex, **stop and ask** — difficulty is a signal
to pause, not push through.

### Small, Atomic Commits

- One logical change per commit, all tests passing
- Format: `<type>: <description>` (types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`)
- Include `Co-Authored-By: Claude <model> <noreply@anthropic.com>`

### Never Break Main

Run `make test && make lint` before every commit. After pushing to
main, verify the GitHub Actions pipeline is green via `gh run list` /
`gh run view`. Don't move on while CI is red.

---

## Sacred Invariants

These are non-negotiable. Violating any of them is a hard architectural
break — stop and ask before proceeding.

### 1. The aggregation boundary

The CLI is the **only** place where raw evidence (resource IDs, ARNs,
usernames, emails, PDF bytes, file hashes) is reduced to counts. Any
change that would cause an identifier to appear in a Cloud API request
breaks the non-custodial model.

What goes to the Cloud API (paid tier, `POST /api/v1/cli/runs`):
- Per-policy: `policy_id`, `control_id`, pass/fail, severity,
  `resources_evaluated`, `resources_failed`, `message` (count-based,
  no IDs), `category`, `remediation`
- Run summary: total/passed/failed/skipped policies, compliance score
- Environment: `ci`, `ci_provider`, `repository`, `branch`,
  `commit_sha`, `cli_version`

What stays in customer storage (always):
- Raw API responses, PDF bytes, full violation lists with resource
  identifiers, ephemeral public key + signature.

The contract is encoded in `internal/core/cloud/types.go`. Rails
strong-params live in `../sigcomply/app/controllers/api/v1/cli/runs_controller.rb`.
If you touch one side, check the other.

### 2. Two — and only two — evidence flows

Every policy declares `evidence_type: automated | manual` in its `metadata`
rule. The OPA evaluator never branches on anything else.

- **Automated**: API collector → structured JSON → wrapped in
  `EvidenceEnvelope` → policy reads `input.data.*`.
- **Manual**: customer-supplied PDF at the catalog-resolved path → CLI
  hashes bytes → small JSON manifest `{evidence_id, file_hash, file_path,
  period, framework}` is wrapped in `EvidenceEnvelope`; PDF mirrored as
  sibling. Policy (v1) checks presence within the temporal window via
  `data.sigcomply.lib.manual.presence_violation`.

There are no `checklist` / `declaration` / `document_upload` sub-types in
the evaluator. The catalog YAML keeps `type`, `items`, `declaration_text`
as render hints **for the SPA** — the CLI ignores them.

### 3. Per-file ephemeral signing

A fresh Ed25519 keypair is generated **per evidence file**, never per run.
Private key is discarded the instant the signature is computed; public key
+ signature live inside the file (`EvidenceEnvelope`). Signing covers
canonical JSON of `{timestamp, evidence}` — not a SHA-256 hash. The PDF
itself is hashed (SHA-256) only because the manual manifest references the
hash; the envelope still signs the manifest, not the hash.

Threat model: protects against accidental corruption and unintentional
drift. Does **not** attempt to prevent a determined customer from
fabricating evidence (that's fraud — out of scope for all compliance
tools).

---

## CLI runtime architecture (summary)

Detailed flow + types live in [ARCHITECTURE.md](./ARCHITECTURE.md). The
short version:

```
sigcomply check
  ├─ collect (automated): AWS / GitHub / GCP collectors → []Evidence
  ├─ collect (manual):    read PDFs from manual-evidence storage → manifests
  ├─ evaluate:            OPA engine evaluates all policies → CheckResult
  ├─ store (--store / auto in CI): per-policy folders with signed envelopes
  │                       + sibling PDFs + result.json + framework summary.json
  └─ submit (paid tier):  POST aggregated counts to /api/v1/cli/runs
```

**Storage layout** (policy-first):
`{framework}/{policy_id}/{timestamp}_{run_id_short}/{evidence,manual_attachments,result.json}`
plus `{framework}/summary.json` and `{framework}/execution-state.json`.

**Manual evidence has its own per-framework backend** under
`manual_evidence.frameworks.<framework>` — a customer can keep SOC 2 PDFs
in S3 and ISO 27001 PDFs in GCS or Azure Blob.

---

## File Structure

```
sigcomply-cli/
├── main.go                            # CLI entry
├── cmd/sigcomply/                     # Cobra commands (check, evidence, version)
│
├── internal/
│   ├── compliance_frameworks/
│   │   ├── engine/                    # OPA engine, framework registry, manual helpers
│   │   ├── shared/lib.rego            # Shared Rego helpers
│   │   ├── soc2/                      # SOC 2 (production-ready)
│   │   │   ├── framework.go
│   │   │   ├── controls.go
│   │   │   └── policies/
│   │   │       ├── aws/               # ~700 .rego files (incl. tests)
│   │   │       ├── gcp/               # GCP policies
│   │   │       ├── github/            # GitHub policies
│   │   │       ├── multi/             # Cross-collector policies
│   │   │       └── manual/            # Manual-evidence policies
│   │   └── iso27001/                  # ISO 27001 (2 policies — early stage)
│   │       └── policies/{aws,multi}/
│   │
│   ├── data_sources/
│   │   ├── apis/                      # Automated collectors
│   │   │   ├── aws/                   # 60+ services (iam, s3, cloudtrail, ec2,
│   │   │   │                          # rds, kms, guardduty, configservice,
│   │   │   │                          # cloudwatch, eks, ecs, lambda, dynamodb,
│   │   │   │                          # securityhub, …) — see directory listing
│   │   │   ├── github/                # collector, repos, members
│   │   │   └── gcp/                   # collector, iam, storage, compute, sql
│   │   └── manual/                    # PDF reader (manual flow)
│   │
│   └── core/
│       ├── evidence/                  # Evidence, PolicyResult, Violation, CheckResult
│       ├── config/                    # Config loading + env var binding
│       ├── output/                    # text, json, junit formatters
│       ├── storage/                   # local, s3, gcs, azure_blob backends + run paths + summary
│       ├── manual/                    # Manual catalog, period/grace logic, execution state
│       │   └── catalogs/              # Embedded YAML catalogs (soc2.yaml today)
│       ├── attestation/               # Ephemeral Ed25519 signing, canonical JSON, OIDC helpers
│       └── cloud/                     # SigComply Cloud client (POST /api/v1/cli/runs)
│
├── examples/                          # CI/CD workflow examples
├── .github/workflows/                 # CI + release automation
└── scripts/                           # Build + dev scripts
```

### Key organizational principles

1. **compliance_frameworks/** — each framework is self-contained
   (framework.go + controls.go + policies/ subtree). Policies are
   organized **by collector under `policies/`** (aws, gcp, github, multi,
   manual) — not flat — because the collection cost differs per source.
2. **data_sources/** separates "where we get data" from "what we check".
   `apis/<service>/` contains one file per AWS/GCP service; `manual/`
   handles the PDF flow.
3. **core/** holds shared types + utilities. Don't put framework- or
   collector-specific logic here.

---

## CLI Interface

| Command | Status | Notes |
|---------|--------|-------|
| `sigcomply check` | Wired | Main entry — collect → evaluate → store → submit |
| `sigcomply evidence init` | Wired | Scaffold per-period folders for manual evidence |
| `sigcomply evidence catalog` | Wired | Print manual catalog; consumed by SPA at build time |
| `sigcomply evidence path <evidence_id>` | Wired | Print upload URI for a specific manual entry |
| `sigcomply version` | Wired | Print CLI version + commit + build time |
| `sigcomply init` | Planned | Not yet in `cmd/sigcomply/root.go` |
| `sigcomply init-ci` | Planned | Not yet in `cmd/sigcomply/root.go` |
| `sigcomply collect` | Planned | Collect-only mode |
| `sigcomply evaluate` | Planned | Evaluate stored evidence offline |
| `sigcomply report` | Planned | Generate audit-ready reports |

Note: `evidence` subcommands take `--config` and `--output`/`-o` only —
**not `--framework`**. Framework comes from `SIGCOMPLY_FRAMEWORK` or
`framework:` in the config file (default: `soc2`).

### Flags actually wired on `sigcomply check`

```
-f, --framework string      Compliance framework (default empty → soc2)
-o, --output string         Output format: text, json, junit
    --json-output string    Also write JSON to this file
-v, --verbose               Verbose output
    --region string         AWS region
    --store                 Persist evidence + results to configured storage
    --storage-path string   Local storage path
    --storage-backend       Storage backend (local, s3, gcs, azure_blob)
    --cloud / --no-cloud    Force / disable Cloud submission
    --github-org string     GitHub org (requires GITHUB_TOKEN)
    --policies string       Comma-separated policy names to run
    --controls string       Comma-separated control IDs to run
    --config string         Path to config file (default .sigcomply.yaml)
```

There is no `--quiet`, `--service`, `--collector`, `--fail-on-violation`,
or `--fail-severity` flag today — `fail_on_violation` and `fail_severity`
are config-file-only fields under `ci:`. SARIF output is **not** yet
wired (the format is in `SupportedOutputFormats` but no formatter
exists).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Violations found |
| 2 | Execution error |
| 3 | Configuration error |

### Auto-detection

- **Collectors**: from available credentials (`AWS_*`, `GITHUB_TOKEN`, GCP ADC)
- **CI environment**: `GITHUB_ACTIONS`, `GITLAB_CI`, generic `CI`
- **Cloud submission**: auto-enabled when an OIDC token is available in CI

---

## Configuration

Full reference: [docs/configuration.md](./docs/configuration.md).

Quick rules:

- YAML key for the framework is **singular** (`framework: soc2`), not a
  list. There is no `frameworks:` field.
- Precedence: CLI flags > env vars (`SIGCOMPLY_*`) > config file > defaults.
- Storage backends: `local`, `s3`, `gcs`, `azure_blob`. The `s3` backend
  also supports on-prem S3-compatible stores via `endpoint` +
  `force_path_style`.
- Manual evidence has its own per-framework backend selection under
  `manual_evidence.frameworks.<framework>`.
- Cloud submission is OIDC-only (no API keys) and auto-enables in CI.

---

## Cross-Repo Integration Points

When changing any of these in the CLI, check the corresponding place in
the Rails app at `../sigcomply/`:

| CLI side | Rails side | Contract |
|----------|------------|----------|
| `internal/core/cloud/types.go` | `app/controllers/api/v1/cli/runs_controller.rb` (strong params) | Aggregated run payload |
| OIDC token helpers in `internal/core/attestation/oidc.go` | `app/services/oidc/token_validator.rb` | Token format, claim names (`repository`, `namespace_path`/`project_path`) |
| Manual evidence catalog (`internal/core/manual/catalogs/*.yaml`) | SPA `scripts/fetch-catalogs.ts` (in `../sigcomply-evidence-spa/`) | The SPA pre-builds catalogs via `sigcomply evidence catalog -o json` |

Other Rails CLI endpoints exist (`policy_evaluations`, `compliance_status`,
`heartbeat`, `health`) — `policy_evaluations` is the legacy precursor of
`runs`. New work goes through `runs`.

---

## Current Status

**Stage**: Active development — SOC 2 production-ready, ISO 27001 early.

**Done**:
- Zero-config `sigcomply check` (auto-detect AWS)
- AWS collector across 60+ services
- GCP collector (IAM, Storage, Compute, SQL)
- GitHub collector (repos, members)
- OPA engine with 400+ embedded SOC 2 policies (split across aws/gcp/github/multi/manual)
- ISO 27001 scaffolding with 2 policies as a proof of concept
- text / json / junit output formatters
- Storage backends: local, S3 (incl. on-prem S3-compatible), GCS, Azure Blob
- Per-file ephemeral Ed25519 signing + canonical JSON
- Manual evidence flow: catalog, period/grace logic, execution state, sidecar mirroring
- Framework `summary.json` (per-policy snapshot, automated/manual split, merge-with-prior)
- SigComply Cloud client (`POST /api/v1/cli/runs`)
- OIDC auth (GitHub Actions + GitLab CI)
- Policy filtering (`--policies`, `--controls`)
- Release automation (auto-release via conventional commits, manual release, GoReleaser)
- GitHub Actions reusable workflow + GitLab CI component
- E2E test framework

**Remaining**:
- HIPAA framework (not started — placeholder string in `config.go` only)
- ISO 27001 policy library (only 2 policies today; no manual catalog)
- Manual catalog for non-SOC 2 frameworks (`internal/core/manual/catalogs/`)
- `init`, `init-ci`, `collect`, `evaluate`, `report`, `config` commands
- Secret scanner
- SARIF output formatter (config validates the format but no implementation)

---

## Notes for AI Assistants

- **Don't undo the aggregation boundary.** The Cloud client must never
  send resource identifiers. `internal/core/cloud/types.go` carries an
  explicit warning against adding a freeform metadata field. Respect it.
- **Don't invent evidence types.** The OPA evaluator only knows
  `automated` and `manual`. Catalog `type` values like `declaration`,
  `checklist`, `document_upload` are SPA render hints — the CLI ignores them.
- **Don't sign hashes.** Signing covers canonical JSON of
  `{timestamp, evidence}`. SHA-256 is used only to identify the manual
  PDF inside the manifest, not as the signing input.
- **Per-file keypair, never per-run.** A run can collect dozens of evidence
  files — each gets its own Ed25519 keypair, and the private key is
  discarded immediately.
- **HIPAA isn't a thing yet.** Don't add HIPAA examples to docs. Don't
  put HIPAA defaults into code paths. The string lives in `config.go`'s
  supported list as a stub; selecting it currently fails at runtime.
- **Framework yaml key is singular.** `framework: soc2`, not `frameworks: [soc2]`.
- **Manual evidence catalog is SOC 2 only today.** ISO 27001 has no
  catalog (`internal/core/manual/catalogs/iso27001.yaml` doesn't exist),
  so `sigcomply evidence catalog --framework=iso27001` errors out.
- **Run paths use basic ISO 8601 timestamps.** No colons in the path —
  `20260325T100000Z`, not `2026-03-25T10:00:00Z`. Some S3-compatible
  tools choke on colons.
- **Don't add files matching `*_test.rego` to non-test counts.** The
  policies/ subtrees mix `_test.rego` test files alongside their
  policies, so naive globs over-count.
- **Avoid editing `cmd/sigcomply/check.go` flag descriptions** without
  reflecting the change in `docs/configuration.md` and the table above.
  The `--framework` description still mentions `hipaa` — leave it for a
  separate cleanup; it's a tracked stale string, not load-bearing.

---

## Resources

- Open Policy Agent: https://www.openpolicyagent.org/
- Rego language: https://www.openpolicyagent.org/docs/latest/policy-language/
- SOC 2: https://www.aicpa.org/soc
- ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
