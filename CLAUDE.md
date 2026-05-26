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

What goes to the Cloud API (paid tier, `POST /api/v1/runs`) — the
`SubmissionPayload`:
- Per-policy: `policy_id`, `control_id`, pass/fail, severity,
  `resources_evaluated`, `resources_failed`, `message` (count-based,
  no IDs), `category`, `remediation`
- Run summary: total/passed/failed/skipped policies, compliance score
- Environment: `ci`, `ci_provider`, `repository`, `branch`,
  `commit_sha`, `cli_version`

The submission type is **structurally** counts-only — no `map[string]any`,
no `Violations` slice. The wire format is physically incapable of
carrying ARNs, emails, file hashes, or any identity.

What stays in customer storage (always):
- Raw API responses, PDF bytes, full violation lists with resource
  identifiers, ephemeral public key + signature, per-run `manifest.json`.

The aggregator/submitter is where this contract lives. Rails strong-params
live under `Api::V1::RunsController` in `../sigcomply/`. If you touch one
side, check the other.

### 2. Two — and only two — evidence flows

Every policy declares `evidence_mode: automated | manual` in its spec.
This is an **explicit first-class field**, not inferred from slot types or
from which evidence types are accepted. The evaluator branches on exactly
this field and nothing else.

- **Automated**: Planner binds configured API source plugins to the
  policy's slots → collector calls `plugin.Collect()` → records validated
  against evidence-type schemas → evaluator runs the `pass_when:` DSL
  condition (primary path) or the `rule:` escape hatch.
- **Manual**: Planner binds `manual.pdf` to an implicit slot, resolving
  the PDF path via `catalog_entry` → collector fetches and validates the
  PDF → evaluator runs the universal PDF-presence check: `file_present`,
  `in_temporal_window`, `file_valid`. `pass_when:` and `rule:` are ignored
  entirely for manual policies.

Projects can override the framework's `evidence_mode` default for any
policy via `policy_overrides` in `.sigcomply.yaml`. This is the mechanism
for customers who rely on manual processes today and plan to wire up API
integrations later — the policy ID stays the same; the audit trail shows
`evidence_mode` so auditors see which path was used.

There are no `checklist` / `declaration` / `document_upload` sub-types in
the evaluator. The catalog YAML keeps `type`, `items`, `declaration_text`
as **descriptive hints** — the optional Evidence SPA helper uses them to
render a clickable form for declaration/checklist entries; the CLI ignores
them entirely. Externally-sourced PDFs (HR exports, scanned documents,
third-party reports) are consumed the same way regardless of the hints.

#### Manual evidence design contract — what we do, what we don't

This is a deliberate, load-bearing design choice. Read this whole block
before changing anything in `internal/sources/manual/` or the
`manual_presence` Rego rules.

**What the CLI does (v1):**

1. **Path-resolves** the catalog entry to a deterministic upload path
   under the project's single manual-evidence bucket:
   `{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/{filename}`.
2. **Fetches** the PDF from that path. Missing file → policy fails
   with a structured "expected at: <path>" message.
3. **Hashes** the bytes (SHA-256) and records the upload timestamp.
4. **Temporal window check**: the upload timestamp must lie in
   `[period_start, period_end + grace]`. Outside → policy fails.
5. **Cheap sanity checks** (in `internal/sources/manual/manual.go`
   `validatePDF`): minimum file size, `%PDF-` magic-bytes prefix,
   presence of at least one `/Page` object. Failures land in
   `validation_failures` on the manifest and flip `file_valid` to
   `false`. Stdlib-only — no PDF parser dependency.
6. **Prior-period duplication check**: if the planner supplied
   `prior_period_id` and a file exists at the equivalent prior path,
   the SHA-256 hashes must differ. A byte-identical match is the
   signature of copy-pasting last period's file and surfaces as
   `copy_paste_of_prior_period` in `validation_failures`. Missing
   prior file is **not** a failure (first run, or no prior period).
7. **Signs** the manifest (canonical JSON of `{timestamp, evidence}`)
   with a fresh ephemeral Ed25519 keypair (see Invariant #3).

**What the CLI explicitly does NOT do:**

- **No PDF content audit.** No text extraction. No
  `signed_by` / `signed_date` parsing. No expiry-date detection. No
  page-count beyond "is there at least one `/Page` token in the byte
  stream." This is deliberate — content review is the auditor's job.
- **No semantic correctness check.** A PDF that satisfies all sanity
  checks but is the *wrong* document (last quarter's by mistake, an
  internally-different-dated file, a PDF unrelated to the policy) will
  pass. The auditor catches this when reading the documents.
- **No scope/completeness check.** "Access review covers 40 users when
  production has 120" is the most common SOC 2 audit finding industry-
  wide and remains undetectable by this design — comparing the
  document's population to live automated evidence is a future
  cross-reference feature, not v1.
- **No signature-inside-PDF detection.** Whether a board minute has
  attendee signatures, whether an NDA is countersigned, etc., is not
  inspected.
- **No fraud detection.** A determined customer who wants to fabricate
  manual evidence can produce a PDF that satisfies every check above.
  That is and remains the auditor's job (and identifying such customers
  is the auditor's livelihood, not the CLI's).

**Why this is the right v1 — and the wrong place to "fix" later
without thought.**

- The product positions itself as **custody-of-evidence**, not
  content-validator. Vanta and Drata shipped this exact model for a
  decade; Secureframe (2025) and Hyperproof (2026) added AI evidence
  validation only by sending customer PDFs to a cloud LLM — which
  breaks "evidence without access," our core differentiator.
- Auditors do not delegate substantive content review to compliance
  tools. They read the documents. The CLI's value-add over Vanta/Drata
  is the cryptographically-signed timeline of when each PDF existed at
  each path — not deeper-than-them content inspection.
- Any future check that requires reading PDF contents must stay inside
  the CLI process (never exfiltrated). Anything richer than the v1
  byte-level checks belongs in a follow-up plugin or a `manual.pdf.v2`,
  not in shortcuts inside `validatePDF`.

**Catalog-driven "this should change every period" is implicit.**
The prior-period duplication check fires for every manual catalog
entry. For genuinely-static evidence (a one-time signed declaration
that doesn't change between periods), customers use exception
declarations in `.sigcomply.yaml` rather than disabling the check. We
have not added a `unique_per_period: bool` catalog field — every
catalog entry shipped today (only `access_review_quarterly` so far) is
expected to differ each period. Add the catalog flag only when a real
catalog entry needs the override.

### 3. Per-file ephemeral signing + signed run manifest

A fresh Ed25519 keypair is generated **per evidence file**, never per run.
Private key is discarded the instant the signature is computed; public key
+ signature live inside the file (`EvidenceEnvelope`). Signing covers
canonical JSON of `{timestamp, evidence}` — not a SHA-256 hash. The PDF
itself is hashed (SHA-256) only because the manual manifest references the
hash; the envelope still signs the manifest, not the hash.

In addition, each run writes a `manifest.json` carrying `file_hashes` for
every file in the run folder (a single-level Merkle table). That manifest
is itself signed with its own ephemeral keypair, so a single signature
covers the integrity of the entire run. Per-file signatures still allow
spot-checking any one envelope offline; the run manifest lets an auditor
verify the run as a whole.

**Threat model — be precise about what this protects against.**

- **Detects** (in scope):
  - Accidental corruption of an envelope after the run (bit rot, a
    sync tool truncating a file).
  - A PDF swapped in place while the original envelope is left
    intact — the manifest's `file_hash` won't match the new bytes.
  - Modification of the per-run manifest after the run (it's signed
    too).
- **Does NOT detect** (out of scope, by design):
  - A determined customer with vault write access who regenerates the
    envelope + PDF together with a fresh ephemeral keypair. The public
    key lives inside the envelope, so any new keypair produces a
    cryptographically-valid envelope. This is indistinguishable from
    original fabrication.
  - A customer who fabricates evidence at upload time and signs it
    legitimately during the run. The CLI signs what it reads; it
    cannot verify reality.

**Customer-side requirement for true tamper-resistance.** For an
auditor to trust that "this envelope hasn't been re-signed since the
run," the bucket holding the vault must be **write-once or
version-controlled at the storage layer**. The CLI does not configure
this. Recommended customer setup:

- **S3**: Object Lock in compliance mode with a retention period
  matching audit retention (typically 7 years), or bucket versioning
  with MFA delete.
- **GCS**: Object Versioning + retention policies, or Bucket Lock.
- **Azure Blob**: Immutable storage with time-based retention
  policies.
- **Local filesystem**: not suitable for production audit retention —
  only for `sigcomply check` ad-hoc runs and CI ephemeral storage.

When this customer-side setup is **not** in place, the signing scheme
still detects accidental drift, but cannot defend against deliberate
re-signing. Make this explicit in customer-facing docs and in the
auditor-handoff guide. Do not claim tamper-resistance the design does
not deliver.

### 4. Source-agnostic policies via evidence-type contracts

Policies and source plugins never reference each other directly. The
evidence-type registry is the **sole** mediator between the two.

- **Policies declare `slots.<name>.accepts: [<type_id>, ...]`** — the
  set of evidence type IDs the slot consumes. There is no `source:`
  field anywhere in a policy spec.
- **Source plugins declare `Emits() []string`** — the set of types
  they can produce. They never know which policies (if any) consume
  their records; `SlotRequest.PolicyID` is a diagnostic-only tag.
- **The planner matches sources to slots by intersection:**
  `source.Emits() ∩ slot.Accepts ≠ ∅`. An empty intersection is a
  plan-time error (exit 3).
- **The collector validates every emitted payload** against the
  registered JSON Schema for `record.Type` before signing. A
  schema-conformance failure is a configuration error
  (>5% in one call → exit 3 for that policy), not a silent pass.

**Consequence (the substitutability property).** Adding a new source
for an existing evidence type requires **zero policy changes** —
write the plugin, drop a config block in `.sigcomply.yaml`, done.
Adding a new evidence type to an existing slot's `Accepts` list (e.g.
extending a storage-encryption policy from AWS-only to AWS+GCP) is
one line of YAML. The canonical worked example: MFA enforced on admin
users, satisfied by AWS IAM, Okta, Azure AD, or a customer's internal
LDAP — one policy spec, four different bindings in four different
projects, zero forks.

Full design: [`docs/architecture/04a-evidence-type-registry.md`](./docs/architecture/04a-evidence-type-registry.md)
and [`docs/architecture/01-conceptual-model.md`](./docs/architecture/01-conceptual-model.md)
§Axiom 1.

### 5. Two-axis cadence: scheduling state is mutable, audit evidence is not

Every policy evaluation lives on two orthogonal axes:

- **Cadence** — "should we re-evaluate this policy now?" — per-policy
  scheduling concern. The state lives in `state/{framework}/policies/
  {policy_id}.json`, is mutable, is NEVER signed, is NEVER an audit
  deliverable. Loss is recoverable (next run treats as first-run).
- **Period** — "what audit window does this run's evidence belong to?"
  — per-run compliance concern. Frozen at run-start by the planner;
  every policy in the run shares the same `period_id`. No mid-run
  rollover, ever.

The decision rule for each policy in each run is strictly layered (see
[`docs/architecture/11-cadence-model.md`](./docs/architecture/11-cadence-model.md)
§The decision rule):

1. Operator filter explicit (`--policies`, `--cadences`) → evaluate.
2. PolicyStates nil (Manual/PR mode) → evaluate.
3. Prior state nil (never run) → evaluate, surface as first-run.
4. Policy content-hash changed (bundle/schema bump) → evaluate.
5. Prior terminal status was NOT pass → evaluate (on_fail_retry).
6. `now - LastPassAt >= CadenceInterval` → evaluate.
7. Else → carry-forward result (small pointer to the prior signed
   envelope; no new signature, no new envelope).

**Consequences worth knowing.**

- The cadence DSL is `continuous|hourly|daily|weekly|monthly|quarterly|annual`
  OR `every:<duration>` (5-minute floor). No cron strings. `every:24h`
  ≠ `daily` (the former drifts; the latter is wall-clock-anchored
  with cron-drift slack).
- Carry-forward results inherit trust from the original envelope's
  signature — the CLI does not re-sign them. The auditor verifies
  the original at `CarryForward.LastEnvelopeRef`.
- Cloud submission v2 (`sigcomply.cloud.v2`) carries
  `ConfiguredCadence`, `LastEvaluatedAt`, `NextDueAt`,
  `IsCarriedForward`, `PolicyContentHash` per policy — all
  non-identifying scalars. The structural counts-only test in
  `core/cloud_test.go` continues to enforce no identity-carrying
  field can be added.
- State writes use a monotonic guard:
  `accept iff new.LastRunAt > existing.LastRunAt OR (equal AND new.LastRunID > existing.LastRunID)`.
  Concurrent CI runs cannot regress state.

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
  └─ submit (paid tier):  POST aggregated counts to /api/v1/runs
```

**Storage layout** (period-first under each framework):
`{framework}/{period_id}/run_{timestamp}_{run_id_short}/policies/{policy_id}/...`
plus `{framework}/{period_id}/summary.json` (rebuilt every run in that
period, frozen when the next period starts).

**Cadence scheduling state** lives outside the immutable evidence
prefix at `state/{framework}/policies/{policy_id}.json` — one shard
per policy, mutable, NOT signed, NOT under Object Lock. Loss of a
state shard is recoverable (next run re-evaluates as first-run).
The cadence DSL accepts the seven named values
(`continuous`|`hourly`|`daily`|`weekly`|`monthly`|`quarterly`|`annual`)
plus the `every:<duration>` escape hatch (`every:6h`, `every:90m`,
floor 5m). See [docs/architecture/11-cadence-model.md](./docs/architecture/11-cadence-model.md)
for the full design.

**Manual evidence is a project-level singleton.** One project = one repo =
one framework, so there is exactly one `manual.pdf` source per project and
one bucket per project for manual uploads — never per-framework. Path
scheme: `{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/{filename}`.
Customers pursuing multiple frameworks (SOC 2 + ISO 27001) typically use
multiple repos.

**Manual-evidence reader backends are symmetric with vault backends.**
Both axes ship the same four in-tree backends — `local`, `s3`, `gcs`,
`azure_blob` — registered through self-registering factories. The `s3`
manual reader supports on-prem S3-compatible stores (MinIO, Ceph, …)
via `endpoint` + `force_path_style`, mirroring the vault s3 backend.
Implementation note: the manual local reader lives inline in
`internal/sources/manual/factory.go` rather than in its own
subpackage; the three cloud backends live under
`internal/sources/manual/{s3,gcs,azureblob}/` and are blank-imported
through `internal/sources/manual/builtin`. This asymmetry is
file-layout-only — the registration mechanism is identical for all
four. Third parties add backends (SFTP, NFS, custom object stores)
the same way, from `.sigcomply/plugins/<id>/` compiled in by
`sigcomply build` (M16).

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
│       └── cloud/                     # SigComply Cloud client (POST /api/v1/runs)
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
| `sigcomply evidence catalog` | Wired | Print manual catalog (text or JSON); the SPA also consumes the JSON form at build time |
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
- Manual evidence is a project-level singleton: one bucket per project
  (not per-framework), configured once under `sources.manual.pdf`.
- Cloud submission is OIDC-only (no API keys) and auto-enables in CI.

---

## Cross-Repo Integration Points

When changing any of these in the CLI, check the corresponding place in
the Rails app at `../sigcomply/`:

| CLI side | Rails side | Contract |
|----------|------------|----------|
| Aggregator / Submitter (`SubmissionPayload`) | `Api::V1::RunsController` (`POST /api/v1/runs`, strong params) | Counts-only run payload |
| OIDC token helpers | Rails OIDC token validator | Token format, claim names (`repository`, `namespace_path`/`project_path`) |
| Manual evidence catalog | SPA `scripts/fetch-catalogs.ts` (in `../sigcomply-evidence-spa/`) | The SPA pre-builds catalogs via `sigcomply evidence catalog -o json` |

Older Rails CLI endpoints (`/api/v1/cli/policy_evaluations`,
`compliance_status`, `heartbeat`, `health`) are legacy. New work goes
through `POST /api/v1/runs`.

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
- SigComply Cloud client (`POST /api/v1/runs`)
- OIDC auth (GitHub Actions + GitLab CI)
- Policy filtering (`--policies`, `--controls`)
- Release automation (auto-release via conventional commits, manual release, GoReleaser)
- GitHub Actions reusable workflow
- GitLab CI: an example pipeline at `examples/gitlab-ci.yml` users can copy. (A first-class GitLab CI component is not yet packaged.)
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
  send resource identifiers. `internal/core/cloud.go` carries an
  explicit warning against adding a freeform metadata field. Respect it.
- **Don't put source IDs inside policy code.** Policies declare
  `slots.<name>.accepts: [...]`; they never name a plugin. A rule that
  branches on `record.SourceID` to behave differently per plugin is a
  code smell — it ties the policy to a specific source ID and breaks
  Invariant #4. Legitimate per-vendor branching uses `record.Type`,
  which the evidence-type registry guarantees.
- **Don't put policy IDs inside source plugins.** A plugin's `Collect`
  receives `SlotRequest.PolicyID` for diagnostics only; using it for
  behavior branching breaks Invariant #4. Plugins emit records of
  their declared types and stop there; what consumes them is not their
  concern.
- **The evidence-type registry is the sole coupling point.** If you
  ever feel the urge to add a "this policy only works with AWS" or
  "this plugin behaves differently for SOC 2" escape hatch, that's the
  signal an evidence-type contract is missing. Add the type (see
  [`docs/architecture/04a-evidence-type-registry.md`](./docs/architecture/04a-evidence-type-registry.md))
  or extend an existing slot's `accepts:` list — not the special case.
- **Design evidence-type schemas top-down from the semantic concept,
  never bottom-up from a vendor's API.** Every field in a cross-vendor
  schema must be satisfiable by all plausible implementations without
  null or a placeholder sentinel. The source plugin owns 100% of the
  vendor→canonical translation — policy Rego must never contain null
  guards (`if record.field != null`) or source-type branches
  (`record.type == "aws_iam_user"`). Both are symptoms of a schema
  designed wrong. If writing a second plugin for an existing evidence
  type requires setting a required field to null, fix the schema —
  not the plugin. The null-trap antipattern (null field → Rego null
  guard → implicit source dispatch → broken substitutability) is the
  most common way this architecture fails silently. Full design
  guidance: [`docs/architecture/04a-evidence-type-registry.md`
  §Schema design](./docs/architecture/04a-evidence-type-registry.md).
- **`evidence_mode: automated | manual` is an explicit first-class
  field on every policy spec — never infer it.** Do NOT detect
  evidence mode by checking whether any slot accepts `signed_document`
  (that is the old implicit pattern in `defaultOnPush` in
  `internal/spec/policy.go` — it is being replaced). Do NOT guess
  mode from slot types or absence of a `rule:` field. `evidence_mode`
  is declared explicitly in every `policy.yaml`. If it is missing,
  fail validation at load time (exit 3) — not silently defaulting to
  automated.
- **`pass_when:` is the primary evaluation path for automated
  policies — `rule:` is the escape hatch.** ~95% of compliance
  checks reduce to a quantifier (all/none/any/count) over a field
  condition on a single slot. That is exactly what `pass_when:`
  handles without writing a single line of Go or Rego. Never write a
  per-policy rule function or Rego rule when the logic fits
  `pass_when:`. Reach for `rule:` only for cross-slot joins, complex
  aggregations, or logic the DSL cannot express. Manual policies
  (`evidence_mode: manual`) never use `pass_when:` or `rule:` — the
  universal PDF presence check (Path A in the L5 evaluator) runs
  unconditionally for all of them.
- **Don't invent evidence sub-types in the evaluator.** The evaluator
  only knows `automated` and `manual` as the *flow* dimension.
  Catalog `type` values like `declaration`, `checklist`,
  `document_upload` are descriptive hints (used by the optional
  Evidence SPA helper to decide whether to render a clickable form) —
  the CLI ignores them.
- **Don't add PDF-content checks to `validatePDF`.** That function is
  stdlib-only, byte-level sanity (size, magic, `/Page` presence,
  prior-period hash equality). Anything that requires understanding
  PDF *contents* — text extraction, signature dictionaries, embedded
  date checks — belongs in a separate, opt-in code path and stays
  inside the customer process. Don't quietly grow `validatePDF` into a
  parser; it will mask its own failures and break the
  "evidence-without-access" promise the moment the parser pulls in a
  network-aware dep. See Invariant #2 §"What the CLI explicitly does
  NOT do."
- **Don't sign hashes.** Signing covers canonical JSON of
  `{timestamp, evidence}`. SHA-256 is used only to identify the manual
  PDF inside the manifest, not as the signing input.
- **Per-file keypair, never per-run.** A run can collect dozens of evidence
  files — each gets its own Ed25519 keypair, and the private key is
  discarded immediately. The per-run `manifest.json` is also signed (with
  its own ephemeral keypair) and covers `file_hashes` for the whole run —
  but each envelope is still independently verifiable on its own.
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
  `hipaa` is omitted from `--framework`'s public help text since there
  is no `hipaa/` package yet, but `SupportedFrameworks` in `config.go`
  still accepts it as a stub value.

---

## Resources

- Open Policy Agent: https://www.openpolicyagent.org/
- Rego language: https://www.openpolicyagent.org/docs/latest/policy-language/
- SOC 2: https://www.aicpa.org/soc
- ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
