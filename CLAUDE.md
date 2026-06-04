# SigComply CLI — Claude Context

AI-coding context for the CLI repo: the invariants, decisions, and
conventions an agent needs to make safe changes. Architecture lives in
[ARCHITECTURE.md](./ARCHITECTURE.md); configuration in
[docs/configuration.md](./docs/configuration.md). **This file does not
restate them — it points to them.**

## Product Overview

**SigComply** is a zero-trust, non-custodial compliance engine —
"Evidence without Access." An open-source Go CLI that runs in customer
CI/CD, evaluates Go-native policies against infrastructure, signs the
resulting evidence locally, and (optionally, paid tier) submits
aggregated counts to a private Rails dashboard. The product spans **4
logical components across 5 sibling repos** — full cross-repo
architecture in the [parent CLAUDE.md](../CLAUDE.md).

| Component | Local path | Remote |
|-----------|-----------|--------|
| **The Engine (CLI)** — this repo, Go | `./` | `git@github.com:SigComply/sigcomply-cli.git` |
| **Compliance Dashboard** — Rails 8.1 / Ruby 3.3 (private) | `../sigcomply/` | `git@github.com:SigComply/sigcomply.git` |
| **Manual Evidence SPA** — React 19 + TS + Vite | `../sigcomply-evidence-spa/` | `git@github.com:SigComply/sigcomply-evidence-spa.git` |
| **CLI E2E (GitHub Actions)** | `../sigcomply-cli-testing-project-github/` | `git@github.com:SigComply/sigcomply-cli-testing-project-github.git` |
| **CLI E2E (GitLab CI)** | `../sigcomply-cli-testing-project-gitlab/` | `git@gitlab-personal:sigcomply/sigcomply-cli-testing-project-gitlab.git` |

**Frameworks shipped:** SOC 2 (production-ready) and ISO/IEC 27001:2022
(all 93 Annex A controls), both Go-native and self-registering via
`internal/frameworks/builtin`. HIPAA is a future goal — no package, no
policies; `config.go` lists `"hipaa"` in `SupportedFrameworks` but
selecting it fails (nothing registers under that name).

**Policies are Go, not Rego.** There are zero `.rego` policy files. Each
policy is an `autoPolicy{...}.policy()` builder under
`internal/frameworks/<fw>/policies_*.go` carrying a declarative
`pass_when:` clause (`all`/`allWhere`/`leaf`/`anyWhere`). As of the
security_alert reconception, **no shipped policy uses the `rule:` escape
hatch** — both SOC 2 and ISO 27001 are 100% `pass_when:` (each
framework's `Rules()` returns nil). The escape-hatch infrastructure
remains available (`internal/evaluator/rego_rule.go` inline Rego,
`go_rule.go` Go rules) for a future check the DSL genuinely cannot
express; OPA stays a dependency for it. To count a framework's policies,
count `.policy()` calls — not files.

---

## IMPORTANT: Check for Local Instructions

**Before starting any work, check if `CLAUDE.local.md` exists in the repo
root.** If present, read it first and follow it — it holds private
integration references and instructions that override or supplement this
public document. It is gitignored and absent in some environments.

---

## Documentation

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — system design, layer stack, types, storage, signing
- **[docs/configuration.md](./docs/configuration.md)** — config file, env vars, flags
- **[docs/architecture/](./docs/architecture/)** — deep design docs (layers, evidence-type registry, vault layout, aggregation, cadence, …)
- **[docs/claude/auth.md](./docs/claude/auth.md)** — OIDC authentication
- **[docs/claude/recipes.md](./docs/claude/recipes.md)** — step-by-step guides for common tasks
- **[README.md](./README.md)** — public-facing intro

---

## Development Rules

- **Ship working code.** Tested code is the measure of progress. Don't
  over-document — update docs only when architecture changes.
- **TDD.** Unit test first → happy-path integration test → minimum code
  to pass → `make test && make lint` green → docs only if architecture moved.
- **Architecture-first.** Read the relevant docs and plan before
  implementing. If the design feels overly complex, **stop and ask** —
  difficulty is a signal to pause, not push through.
- **Small atomic commits.** One logical change, all tests passing.
  Format `<type>: <description>` (`feat`/`fix`/`refactor`/`test`/`docs`/`chore`).
  Include `Co-Authored-By: Claude <model> <noreply@anthropic.com>`.
- **Never break main.** `make test && make lint` before every commit;
  after pushing, confirm CI is green (`gh run list` / `gh run view`).
  Don't move on while CI is red.

---

## Sacred Invariants

Non-negotiable. Violating any is a hard architectural break — stop and
ask before proceeding.

### 1. The aggregation boundary

The CLI is the **only** place raw evidence (resource IDs, ARNs,
usernames, emails, PDF bytes, file hashes) is reduced to counts. Any
change that would let an identifier reach a Cloud API request breaks the
non-custodial model.

- **To the Cloud API** (paid tier, `POST /api/v1/runs`, the
  `SubmissionPayload`): per-policy `policy_id`, `controls[]`
  (framework taxonomy, no identity), pass/fail,
  severity, `resources_evaluated`, `resources_failed`, `message`
  (count-based, no IDs), `category`, `remediation`; run summary
  (total/passed/failed/skipped, compliance score); environment (`ci`,
  `ci_provider`, `repository`, `branch`, `commit_sha`, `cli_version`).
- **Stays in customer storage, always:** raw API responses, PDF bytes,
  full violation lists with identifiers, ephemeral public key +
  signature, per-run `manifest.json`.

The submission type is **structurally** counts-only — no
`map[string]any`, no `Violations` slice — so the wire format physically
cannot carry identity. A reflection test in `core/cloud_test.go` fails
the build if a freeform field is added. Rails strong-params under
`Api::V1::RunsController` (`../sigcomply/`) are the second-layer
allow-list. Touch one side → check the other.

### 2. Two — and only two — evidence flows

Every policy declares `evidence_mode: automated | manual` as an
**explicit first-class field** — never inferred from slot types, accepted
evidence types, or presence of a `rule:`. The evaluator branches on this
field and nothing else. Missing → fail validation at load (exit 3); never
default silently.

- **Automated:** planner binds API source plugins to slots → collector
  calls `plugin.Collect()` → records validated against evidence-type
  schemas → evaluator runs the `pass_when:` DSL (primary) or `rule:`
  escape hatch.
- **Manual:** planner binds `manual.pdf` to an implicit slot, resolving
  the path via `catalog_entry` → collector fetches/validates the PDF →
  evaluator runs the universal PDF-presence check (`file_present`,
  `in_temporal_window`, `file_valid`). `pass_when:`/`rule:` are ignored.

Projects can override the framework's `evidence_mode` default per policy
via `policy_overrides` in `.sigcomply.yaml` (same policy ID; audit trail
records which path ran) — the migration path for customers on manual
processes today who wire up APIs later.

There are **no** `checklist`/`declaration`/`document_upload` sub-types in
the evaluator. Catalog `type`/`items`/`declaration_text` are descriptive
hints the optional Evidence SPA uses to render a clickable form; the CLI
ignores them. Externally-sourced PDFs (HR exports, scans, third-party
reports) flow through the same path.

#### Manual evidence contract (read before touching `internal/sources/manual/` or `internal/evaluator/manual_check.go`)

**What the CLI does (v1):** for the catalog-resolved folder
`{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/` —

1. **Folder-scan**; no files → fail with a structured "expected files in: <folder>".
2. **Classify by extension** (PDF, JPEG, PNG, GIF, TIFF, WebP, BMP).
   Unsupported (e.g. `.docx`) → `unsupported_file_type` in
   `validation_failures`; none supported → `file_valid=false`.
3. **Fetch, SHA-256 the original bytes, convert images to PDF** via
   `fileconv.ToPDF` (pure-Go); record a per-file audit entry in
   `source_files`.
4. **Merge** all PDF parts via `pdfmerge.Merge` (pdfcpu).
5. **Cheap sanity checks** (`validatePDF` in `manual.go`): min size,
   `%PDF-` magic prefix, ≥1 `/Page` object. Stdlib-only, no PDF parser.
6. **Temporal window:** latest upload timestamp must lie in
   `[period_start, period_end + grace]`.
7. **Prior-period duplication:** if planner supplied `prior_period_id`,
   compute a `sourceFingerprint` (SHA-256 of sorted `filename:sha256`);
   byte-identical to prior → `copy_paste_of_prior_period`. Missing prior
   folder is not a failure.
8. **Sign** the manifest with a fresh ephemeral keypair (Invariant #3).

**What it explicitly does NOT do** (all deliberate — content review is
the auditor's job): no PDF content audit / text extraction / signature
or expiry parsing; no semantic-correctness check (wrong-but-valid PDF
passes); no scope/completeness check; no fraud detection.

**Why v1 stops here:** the product is custody-of-evidence, not
content-validator. Richer inspection (text extraction, etc.) is exactly
what breaks "evidence without access" the moment it pulls in a
network-aware dep, and belongs in a separate opt-in path or a
`manual.pdf.v2` — **never** as shortcuts inside `validatePDF`. The
prior-period check fires for every manual entry; genuinely-static
evidence uses exception declarations in `.sigcomply.yaml`, not a catalog
flag (no `unique_per_period` field exists — add only when a real entry
needs it).

### 3. Per-file ephemeral signing + signed run manifest

A fresh Ed25519 keypair per **evidence file** (never per run); private
key discarded the instant the signature is computed; public key +
signature live in the file (`EvidenceEnvelope`). Signing covers canonical
JSON of `{timestamp, evidence}` — **not** a SHA-256 hash. The PDF is
SHA-256-hashed only so the manifest can reference it; the envelope still
signs the manifest.

Each run also writes a `manifest.json` of `file_hashes` for the whole run
(single-level Merkle), itself signed with its own ephemeral keypair — so
one signature covers run-wide integrity while per-file signatures stay
independently spot-checkable.

**Threat model.** *Detects:* accidental envelope corruption; a PDF
swapped while the envelope is left intact (manifest hash mismatch);
post-run manifest modification. *Does NOT detect (by design):* a customer
with vault write access regenerating envelope+PDF with a fresh keypair
(the public key lives inside the envelope — indistinguishable from
original fabrication); evidence fabricated at upload time and signed
legitimately (the CLI signs what it reads).

**Customer-side requirement for real tamper-resistance:** the vault
bucket must be write-once / version-controlled at the storage layer (S3
Object Lock or versioning + MFA delete; GCS Object Versioning + retention
or Bucket Lock; Azure immutable storage; local FS is dev/CI-ephemeral
only). The CLI does not configure this. Without it the scheme still
detects accidental drift but not deliberate re-signing — say so in
customer/auditor docs; never claim tamper-resistance the design doesn't
deliver.

### 4. Source-agnostic policies via evidence-type contracts

Policies and source plugins never reference each other. The evidence-type
registry is the **sole** mediator.

- Policies declare `slots.<name>.accepts: [<type_id>, ...]`. There is no
  `source:` field in a policy spec.
- Source plugins declare `Emits() []string`. They never know which
  policies consume them; `SlotRequest.PolicyID` is diagnostic-only.
- The planner matches by intersection (`Emits() ∩ Accepts ≠ ∅`); empty →
  plan-time error (exit 3).
- The collector validates every payload against the registered JSON
  Schema for `record.Type` before signing — full JSON Schema draft-07
  (gojsonschema): enum, format, pattern, minimum/maximum, and nested
  object/array constraints are all enforced, not just `required`. The
  first non-conforming record fails the binding and tags the policy
  `error` (exit 3); there is no partial-acceptance threshold (a ">5% of
  records" permissive mode is design intent only — see
  `docs/architecture/04a-evidence-type-registry.md`).

**Substitutability:** adding a new source for an existing type needs zero
policy changes; extending a slot's `accepts:` is one line of YAML.
Canonical example: "MFA enforced on admins" satisfied by AWS IAM / Okta /
Azure AD / internal LDAP — one spec, four bindings, zero forks. Full
design: [`docs/architecture/04a-evidence-type-registry.md`](./docs/architecture/04a-evidence-type-registry.md),
[`docs/architecture/01-conceptual-model.md`](./docs/architecture/01-conceptual-model.md) §Axiom 1.

### 5. Two-axis cadence: scheduling state is mutable, audit evidence is not

- **Cadence** — "re-evaluate now?" Per-policy scheduling. State in
  `state/{framework}/policies/{policy_id}.json`: mutable, NEVER signed,
  NEVER an audit deliverable, loss recoverable (next run = first-run).
- **Period** — "which audit window?" Per-run, frozen at run-start by the
  planner; every policy in a run shares one `period_id`. No mid-run
  rollover, ever.

Per-policy decision rule (strictly layered — full design in
[`docs/architecture/11-cadence-model.md`](./docs/architecture/11-cadence-model.md)):
explicit operator filter → evaluate; PolicyStates nil → evaluate; prior
state nil → evaluate (first-run); content-hash changed → evaluate; prior
terminal status ≠ pass → evaluate; `now - LastPassAt >= CadenceInterval`
→ evaluate; else carry-forward (pointer to the prior signed envelope, no
re-sign).

Worth knowing: cadence DSL is
`continuous|hourly|daily|weekly|monthly|quarterly|annual` OR
`every:<duration>` (5-min floor, no cron strings — `every:24h` drifts,
`daily` is wall-clock-anchored). Carry-forward inherits trust from the
original signature; the auditor verifies it at
`CarryForward.LastEnvelopeRef`. The cadence model added five
non-identifying per-policy scalars to the cloud payload in v2 —
`ConfiguredCadence`/`LastEvaluatedAt`/`NextDueAt`/`IsCarriedForward`/`PolicyContentHash`
— retained unchanged in the current `sigcomply.cloud.v3` schema (the
counts-only test still guards). (v3 itself swapped the per-policy scalar
`control_id` for a `controls []ControlRef` list — multi-framework
mapping; see `docs/architecture/06-aggregation.md`.) State
writes use a monotonic guard (accept iff newer `LastRunAt`, or equal-and-
greater `LastRunID`) so concurrent CI runs can't regress state.

---

## Conventions & Code Smells

Actionable do/don'ts. The *why* is in the invariants above — these are
the patterns to catch in review.

- **Never send identifiers to the Cloud client.** `internal/core/cloud.go`
  carries an explicit warning; respect it. (Inv #1)
- **No source IDs in policy code; no policy IDs in source plugins.**
  Branching on `record.SourceID`, or on `SlotRequest.PolicyID` for
  behavior, breaks substitutability. Legitimate per-vendor branching uses
  `record.Type`. The urge to add "this policy only works with AWS" /
  "this plugin behaves differently for SOC 2" means an evidence-type
  contract is missing — add the type or extend `accepts:`, not a special
  case. (Inv #4)
- **Design evidence-type schemas top-down from the semantic concept, not
  from a vendor API.** Every field must be satisfiable by all plausible
  sources without null/sentinel. The plugin owns 100% of
  vendor→canonical translation; policy logic must never contain null
  guards or source-type branches. If a second plugin forces a required
  field to null, fix the schema. (The null-trap → null-guard → implicit
  source dispatch is how this architecture fails silently. See
  [`04a-evidence-type-registry.md`](./docs/architecture/04a-evidence-type-registry.md) §Schema design.)
- **`pass_when:` is the primary path; `rule:` is the escape hatch.** ~95%
  of checks are a quantifier (all/none/any/count) over a field condition
  on one slot — that's `pass_when:`, no Go/Rego. Reach for `rule:` only
  for cross-slot joins, complex aggregations, or what the DSL can't
  express. Manual policies use neither.
- **Don't invent evidence sub-types in the evaluator.** Only `automated`
  and `manual` exist as flows; catalog `type` values are SPA hints. (Inv #2)
- **Don't grow `validatePDF` into a parser.** Stdlib-only byte-level
  sanity. Anything needing PDF *contents* goes in a separate opt-in path,
  inside the customer process. (Inv #2)
- **Don't sign hashes; per-file keypair, never per-run.** (Inv #3)
- **Manual catalogs are generated in Go from one list per framework.**
  Each framework's `manualSpecs()` (`policies_manual.go`) feeds both
  `ManualCatalog()` (runtime path resolution) and `ManualCatalogExport()`
  (SPA-facing, `internal/manualcatalog`) so policy and catalog metadata
  can't drift. No embedded `catalogs/*.yaml`, no
  `internal/core/manual/catalogs/`. The export shape must stay in lockstep
  with `sigcomply-evidence-spa/src/types/catalog.ts`.
- **Run paths use basic ISO 8601 (no colons):** `20260325T100000Z`, not
  `2026-03-25T10:00:00Z` — some S3-compatible tools choke on colons.
- **Framework YAML key is singular:** `framework: soc2`, never
  `frameworks: [soc2]`.
- **HIPAA isn't a thing yet.** No HIPAA examples in docs, no HIPAA
  defaults in code paths — it's a stub string in `config.go` that fails
  at runtime.
- **Editing `cmd/sigcomply/check.go` flag descriptions** requires
  matching updates in `docs/configuration.md` and the command table
  below. `hipaa` is omitted from `--framework`'s help text.

---

## Code Organization

Numbered layer stack **L0–L9**, one package each under `internal/`;
`internal/orchestrator` (L9) wires L3→L8 for `sigcomply check`. Full tree
and layer responsibilities: [ARCHITECTURE.md](./ARCHITECTURE.md) and
[`docs/architecture/02-layers.md`](./docs/architecture/02-layers.md). The
load-bearing rules:

1. **`internal/frameworks/<fw>/`** — each framework self-contained
   (`framework.go`, `controls.go`, `builders.go`, `policies_*.go` grouped
   by control family). Go-native `.policy()` builders, no `.rego` files.
   Self-registers via factory; `frameworks/builtin` blank-imports.
2. **`internal/sources/<vendor>/`** — separates "where we get data" from
   "what we check". Each declares `Emits()`; the planner binds by
   evidence-type intersection. `sources/builtin` blank-imports all. The
   manual reader's `local` backend is inline in `factory.go`; `s3`/`gcs`/
   `azureblob` are subpackages blank-imported via `manual/builtin` (a
   file-layout asymmetry only — registration is identical, and symmetric
   with the four vault backends).
3. **`internal/core/`** (L1) — frozen interfaces + shared types. Never put
   framework- or source-specific logic here.

**Manual evidence is a project-level singleton:** one repo = one
framework, so exactly one `manual.pdf` source and one bucket per project
(never per-framework). Multi-framework customers use multiple repos.

---

## CLI Interface

| Command | Status | Notes |
|---------|--------|-------|
| `sigcomply check` | Wired | Main entry — plan → collect → evaluate → aggregate → sign/store → submit |
| `sigcomply init-ci` | Wired | Scaffold CI workflow files calibrated to a framework's cadence distribution |
| `sigcomply build` | Wired | Compile a project-tailored binary with `.sigcomply/` Go extensions |
| `sigcomply report` | Wired | Read-only auditor snapshot of the vault |
| `sigcomply evidence catalog` | Wired | Print the manual-evidence catalog (`-o text\|json`); `-o json` matches the Evidence SPA contract. Standalone, no project config. `-f` defaults to `$SIGCOMPLY_FRAMEWORK` then `soc2` |
| `sigcomply version` | Wired | Print version + commit + build time |
| `sigcomply init` | Planned | Not yet in `root.go` |
| `sigcomply collect` / `evaluate` | Planned | Collect-only / offline-evaluate modes |
| `sigcomply evidence {init, path}` | Removed | Old period-scaffolding / upload-URI subcommands; only `catalog` returned |

Framework resolves from `SIGCOMPLY_FRAMEWORK` or `framework:` in config
(default `soc2`), or `-f/--framework` on `check`.

**Flags & config:** full flag list and `.sigcomply.yaml` schema in
[docs/configuration.md](./docs/configuration.md). Gotchas: there is **no**
`--quiet`/`--service`/`--collector`/`--fail-on-violation`/`--fail-severity`
flag — `fail_on_violation` and `fail_severity` are config-file-only under
`ci:`. **Output formatting for `check` is not configurable**: `check` has
no `--output`/`-o` flag and emits one fixed text summary (the
`renderAndExitCode` line). The `output.format` config key validates
`text`/`json`/`junit` but only `report` actually renders alternate formats
(json/csv). `sarif` is rejected by the validator — no formatter exists.

**Exit codes:** `0` passed · `1` violations · `2` execution error · `3`
configuration error.

**Auto-detection:** collectors from credentials (`AWS_*`, `GITHUB_TOKEN`,
GCP ADC); CI env from `GITHUB_ACTIONS`/`GITLAB_CI`/`CI`; Cloud submission
auto-enables when an OIDC token is present in CI.

---

## Configuration (quick rules)

Full reference: [docs/configuration.md](./docs/configuration.md).

- Framework key is **singular** (`framework: soc2`); no `frameworks:` field.
- Precedence: CLI flags > env (`SIGCOMPLY_*`) > config file > defaults.
- Storage backends: `local`, `s3`, `gcs`, `azure_blob`; `s3` supports
  on-prem S3-compatible stores via `endpoint` + `force_path_style`.
- Manual evidence is a project-level singleton — one bucket per project,
  configured once under `sources.manual.pdf`.
- Cloud submission is OIDC-only (no API keys), auto-enables in CI.

---

## Cross-Repo Integration Points

When changing these in the CLI, check the matching place in the Rails app
(`../sigcomply/`):

| CLI side | Rails / other side | Contract |
|----------|--------------------|----------|
| Aggregator / Submitter (`SubmissionPayload`) | `Api::V1::RunsController` (`POST /api/v1/runs`, strong params) | Counts-only run payload |
| OIDC token helpers | Rails OIDC token validator | Token format, claim names (`repository`, `namespace_path`/`project_path`) |
| Manual evidence catalog | SPA `scripts/fetch-catalogs.ts` | SPA pre-builds catalogs via `sigcomply evidence catalog --framework <fw> -o json`; `ManualCatalogExport()` emits the SPA's `Catalog`/`CatalogEntry` contract verbatim. Changing entry fields or JSON tags means updating `sigcomply-evidence-spa/src/types/catalog.ts`. |

Older Rails CLI endpoints (`/api/v1/cli/policy_evaluations`,
`compliance_status`, `heartbeat`, `health`) are legacy — new work goes
through `POST /api/v1/runs`.

---

## Not Yet Wired

(For "what's done", read the code — don't assume a feature exists because
it's plausible.)

- HIPAA framework (stub string in `config.go` only)
- `init`, `collect`, `evaluate`, `config` commands
- Secret scanner
- SARIF output formatter (config validates the format; no implementation)
- First-class GitLab CI component (only an example pipeline at
  `examples/gitlab-ci.yml` to copy)

---

## Resources

- Open Policy Agent: https://www.openpolicyagent.org/ · Rego: https://www.openpolicyagent.org/docs/latest/policy-language/
- SOC 2: https://www.aicpa.org/soc · ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
