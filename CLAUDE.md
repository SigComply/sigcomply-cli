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
(all 93 Annex A controls, 26 automated, plus the
16 clause 4-10 management-system requirements as manual annual document
uploads — `C.`-prefixed controls that carry
`core.ControlKindManagementSystem`, cannot be declared `not_applicable`,
and are counted apart from Annex A everywhere a coverage figure is
rendered), both Go-native and self-registering via
`internal/frameworks/builtin`. HIPAA is a future goal — no package, no
policies, and (contrary to older notes) **no `hipaa` string anywhere in
the Go code**: framework validation is purely dynamic via
`frameworks.Lookup` / `frameworks.IDs()`, so selecting `hipaa` fails
exactly like any other unregistered name (nothing registers under it).

**Policies are Go, not Rego.** There are zero `.rego` policy files. Each
policy is an `autoPolicy{...}.policy()` builder under
`internal/frameworks/<fw>/policies_*.go` carrying a declarative
`pass_when:` clause (`all`/`allWhere`/`leaf`/`anyWhere`); the four
identity-roster policies use `rosterPolicy{...}` — two slots (`roster`,
`accounts`) joined by the `matches_in` operator. As of the
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
- **[TESTING.md](./TESTING.md)** / **[docs/architecture/11-testing-strategy.md](./docs/architecture/11-testing-strategy.md)** — testing strategy: layered tests (L0–L4b), CLI-vs-E2E repo split, cassette/contract conventions
- **[docs/claude/development-workflow.md](./docs/claude/development-workflow.md)** — the end-to-end change loop: plan → tests-first → implement → verify (`make test && make lint` + exercise the built CLI) → update docs → commit to `main`. Read before starting any task.
- **[docs/claude/auth.md](./docs/claude/auth.md)** — OIDC authentication
- **[docs/guides/vendor-risk.md](./docs/guides/vendor-risk.md)** — the third-party register and fan-out catalog entries
- **[docs/claude/recipes.md](./docs/claude/recipes.md)** — step-by-step guides for common tasks (adding a source/policy/evidence type/framework/backend)
- **[README.md](./README.md)** — public-facing intro

---

## Development Rules

This SDLC is run almost entirely by **Claude Code agents** — coding,
tests, planning, verification, and debugging. The full step-by-step loop
(and how to manually verify a CLI with no web UI) is
**[docs/claude/development-workflow.md](./docs/claude/development-workflow.md)**;
the rules below are the summary.

- **Ship working code.** Tested code is the measure of progress.
- **TDD.** Unit test first → happy-path integration test → minimum code
  to pass → `make test && make lint` green → **build & exercise the CLI**
  (`make build`; run the affected `sigcomply` subcommand; check stdout +
  exit code + vault) → **update the docs your change touched** → commit.
- **Docs are part of "done".** Every change updates the focused doc it
  affects (a recipe, `configuration.md`, an `architecture/` doc, this
  file's command table) in the same commit — not "only when architecture
  moves". A purely-internal change with no behavioral surface is the
  justified exception, not the default.
- **Architecture-first.** Read the relevant docs and plan before
  implementing. If the design feels overly complex, **stop and ask** —
  difficulty is a signal to pause, not push through.
- **Small atomic commits.** One logical change, all tests passing.
  Format `<type>: <description>` (`feat`/`fix`/`refactor`/`test`/`docs`/`chore`).
  Include `Co-Authored-By: Claude <model> <noreply@anthropic.com>`.
- **Pre-launch: commit directly to `main`.** The product has no users yet.
  Once tests pass and you've verified, commit to `main` and push — no PRs,
  no reviews for internal work (this becomes a PR + review flow at public
  launch; `CONTRIBUTING.md` and the PR template already govern external
  contributions). No backward-compat/backfill burden for local state, but
  cross-repo contracts (Inv #1) still stay in lockstep.
- **A push to `main` auto-cuts a release.** `auto-release.yml` runs on every
  push, bumps the version from your commit's conventional-commit prefix
  (`feat`→minor, `fix`/`refactor`/`perf`→patch, `BREAKING CHANGE` in the
  body→major), tags, and runs GoReleaser to publish binaries to GitHub
  Releases. The commit *type* is therefore load-bearing, not cosmetic.
  Doc-only pushes (`*.md`, `docs/**`) are path-ignored and cut no release.
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
  (count-based, no IDs), `category`, `evidence_mode` (`automated`/`manual`)
  and `evidence_mode_overridden`; run summary
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
via `policy_overrides` in `.sigcomply.yaml` (same policy ID). The audit
trail records which path ran: every `PolicyResult` carries the effective
`EvidenceMode` plus `EvidenceModeOverridden`, persisted in `result.json`
and submitted on the wire, so a downgraded control is visible rather than
silent — the migration path for customers on manual
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

**Fan-out entries (one entry, N folders).** A catalog entry may declare
`fanOut` naming a set the project declares in config — today
`experimental.vendors`, the third-party register. The plugin then scans
`{prefix}{evidence_catalog_id}.{instance_id}/{period_id}/` once per
member and emits **one** record carrying every member's verdict plus
`instances_total`/`instances_satisfied`; the evaluator fails the policy
if any *required* member is unsatisfied and sets
`resources_evaluated`/`resources_failed` from the counts.

This is deliberately **not** a third evidence flow (Inv #2 still holds:
only `automated` and `manual` exist). It multiplies the *folder*, never
the policy — one policy ID, one binding, one envelope, one state shard.
Minting one policy per member would make the member slug a first-class
identity that state shards, project-config overrides, `evidence due` and
the framework-sourced policy list in `report --view coverage`/`soa` all
key off, and would put the member list on the wire via `policy_id`.
Members stay vault-side; the aggregation boundary sees two integers.
Resolution lives in `internal/vendorfanout`, never in a framework (the
static catalog cannot see project config, and must not — the SPA export
and the published coverage figures depend on it staying config-free).
An entry with no members behaves exactly like a single-folder entry.

A fan-out member may also declare `assurance_period_end`: the last day
its own assurance report covers. Compared arithmetically against the
period, it is the only thing that catches a stale report, since the
temporal window proves upload time only. **Declared, never parsed** —
do not grow this into document inspection (see below).

**What it explicitly does NOT do** (all deliberate — content review is
the auditor's job): no PDF content audit / text extraction / signature
or expiry parsing; no semantic-correctness check (wrong-but-valid PDF
passes); no check that the *contents* of a document cover the control's
full scope; no fraud detection.

(That last point is about document contents only. Estate-level
completeness — "was every source this project claims to cover actually
reached?" — is a separate, opt-in, run-level check; see
`internal/scope` and `experimental.scope` in
[docs/configuration.md](./docs/configuration.md). It never inspects a
PDF.)

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
[`docs/architecture/10-cadence-model.md`](./docs/architecture/10-cadence-model.md)):
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
  on one slot — that's `pass_when:`, no Go/Rego. Cross-slot key joins
  are `pass_when:` too (`matches_in` + `in_slot`, e.g. accounts vs the
  roster). Reach for `rule:` only for complex aggregations or what the
  DSL can't express. Manual policies use neither.
- **The evaluator never guesses.** A `pass_when` reference to a field the
  record does not carry is `status=error`, in a clause `filter` as much as
  in a `condition` — an undecidable filter leaves the clause's *scope*
  unknown, and dropping the record biases toward passing because
  `all`/`none` are true of the empty set. A filter reading a
  schema-optional field must be `is_set`-guarded inside an `all_of`;
  `TestEveryFilterGuardsOptionalFields` (`internal/manualcatalog/`) fails
  the build otherwise.
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
  with `sigcomply-evidence-spa/src/types/catalog.ts` — and must stay
  **config-independent**: fan-out members are resolved onto the *runtime*
  catalog in `internal/vendorfanout`, never onto the exported
  `manualcatalog.Entry`, whose field count is pinned by a test and whose
  entry count is pinned into five docs by `TestDocFiguresMatchCode`.
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
(The singleton is the *source and bucket*. A fan-out entry still uses
that one bucket — it multiplies folders inside it, not sources.)

---

## CLI Interface

| Command | Status | Notes |
|---------|--------|-------|
| `sigcomply check` | Wired | Main entry — plan → collect → evaluate → aggregate → sign/store → submit. Summary breaks passes down by what earned them (inspection vs document presence) |
| `sigcomply init` | Wired | Scaffold a starter `.sigcomply.yaml` (`-f` framework, `-o` out path, `--force`); refuses to overwrite without `--force` |
| `sigcomply init-ci` | Wired | Scaffold CI workflow files calibrated to a framework's cadence distribution (SOC 2 only in v1-alpha; other frameworks exit 3) |
| `sigcomply build` | Wired | Compile a project-tailored binary with `.sigcomply/` Go extensions |
| `sigcomply report` | Wired | Read-only auditor snapshot of the vault (`--view latest\|exceptions\|integrity\|scope\|coverage\|soa`). `--view soa` renders the ISO 27001 Statement of Applicability and is the one view that requires the project config — the applicability decisions live only there, so it exits 3 rather than reporting every control as applicable |
| `sigcomply evidence catalog` | Wired | Print the manual-evidence catalog (`-o text\|json`); `-o json` matches the Evidence SPA contract. Standalone, no project config. `-f` defaults to `$SIGCOMPLY_FRAMEWORK` then `soc2` |
| `sigcomply evidence due` | Wired | List manual entries whose current-period folder is empty (`-c`, `-f`, `-o text\|json`, `--within-days`, `--all`). Read-only LIST calls; **always exits 0** when the scan completes, so it is safe as a non-failing CI step. Wired into the scaffolded daily workflow |
| `sigcomply version` | Wired | Print version + commit + build time |
| `sigcomply collect` / `evaluate` | Planned | Collect-only / offline-evaluate modes |
| `sigcomply evidence {init, path}` | Removed | Old period-scaffolding / upload-URI subcommands; only `catalog` returned |

Framework resolution differs by command: `init` and `evidence catalog`
resolve `-f/--framework` → `SIGCOMPLY_FRAMEWORK` → `soc2` default;
`evidence due` inserts the config's `framework:` between the flag and the
env var (it already loads the config). **`check`
reads `framework:` from the loaded config only** — it has no `--framework`
flag and ignores `SIGCOMPLY_FRAMEWORK`; a missing `framework:` is a config
error (exit 3), not a `soc2` default.

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

- HIPAA framework (no package, no policies, no `hipaa` string in code — any unregistered framework name fails identically)
- `collect`, `evaluate`, `config` commands (`init` is now wired)
- Secret scanner
- SARIF output formatter (config validates the format; no implementation)
- First-class GitLab CI *component* (the `include: component` catalog
  feature). `init-ci --ci gitlab` does scaffold a standalone `.gitlab-ci.yml`
  (from `cmd/sigcomply/templates/gitlab/.gitlab-ci.yml`), and
  `examples/gitlab-ci.yml` is copyable — but no reusable component/catalog
  entry is published

---

## Resources

- Open Policy Agent: https://www.openpolicyagent.org/ · Rego: https://www.openpolicyagent.org/docs/latest/policy-language/
- SOC 2: https://www.aicpa.org/soc · ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
