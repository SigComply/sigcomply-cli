# SigComply CLI: agent instructions

Personal, machine-local instructions live in `AGENTS.local.md` (gitignored; may not exist). Read
it if it exists; it adds to and overrides this file. @AGENTS.local.md

This file points to the docs that own each topic and does not restate them (architecture:
`ARCHITECTURE.md`; configuration: `docs/configuration.md`).

## How work happens here

- Agents do the whole SDLC, from research to a pushed commit with green CI and release.
- The human sets intent, approves plans and owns the decisions listed under "When to ask the
  human" in the `task-workflow` skill.
- Pre-launch, internal work by maintainers commits and pushes straight to `main`, no PRs.
  Outside contributors open a pull request; `CONTRIBUTING.md` describes both flows. Local state
  (cadence state files) has no backward-compatibility burden; cross-repo contracts still change in
  lockstep (Invariant #1).
- This repo is public, and another human contributor also commits to `main`. Everything you
  commit is published.
- A push to `main` runs the tests and, unless every changed file is path-ignored (docs and agent
  files), cuts a versioned GitHub Release. The GitHub E2E repo picks it up on its next daily run;
  the GitLab E2E repo pins a version and needs a manual bump. Details in
  `docs/claude/development-workflow.md`.

## Every task

Run the `task-workflow` skill (`.claude/skills/task-workflow/SKILL.md`) for every change. This
repo's bindings (gate commands, test layers, real-product verification, what a push triggers,
doc routing) are in `docs/claude/development-workflow.md`. Review skills: `self-review`,
`adversarial-review`; lenses `review-security`, `review-testing`, `review-performance`; docs:
`writing-docs`. The `.claude/` skills and agents are shared byte-for-byte with the other four
SigComply repos (`.claude/README.md`); repo-specific rules go here or in the workflow doc, never
in them.

## Always-on rules

1. Verify by running, not by reasoning: run the gate, then build the binary and run the affected
   `sigcomply` command (stdout, exit code, vault output). Report failures and skipped steps
   plainly.
2. Tests first; never weaken, skip or delete a test to get green. When `TestDocFiguresMatchCode`
   fails, fix the doc it names.
3. Docs change with the code, agent-internal and customer-facing, in the same commit.
4. Make the smallest change that fixes the root cause; note unrelated problems instead of fixing
   them.
5. Never bypass hooks (`--no-verify`, `LEFTHOOK=0`), force-push, or rewrite pushed history.
6. No secrets, real customer data, personal emails, SSH host aliases or machine-specific paths in
   code, fixtures, cassettes, logs or docs. The repo is public; gitleaks and
   `make check-fixtures` catch only part of this.
7. Breaking a Sacred Invariant below is a stop-and-ask. So is a design that feels overly complex.
8. Fan out subagents for wide research and parallel review; keep the main context for decisions.
9. Comments explain why, not what.
10. Pick the commit type deliberately: it sets the release version bump (`feat` minor, any other
    type patch). `<type>!:` or the words "breaking change" anywhere in a subject, in any case, is
    major, so never write them in a subject unless you mean it.
11. Never write the release skip marker in a commit message unless you mean to skip the release.
    The release job matches it anywhere in the head commit's message, so quoting it while
    explaining it skips the release (this shipped `02d4d09` unreleased). In prose, write "the
    skip marker".
12. Touch one side of a cross-repo contract (cloud payload, manual catalog export, OIDC claims),
    check and update the other in the same task (see "Cross-Repo Integration Points").

## Commands

| Purpose | Command | Notes |
|---|---|---|
| Build | `make build` | Writes `bin/sigcomply` with version, commit and build time |
| Fast tests | `make test` | `go test -short -race -v ./...`; skips the heavy `sigcomply build` tests |
| Full tests | `make test-full` | `go test -race ./...`, what CI runs |
| Coverage | `make test-coverage` | Full suite plus report in `coverage/`; prints the total but does not enforce the floor |
| L2 contract tests | `make test-contract` | Cassette and fixture-vs-spec conformance |
| L4a live tests | `make test-live` | Calls real vendor APIs with your creds; run only when the task needs it |
| Lint | `make lint` | mise-pinned golangci-lint (`mise.toml`) |
| Format, vet | `make fmt`, `make fmt-check`, `make vet` | gofmt and `go vet` |
| Fixture scan | `make check-fixtures` | Secrets and PII in `testdata/` and `contracts/` |
| Security | `make security-deps`, `make security-code`, `make security-secrets` | govulncheck + nancy, gosec, gitleaks |
| Local CI | `make ci`, `make pre-commit` | `deps lint test build`; `fmt-check vet lint check-fixtures test-unit`. Neither enforces coverage |
| Workflow lint | `actionlint` | After editing `.github/workflows/*` |

Lefthook pre-commit: gofmt on staged Go files, `go vet`, `make lint`, `make test` (these four
only when Go files are staged), `go mod tidy` check (when `go.mod`/`go.sum` are staged), and
`gitleaks protect --staged`. Pre-push: `make lint`, `go test -short -race ./...`, `gitleaks
detect`. Only CI runs: the 80% coverage floor (`test.yml`), the cross-platform build matrix, the
`security.yml` scanners (govulncheck, gosec, CodeQL, Semgrep, Trivy, OSV, Scorecard, SBOM,
license check), weekly `contract-drift.yml` and nightly `live-saas.yml`.

## Docs map

Agent-internal (read when):

- `docs/claude/development-workflow.md`: at the start of every task.
- `ARCHITECTURE.md` and `docs/architecture/`: before changing the layer you touch.
- `docs/claude/recipes.md`: adding a source, policy, evidence type, framework or vault backend.
- `docs/claude/auth.md`: touching OIDC or cloud submission auth.
- `TESTING.md` and `docs/architecture/11-testing-strategy.md`: choosing a test layer.
- `SECURITY.md`: touching signing, the vault or the threat model.
- `CONTRIBUTING.md`, `.github/pull_request_template.md`: human-facing contribution rules.

Customer-facing (audience):

- `README.md`, `docs/quickstart.md`, `docs/getting-started.md`: new users.
- `docs/guides/*`: operators doing one task (install, sources, CI, manual evidence, verify).
- `docs/reference/*`, `docs/configuration.md`: operators looking up a flag, key or count.
- `docs/concepts.md`: evaluators and auditors learning the model.
- `docs/for-ai-agents.md`, `llms.txt`: AI agents setting up a customer repo.
- `CHANGELOG.md`, `examples/`: users upgrading or copying a CI setup.

---

## Product Overview

**SigComply** is a zero-trust, non-custodial compliance engine —
"Evidence without Access." An open-source Go CLI that runs in customer
CI/CD, evaluates Go-native policies against infrastructure, signs the
resulting evidence locally, and (optionally, paid tier) submits
aggregated counts to a private Rails dashboard. The product spans **4
logical components across 5 sibling repos** — full cross-repo
architecture in the [parent AGENTS.md](../AGENTS.md).

| Component | Local path | Repository |
|-----------|-----------|--------|
| **The Engine (CLI)** — this repo, Go | `./` | https://github.com/SigComply/sigcomply-cli |
| **Compliance Dashboard** — Rails 8.1 / Ruby 3.3 (private) | `../sigcomply/` | https://github.com/SigComply/sigcomply (private) |
| **Manual Evidence SPA** — React 19 + TS + Vite | `../sigcomply-evidence-spa/` | https://github.com/SigComply/sigcomply-evidence-spa |
| **CLI E2E (GitHub Actions)** | `../sigcomply-cli-testing-project-github/` | https://github.com/SigComply/sigcomply-cli-testing-project-github |
| **CLI E2E (GitLab CI)** | `../sigcomply-cli-testing-project-gitlab/` | https://gitlab.com/sigcomply/sigcomply-cli-testing-project-gitlab |

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
`accounts`) joined by the `matches_in` operator. The `accounts` slot
accepts `rosterSubjectTypes` (the `directory_user` family **plus**
`iam_binding`), not `directoryUserTypes`: the roster join is the one
identity question a cloud IAM grant can answer, while the MFA and
lifecycle policies that read `directory_user` cannot be asked of a
grant. Widen `rosterSubjectTypes`, never `directoryUserTypes`. As of the
security_alert reconception, **no shipped policy uses the `rule:` escape
hatch** — both SOC 2 and ISO 27001 are 100% `pass_when:` (each
framework's `Rules()` returns nil). The escape-hatch infrastructure
remains available (`internal/evaluator/rego_rule.go` inline Rego,
`go_rule.go` Go rules) for a future check the DSL genuinely cannot
express; OPA stays a dependency for it. To count a framework's policies,
count `.policy()` calls — not files.

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

**`{period_id}` is the entry's cadence window, not the run's period.**
`planner.CadencePeriod` maps daily→`2026-01-15`, weekly→`2026-W03`
(ISO), monthly→`2026-01`, quarterly→`2026-Q1`, annual→`2026`; a
`fiscal_year` calendar keeps `FY2026` for annual, and a `custom`
calendar (plus `continuous`/`hourly`/`every:<dur>`) keeps the run's
period. The planner stamps all four period fields onto the manual
binding (`Binding.Period`) and `collector.buildSlotRequest` applies them
together, so folder, temporal window and prior-period comparison can
never disagree. Selection uses the policy's **declared** cadence, not
the `policy_overrides`-resolved one — a scheduling override must not
relocate a customer's upload folder, and `evidence due` keys off the
catalog entry's cadence, which is the same value. Everything else —
vault run root, `manifest.json`, `summary.json`, the wire `period_id`,
`PolicyState.LastPeriodID` — is still the **run's** period.

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
7. **Prior-period duplication:** if planner supplied `prior_period_id`
   (the prior *cadence* period — last year for an annual entry),
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
  rollover, ever. The clock it is measured on is
  `planner.PeriodTime` — HEAD's commit timestamp by default, the run's
  start under `period.time_basis: wall_clock`. **One carve-out, and it
  touches no run artifact:** a manual entry's *upload folder* (and the
  temporal window checked against it, and the `period_id` inside its
  evidence record) is keyed by the entry's own cadence —
  `planner.CadencePeriod`. An annual attestation belongs in `…/2026/`,
  not in whichever quarter read it.

Per-policy decision rule (strictly layered — full design in
[`docs/architecture/10-cadence-model.md`](./docs/architecture/10-cadence-model.md)):
explicit operator filter → evaluate; PolicyStates nil → evaluate; prior
state nil → evaluate (first-run); content-hash changed → evaluate (the
hash covers `pass_when`, so editing a clause is enough); prior
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
— retained unchanged in the current `sigcomply.cloud.v5` schema (the
counts-only test still guards). (v3 itself swapped the per-policy scalar
`control_id` for a `controls []ControlRef` list — multi-framework
mapping; v4 then added the `evidence_mode` / `evidence_mode_overridden`
pair, without which the dashboard cannot tell a verified estate from a
folder of PDFs; see `docs/architecture/06-aggregation.md`.) State
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
  case. (Inv #4) **Error *classification* is not behavior dispatch.**
  `internal/sources/errors.go` is a shared `Retryable() bool` /
  `sources.APIError` contract so the collector can tell a 429 from a 403;
  it reads vendor error shapes via `errors.As` and changes only whether
  the backoff budget is spent, never what is collected or mapped. An
  unclassified error stays retryable, so adopting it is incremental.
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
- **Declared-but-never-matched roster keys are reported, not ignored.**
  An `experimental.roster.aliases` / `non_human` entry naming an account
  no source returned is a silent typo — a perfectly valid entry for an
  account that does not exist. `internal/evaluator/rosterusage.go`
  accumulates which keys actually matched, **run-scoped across every
  roster policy** (the `Aliases` map is shared by reference while each
  policy gets its own `evalCtx`, so a per-policy verdict would be wrong),
  and the orchestrator prints `unused-alias:` / `unused-non-human:` to
  **stdout** — not `logger.Warnf`, whose `Redact()` would rewrite an
  email-shaped alias key to `<redacted:email>`. The source-ID half of the
  same typo stays fatal at plan time (`checkRosterSourceKeys`).
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
  entry count is pinned into nine docs by `TestDocFiguresMatchCode`.
- **Run paths use basic ISO 8601 (no colons):** `20260325T100000Z`, not
  `2026-03-25T10:00:00Z` — some S3-compatible tools choke on colons.
- **Framework YAML key is singular:** `framework: soc2`, never
  `frameworks: [soc2]`.
- **HIPAA isn't a thing yet.** No HIPAA examples in docs, no HIPAA
  defaults in code paths — it's a stub string in `config.go` that fails
  at runtime.
- **`sources.Env` has two fields: `Config` and `FrameworkExtras`.** There
  is no `Vault` field — a plugin that needs storage configures its own
  backend the way `manual.pdf` does. One was declared and never read;
  don't reintroduce it.
- **A source factory must resolve its credentials, not just build a
  client.** `sources:` is the operator's declaration of what the project
  audits, so a listed source whose credentials are missing is a *config*
  error (exit 3, before collection), never a collection outcome. Neither
  cloud SDK fails on its own — `awsconfig.LoadDefaultConfig` builds a lazy
  chain and succeeds with nothing, and `azidentity.NewDefaultAzureCredential`
  never errors because failed sub-credentials are appended wrapped in an
  error reporter — so the eager step is explicit: `awscfg.Load` retrieves,
  `azcommon.NewCredential(ctx, scope)` mints one token. Both memoize (per
  `Options` / per scope), neither caches a failure, and both bound the
  resolve with a 60s timeout. A new backend that builds its own client owes
  the same check — `manual.pdf`'s `s3`/`azure_blob` readers and the
  `s3`/`azure_blob` **vault** backends each carry their own copy for exactly
  that reason (Go's internal-visibility rule puts `azcommon` out of reach
  for all four). The same rule covers the vault: a run that cannot write its
  evidence should say so before collecting, not after.
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
4. **`plugin/`** — the module's ONLY non-`internal` package: a thin façade
   of type aliases + three `Register*` forwarders that project-local Go
   extensions (which `sigcomply build` compiles inside the *customer's*
   module, where `internal/` is unreachable) import. Adding an export here
   is a compatibility promise for the whole major version, so add one only
   when a documented extension point needs it — and never widen an
   `internal/` API just to make a re-export easier. In-tree code keeps
   importing `internal/…` directly; `plugin/plugin_test.go` and
   `plugin/external_module_test.go` are the drift guards.

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
| `sigcomply evidence due` | Wired | List manual entries whose current-period folder is empty (`-c`, `-f`, `-o text\|json`, `--within-days`, `--all`). Each entry's period is its own cadence window, derived by the same `planner.CadencePeriod` call `check` makes. Read-only LIST calls; **always exits 0** when the scan completes, so it is safe as a non-failing CI step. Wired into the scaffolded daily workflow |
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
| Manual evidence catalog | SPA `scripts/fetch-catalogs.ts` | The SPA's deploy installs the released CLI and regenerates catalogs via `sigcomply evidence catalog --framework <fw> -o json` on every deploy (it used to run a bare `npx vite build`, which skipped the `prebuild` hook and served committed JSON forever). `ManualCatalogExport()` emits the SPA's `Catalog`/`CatalogEntry` contract verbatim. Changing entry fields or JSON tags means updating `sigcomply-evidence-spa/src/types/catalog.ts`. A catalog change now reaches the site on the SPA's next deploy, but only once this repo has cut the release the SPA resolves as `releases/latest`. |

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
