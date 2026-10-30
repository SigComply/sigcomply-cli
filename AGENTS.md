# SigComply CLI: agent instructions

Personal, machine-local instructions live in `AGENTS.local.md` (gitignored; may not exist). Read
it if it exists; it adds to and overrides this file. @AGENTS.local.md

Rules and pointers only. Each topic has one owner doc (docs map below); read it instead of
guessing, and fix it when it disagrees with the code. Code wins.

## The product in brief

The `sigcomply` CLI is a compliance engine and evidence collector that runs in the customer's CI.
Automated policies (`evidence_mode: automated`) evaluate API data from AWS, GCP, Azure, GitHub,
GitLab, Okta and Active Directory. Manual policies (`evidence_mode: manual`) only collect
uploaded documents: presence, format, upload window, merge, sign; content is never judged.
Evidence and results go to a vault the customer owns. With a paid SigComply Cloud plan, the CLI
also sends per-policy counts, never identities, to the private Rails dashboard (`../sigcomply/`).
Frameworks self-register via `internal/frameworks/builtin` (`frameworks.IDs()`). The workspace
overview `../AGENTS.md` exists only on maintainer machines; nothing here may depend on it.

## How work happens here

- Agents do the whole SDLC, from research to a pushed commit with green CI and release. The human
  sets intent, approves plans and owns the decisions listed under "When to ask the human" in the
  `task-workflow` skill.
- Maintainers push straight to `main` (pre-launch rules: `docs/claude/development-workflow.md`).
  Outside contributors open a pull request (`CONTRIBUTING.md`).
- The repo is public, and another human contributor also commits to `main`. Everything you commit
  is published.
- The code is source-available under the Elastic License 2.0 (`LICENSE`), not open source. Never
  call the CLI or its policies "open source" or "open"; "open core" names the business model
  only. `NOTICE` holds the copyright line and the Apache-2.0 cut-off (releases up to v0.90.2);
  keep `licenses/APACHE-2.0.txt`, which that cut-off refers to. A future
  license-key check is protected by ELv2's license key clause; keep it in this repo so that
  clause applies.
- A push to `main` runs the tests and cuts a GitHub Release unless every changed file is
  path-ignored. Nested READMEs, `llms.txt`, `examples/**` and `.github/` templates are not
  ignored. The release is published as a prerelease and promoted to latest, after the E2E release
  gate when the repository variable `RELEASE_GATE` is `on`. Release mechanics:
  `docs/claude/development-workflow.md`.

## Every task

Run the `task-workflow` skill (`.claude/skills/task-workflow/SKILL.md`) for every change. This
repo's bindings (gate, test layers, real-product verification, what a push triggers, doc routing)
are in `docs/claude/development-workflow.md`. Review skills: `self-review`, `adversarial-review`;
lenses `review-security`, `review-testing`, `review-performance`; docs: `writing-docs`. The
`.claude/` skills and agents are shared byte-for-byte with the other four SigComply repos
(`.claude/README.md`); repo-specific rules go here or in the workflow doc, never in them.

## Always-on rules

1. Verify by running, not by reasoning: run the gate, then `make build` and run the affected
   `./bin/sigcomply` command (stdout, exit code, vault output). Report failures and skipped steps.
2. Tests first. Never weaken, skip or delete a test to get green. When `TestDocFiguresMatchCode`
   fails, fix the doc it names.
3. Docs change with the code, agent-internal and customer-facing, in the same commit.
4. Make the smallest change that fixes the root cause; note unrelated problems instead of fixing
   them.
5. Never bypass hooks (`--no-verify`, `LEFTHOOK=0`), force-push, or rewrite pushed history.
6. No secrets, real customer data, personal emails, SSH host aliases or machine-specific paths in
   code, fixtures, cassettes, logs or docs. gitleaks and `make check-fixtures` catch only part.
7. Breaking a Sacred Invariant below is a stop-and-ask. So is a design that feels overly complex.
8. Fan out subagents for wide research and parallel review; keep the main context for decisions.
9. Comments explain why, not what.
10. Pick the commit type deliberately: `feat` is a minor release, any other type a patch.
    `<type>!:` or the words "breaking change" anywhere in a subject, in any case, is major.
11. Never write the release skip marker in a commit message unless you mean to skip the release.
    The job matches it anywhere in the head commit's message. In prose, write "the skip marker".
12. When you touch one side of a cross-repo contract (table at the end), check and update the
    other side in the same task.
13. Your machine may hold ambient AWS, GCP or Azure credentials. `make test` is hermetic, but
    `make test-live`, record drivers and `./bin/sigcomply check` with a cloud source use whatever
    they find. Run the CLI and tests inside the `env -i` wrapper in
    `docs/claude/development-workflow.md` "Cloud credentials when running tests".

## Commands

| Purpose | Command | Notes |
|---|---|---|
| Build | `make build` | Writes `bin/sigcomply` with version, commit and build time |
| Fast tests | `make test` | `go test -short -race -v ./...`; skips the heavy `sigcomply build` tests |
| Full tests | `make test-full` | `go test -race ./...`; CI adds coverage |
| Coverage | `make test-coverage` | Full suite plus `coverage/`; prints the total; only CI enforces the floor |
| L2 contract tests | `make test-contract` | Cassette conformance; fixture-vs-spec for GitHub and Okta |
| L4a live tests | `make test-live` | Real vendor APIs with your creds; only when the task needs it, inside the `env -i` wrapper (rule 13) |
| Lint | `make lint` | mise-pinned golangci-lint (`mise.toml`) |
| Format, vet | `make fmt`, `make fmt-check`, `make vet` | gofmt and `go vet` |
| Fixture scan | `make check-fixtures` | Secrets and PII in `testdata/` and `contracts/` |
| Security | `make security-deps`, `make security-code`, `make security-secrets` | govulncheck + nancy, gosec, gitleaks |
| Hooks | `make hooks-install` | `lefthook install` |
| Local bundles | `make pre-commit`, `make ci` | Neither equals CI: no full suite, no coverage floor |
| Workflow lint | `actionlint` | After editing `.github/workflows/*`; not pinned in `mise.toml` |

What lefthook runs and what only CI runs: `docs/claude/development-workflow.md` "Gate".

## Docs map

Agent-internal (read when):

- `docs/claude/development-workflow.md`: at the start of every task (gate, release, doc routing).
- `ARCHITECTURE.md` and `docs/architecture/`: before changing the layer you touch. Owners:
  `14-manual-evidence.md` (manual evidence, fan-out), `06-aggregation.md` (wire payload,
  submission decision), `10-cadence-model.md` (cadence, periods, state),
  `04a-evidence-type-registry.md` (evidence types, schema design).
- `docs/claude/recipes.md`: adding a source, policy, evidence type, framework or vault backend.
- `docs/claude/auth.md`: OIDC and cloud submission auth.
- `docs/architecture/11-testing-strategy.md`: choosing a test layer.
- `SECURITY.md`: signing, the vault, the threat model (owner).
- `CONTRIBUTING.md`, `.github/pull_request_template.md`: human contribution rules.

Customer-facing (owner of):

- `docs/reference/commands.md`: commands, flags, exit codes, framework resolution.
- `docs/configuration.md`: every `.sigcomply.yaml` key and env var.
- `docs/reference/sources.md`: per-source config, credentials and permissions.
- `docs/reference/frameworks.md`: framework IDs and published counts (test-pinned).
- `docs/guides/*`: one operator task each. `docs/concepts.md`: the model, for evaluators and
  auditors. `README.md`, `docs/quickstart.md`, `docs/getting-started.md`: new users.
  `docs/for-ai-agents.md`, `llms.txt`: AI agents. `CHANGELOG.md`, `examples/`: upgrades, CI.

## Sacred invariants

Code comments cite these by number. Keep the numbers.

### 1. The aggregation boundary

The CLI is the only place raw evidence (resource IDs, ARNs, usernames, emails, documents, file
hashes) is reduced to counts. Nothing that identifies a resource or person may reach a cloud API
request. The wire type `core.SubmissionPayload` (`internal/core/cloud.go`) has no
`map[string]any`, no `Violations` slice and no freeform field;
`TestSubmissionPayload_StructurallyCountsOnly` (`internal/core/cloud_test.go`) fails the build if
one is added. Field list and rationale: `docs/architecture/06-aggregation.md`. Evidence records,
violation lists, envelopes and `manifest.json` stay in the customer's vault.

### 2. Two evidence flows, and only two

Every policy declares `evidence_mode: automated | manual` explicitly; it is never inferred, and a
missing value fails validation at load. The evaluator branches on this field and nothing else. A
project may switch a policy's mode with `policies.<id>.evidence_mode` (plus `catalog_entry` when
switching to manual); every `PolicyResult` records the effective `EvidenceMode` and
`EvidenceModeOverridden`, and both go on the wire. There are no evidence sub-types in the
evaluator: catalog `type`, `items` and `declaration_text` are Evidence SPA hints. The manual
contract (folders, checks, fan-out, non-goals): `docs/architecture/14-manual-evidence.md`.

### 3. Per-file ephemeral signing and a signed run manifest

A fresh Ed25519 keypair per evidence file, never per run. The private key is discarded after
signing; the public key and signature live in the envelope. The signature covers canonical JSON of
`{format_version, produced_at, records}` (`internal/sign/envelope.go`), not a hash. Each run's
`manifest.json` lists `file_hashes` for the run's vault files and is signed with its own keypair.
This detects accidental drift; it does not stop someone with vault write access from re-signing.
Never claim tamper-resistance the design does not deliver. Threat model: `SECURITY.md`.

### 4. Source-agnostic policies via evidence-type contracts

Policies and source plugins never reference each other. Policies declare
`slots.<name>.accepts: [<type_id>]`; plugins declare `Emits()`; the evidence-type registry is the
only mediator (`evidencetypes.VerifyRegistrations` checks it at startup). A slot with no bound
source makes the policy `skip`, which drops it from the score denominator. The collector validates
every record against its JSON Schema (draft-07) before signing; a non-conforming record makes the
policy `error` (exit 2). Design: `docs/architecture/04a-evidence-type-registry.md`.

### 5. Cadence state is mutable; audit evidence is not

Cadence ("re-evaluate now?") is per policy. Its state shard,
`state/{framework}/policies/{policy_id}.json`, is mutable, never signed, never an audit
deliverable, and loss-tolerant (the next run is a first run). Writes use a monotonic guard.
Period ("which audit window?") is frozen per run by the planner from `planner.PeriodTime` (the
run's start time by default; HEAD's commit time under `period.time_basis: commit`). One carve-out: a manual entry's folder and window follow the entry's own
cadence (`planner.CadencePeriod`); every run artifact keeps the run's period. Design:
`docs/architecture/10-cadence-model.md`.

## Code smells to catch in review

- An identifier reaching `internal/core/cloud.go` types or the submitter. (Inv 1)
- Branching on `record.SourceID` in policy code, or on `SlotRequest.PolicyID` in a plugin.
  Per-vendor differences go in the evidence type; `internal/sources/errors.go` classifies errors
  for retry only. (Inv 4)
- An evidence-type schema shaped by one vendor's API, or a field a second source can only fill
  with null. Fix the schema; never add null guards in policies.
- A `rule:` where `pass_when:` fits. No shipped policy uses `rule:`; cross-slot joins use
  `matches_in`.
- A `pass_when` filter on a schema-optional field without an `is_set` guard inside `all_of`
  (`TestEveryFilterGuardsOptionalFields`). The evaluator never guesses: a missing field is `error`.
- A new policy per evidence type or per fan-out member. Widen the slot (`rosterSubjectTypes` for
  roster policies) or fan out folders instead; a policy that always skips downgrades coverage and
  the Statement of Applicability.
- Evidence sub-types in the evaluator, or `validatePDF` growing into a parser. (Inv 2)
- Signing a hash, or one keypair per run. (Inv 3)
- A manual catalog edited anywhere but the framework's `manualSpecs()`
  (`policies_manual.go`), or config-dependent data in the exported `manualcatalog.Entry`.
- Run paths in extended ISO 8601 (use `20260325T100000Z`, no colons), or `frameworks:` in config
  (the key is singular: `framework: soc2`).
- A `Vault` field on `sources.Env` (it has `Config` and `FrameworkExtras` only).
- A source factory that builds a client without resolving credentials. A listed source with
  missing credentials is a config error (exit 3) before collection: see `awscfg.Load`,
  `azcommon.NewCredential` and the vault and manual-reader backends.
- Roster alias or non-human keys that match nothing must be reported to stdout
  (`internal/evaluator/rosterusage.go`), not through `logger.Warnf`, which redacts emails.

## Code layout rules

Full package map: `ARCHITECTURE.md` and `docs/architecture/02-layers.md`.

- `internal/core/` (L1) holds stable interfaces and shared types. No framework- or
  source-specific logic.
- Frameworks (`internal/frameworks/<fw>/`), sources (`internal/sources/<vendor>/`), vault backends
  and manual readers self-register in `init()` and are blank-imported by their `builtin` package.
  No hardcoded switches.
- `plugin/` is the only non-`internal` package: aliases and `Register*` forwarders for
  project-local extensions built by `sigcomply build`. Each export is a compatibility promise for
  the major version; add one only for a documented extension point. Guards:
  `plugin/plugin_test.go`, `plugin/external_module_test.go`.

## Cross-repo contracts

| This repo | Other side | Guard |
|---|---|---|
| `core.SubmissionPayload` (schema `aggregator.SchemaVersion`): run metadata (`run_id`, `framework`, `period_id`, `commit_sha`, `commit_time`, `branch`, `cli_version`, `started_at`, `completed_at`), `repository{provider,name_slug,url}`, `environment{provider,workflow,run_url,worker_image}`, `summary` (`policies_*` per status, `compliance_score`), per-policy `policy_id`, `controls[]`, `status`, `severity`, `category`, `resources_evaluated`, `resources_failed`, `message`, `rule_version`, cadence scalars, `evidence_mode`, `evidence_mode_overridden`, `vacuous` | The dashboard's runs API (`POST /api/v1/runs`), which keeps only fields it allow-lists | `TestCloud_GoldenWireContract`; copy a regenerated golden to the dashboard repo (path in the test's `railsFixtureRelPath`) |
| OIDC: audience `submitter.DefaultAudience`, `X-OIDC-Provider` header; `X-SigComply-Project` header (`submitter.ProjectHeader`, from `cloud.project_id`) | The dashboard's OIDC validator (audience, issuer, claims `repository` / `project_path`, `namespace_path`; with the header, the project with that public ID must match the claims) | `docs/claude/auth.md`; `TestSubmit_SendsProjectHeader`, `TestBinaryE2E_Check_SendsProjectIDHeader` |
| `sigcomply evidence catalog -o json` (`internal/manualcatalog`) | SPA `src/types/catalog.ts`, `scripts/fetch-catalogs.ts` (runs the released CLI on deploy) | `cmd/sigcomply` export and binary E2E tests; golden `internal/manualcatalog/testdata/<framework>_golden.json`, copied to the SPA's `src/lib/__fixtures__/golden/` |
| `manual.FolderPrefix`, default prefix `manual/`; manual folder periods (`planner.CadencePeriod`) | SPA `src/lib/storage-path.ts`, `src/lib/period.ts`, `public/config.json` | `internal/sources/manual/paths_test.go`; golden `internal/planner/testdata/spa-golden/periods.json`, copied to the SPA's `src/lib/__fixtures__/golden/periods.json` |
| Envelope and manifest format (`internal/sign`) | SPA `/verify` page (`src/lib/verification/`) | `internal/sign` tests; golden vectors `internal/sign/testdata/spa-golden/`, copied to the SPA's `src/lib/verification/__fixtures__/golden/` |
| Release asset names, `checksums.txt`, command flags, exit codes | E2E repos `../sigcomply-cli-testing-project-{github,gitlab}` (the GitHub one runs `release-gate.yml` per release candidate) | `cmd/sigcomply/e2e_*_test.go`, `cmd/sigcomply/init_ci_contract_test.go`; the release gate |

Push order: the receiving side first. The dashboard silently drops fields it does not allow-list,
so it must accept a new field before the CLI sends it. Refresh the SPA copies of all three SPA
goldens with `npm run check:goldens -- --copy` in the SPA (`npm run check:goldens` alone reports
drift). `POST /api/v1/runs` is the only Rails endpoint the CLI calls.
