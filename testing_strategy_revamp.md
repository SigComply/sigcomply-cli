# Testing Strategy Revamp

> **Status:** **COMPLETE** — all work units in the §15 dashboard are `[x]`. L0–L3 (unit, integration, cassette conformance, spec-diff drift) plus the scheduled `contract-drift` and `live-saas` workflows are implemented across all providers; `contracts/` holds ~47 snapshots (aws/azure/gcp/github/okta); the E2E repos have `expected-outcomes.yaml` + assertions + sweepers. **Known scope limit (by design):** L4a *live* coverage exists only for GitHub/GitLab/Okta/Entra; **AWS, GCP, and Azure-ARM are cassette-only** (no live layer). GCP live recording is now unblocked via SA impersonation (keys still org-blocked) but real cassettes remain hand-authored until a maintainer records against seeded fixtures — see `docs/architecture/11-testing-strategy.md` §3.
> **Scope:** `sigcomply-cli/`, `sigcomply-cli-testing-project-github/`, `sigcomply-cli-testing-project-gitlab/`
> **Owner:** @jayakrishnan
> **Execution model:** Multiple Claude Code sessions. This document is the source of truth and the progress tracker.

---

## 0. How to use this document (session protocol)

This plan is executed across many sessions. Each session MUST:

1. **Read this whole file first.** It is the single source of truth for what's done and what's next.
2. **Find the next actionable work unit** in the [Tracking Dashboard](#12-tracking-dashboard) — the first `[ ]` whose dependencies are all `[x]`.
3. **Do exactly one work unit** (occasionally a tightly-coupled pair). Each WU is sized to be **one small atomic commit with all tests passing** — per the repo rule "Small Atomic Commits / Never Break Main." **Commit directly on `main` and push** (the app is not yet live; no feature branches / PRs for these WUs).
4. **Follow TDD** — write the test first, implement to pass (repo Development Rule #1).
5. **Update both** the WU's inline checklist and the Tracking Dashboard row to `[x]`, and append a one-line note under the WU ("Done <date>: <commit/PR>").
6. **Verify CI is green** for the touched repo before marking done.
7. **Do not skip the docs portion of a WU.** Docs are first-class deliverables here (requirement from the brief).

### Per-work-unit execution discipline (how each session does its one WU)

To keep quality high **without context overload**, every WU session follows this loop:

1. **Orient with a targeted read.** Read the Tracking Dashboard to pick the next unblocked WU, then read *only* that WU's section + the conventions/specs it points to (§4, §5). Do not read unrelated WUs.
2. **Plan the WU before editing.** Write a short execution plan (files to touch, approach, acceptance criteria). For non-trivial WUs use the Plan agent / plan mode.
3. **Fan out subagents for exploration & research.** Delegate codebase pattern-study (Explore agent) and any external tooling/library research (general-purpose + web) to subagents, running independent ones **in parallel**. Subagents return distilled conclusions; raw file contents and search dumps stay out of the main thread. Scale the count to the WU — a harness or cassette WU may warrant 2–3 (existing-test pattern study + library/API research); a docs-only or workflow-yaml WU may need none.
4. **Implement from the distilled findings** in the main thread, TDD (test first).
5. **Verify & close.** Tests + lint green, CI green, update the WU checkbox + dashboard row with a done-note, and make one atomic commit **directly on `main`, then push**.

**Guardrail:** if the main-thread context starts filling with file contents or tool output, stop and delegate to a subagent instead.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked (note why)

**Golden rule for the whole revamp:** never let a test give *false confidence*. A green per-PR suite must be backed by a drift detector that is *allowed to fail loudly* when an upstream API changes. See §2.

---

## 1. Problem statement

We are integrating many evidence-source APIs (GitHub, GitLab, AWS, GCP, Azure, Okta, and later HR tools). Two requirements pull against each other:

- **Robustness:** when a vendor API changes shape or behavior, *a test must fail* and tell us the app is broken.
- **Cost:** we cannot afford to spin up paid cloud resources on every CI run.

The naïve plan — "E2E repos provision real cloud resources and assert" — is correct *as one layer* but is the most expensive tool in the box, and on its own it is both costly and slow. It also misses the cheapest robustness mechanism available (spec-diffing, §2 / Layer L3).

This revamp installs a **layered strategy** with a clear **repo split** so that the per-PR path is fast/free/deterministic and the "did the vendor change?" question is answered by a separate, mostly-free, scheduled path.

---

## 2. The strategy in one model

Every test is either a **regression test** (your code vs. a *frozen* contract — fast, free, but blind to API changes) or a **drift detector** (the contract vs. *reality* — the only thing that catches API changes). Build both, and never confuse them.

| Layer | What it checks | Catches an API change? | Cost | Cadence | **Repo** |
|------|----------------|------------------------|------|---------|----------|
| **L0 — Invariants** | structural/privacy guarantees (e.g. no freeform field on the wire type) | n/a (guards *us*) | $0 | per-PR | **CLI** |
| **L1 — Mapping unit** | fake API response → mapped `EvidenceRecord`; every schema field populated; deterministic | No (by design) | $0 | per-PR | **CLI** |
| **L2 — Contract/fixture** | recorded cassette replayed **through the real SDK deserializer**; cassette validated against the **vendor's published spec** | Partially (when re-recorded / when spec snapshot updated) | $0 | per-PR | **CLI** |
| **L3 — Spec-diff drift** | diff the vendor's own machine-readable API model on a schedule | **Yes — shape/contract changes**, for $0 | $0 | scheduled (weekly) | **CLI** |
| **L4a — SaaS/Entra live** | real calls to **free** accounts (GitHub/GitLab/Okta/Entra) | **Yes — incl. behavioral** | ~$0 | scheduled (nightly) | **CLI** (`//go:build live`) |
| **L4b — Cloud + pipeline E2E** | provision minimal real cloud infra, run the released binary end-to-end, **assert expected per-policy outcomes** | **Yes — incl. behavioral + integration** | bounded (~$1–5/run) | scheduled / manual | **E2E repos** |

Key insight that makes L3 the centerpiece: AWS (Smithy models), Azure (`azure-rest-api-specs` OpenAPI), GCP (Discovery Documents), GitHub (`github/rest-api-description`), and Okta (OpenAPI) all publish the machine-readable model their own SDK is generated from. Diffing it on a schedule catches contract changes with **zero accounts and zero live calls**. GitLab's spec is thin → for GitLab we lean on L4a cassette-re-record diffs instead.

---

## 3. Repo assignment — which tests go where, and why

**`sigcomply-cli/` owns L0, L1, L2, L3, L4a.** Rationale: these are Go tests (or scheduled Go tooling) that live next to the plugin code, need no infrastructure provisioning, and gate every CLI change. L4a (SaaS/Entra) lives here because those vendors are *free* and need only a token — no Terraform, no teardown.

**The E2E repos own L4b only.** Rationale: L4b needs real provisioned cloud infrastructure (apply → read → assert → destroy), credential/OIDC plumbing per CI platform, and a sweeper to garbage-collect leaks. That machinery already lives in the E2E repos (`scripts/*-aws*.sh`, OIDC setup). L4b validates the **released binary end-to-end**, which is a different purpose than CLI unit/contract tests.

```
                      ┌─────────────────────────── sigcomply-cli/ ───────────────────────────┐
   per-PR  ──────────▶│ L0 invariants · L1 mapping · L2 cassette+spec-conformance             │
   scheduled (weekly) │ L3 spec-diff drift  → alert-only (opens issue)                        │
   scheduled (nightly)│ L4a SaaS/Entra live (free accounts, //go:build live) + cassette re-rec│
                      └───────────────────────────────────────────────────────────────────────┘
                                                   │ releases binary
                                                   ▼
                      ┌──────── E2E repos (github / gitlab) ────────┐
   scheduled / manual │ L4b provision minimal cloud → run binary →  │
                      │     ASSERT expected outcomes → destroy →    │
                      │     sweep leaks                             │
                      └─────────────────────────────────────────────┘
```

**Boundary rules:**
- Cloud per-plugin *contract* verification (AWS/GCP/Azure) is done via **L2 cassettes** in the CLI repo; the cassettes are **recorded** during L4b runs (or a one-off maintainer record) so the two layers share fixtures.
- The CLI repo never provisions cloud resources in CI. The E2E repos never contain Go unit tests of mappers.

---

## 4. Cross-cutting conventions (decide once, in Phase 0)

These are established in **WU-0.1/0.2** and then obeyed everywhere.

1. **Cassette location:** `internal/sources/<provider>/<service>/testdata/cassettes/*.yaml` (go-vcr v4). One cassette per scenario (e.g. `list_buckets_encrypted.yaml`, `list_buckets_unencrypted.yaml`).
2. **Vendor spec snapshots ("contracts"):** `contracts/<provider>/<service>@<api-version>.json`. Serves **both** L2 (validate cassettes against spec) and L3 (diff over time). Pin only the services we use.
3. **Redaction (mandatory — privacy invariant):** go-vcr `BeforeSaveHook` scrubs `Authorization`, tokens, ARNs, account IDs, emails, usernames to stable placeholders. A CI gate (WU-0.3) greps `testdata/` + `contracts/` for `AKIA`, 12-digit account IDs, `@`-emails, bearer tokens and fails the build on a hit.
4. **Build tags:** live tests are `//go:build live` and additionally skip if required env (token) is absent (`TF_ACC`-style). They are excluded from the per-PR suite and from the 80% coverage gate.
5. **Coverage:** keep the existing **80% floor** (`test.yml`). L2 cassette replay *raises* coverage (real deserialize paths run). Live/build-tagged code is excluded from the gate.
6. **Shared harness:** all source-plugin tests run through `internal/sources/sourcetest/` (built in WU-1.1) — schema conformance + completeness + determinism + metadata checks. Adding a plugin must not require re-inventing test scaffolding.
7. **Naming for live/E2E resources:** fixed prefix `sigcomply-e2e-` so sweepers can find and delete leaks safely.
8. **Drift jobs are alert-only:** they open/update a GitHub issue; they do not block PRs (they run on a schedule, not on PRs).

---

## 5. Tooling reference

| Concern | Tool | Notes |
|--------|------|-------|
| HTTP record/replay | `dnaeon/go-vcr` v4 | transport seam; add to `go.mod` in WU-1.2 |
| AWS test seam | fake `HTTPClient` via `config.WithHTTPClient` (runs real deserializer); interface stubs for pure-logic | per-protocol matcher needed for query/json APIs (IAM/EC2/STS) |
| GCP test seam | `option.WithHTTPClient` + `option.WithoutAuthentication` → httptest / go-vcr | REST/JSON clients |
| Azure test seam | `arm.ClientOptions{Transport: ...}` | swap transport; fake `azcore.TokenCredential` |
| Spec-diff (OpenAPI) | `oasdiff` | GitHub, GitLab(partial), Okta, Azure |
| Spec-diff (AWS) | `smithy diff` / track `botocore` `.changes` | models in `aws/aws-sdk-go-v2` `codegen/sdk-codegen/aws-models/` |
| Spec-diff (GCP) | snapshot Discovery Doc + JSON/`oasdiff` (via converter) | `https://<api>.googleapis.com/$discovery/rest?version=<v>` |
| Sweeper | `gruntwork-io/cloud-nuke` or `ekristen/aws-nuke` | name-prefix scoped; dedicated test account |
| Free identity tenant | Microsoft 365 Developer Program | Entra ID P2 + seeded users (for L4a Entra) |
| Schema validation in tests | existing `internal/evidence_types` (`gojsonschema`) | reuse `Validate()` |

Sources for the research behind this plan are linked in the conversation that produced it; key entry points: `github.com/dnaeon/go-vcr`, `github.com/oasdiff/oasdiff`, `github.com/smithy-lang/smithy`, `github.com/Azure/azure-rest-api-specs`, `github.com/github/rest-api-description`, `developer.microsoft.com/microsoft-365/dev-program`.

---

## 6. Current-state baseline (what exists today)

**CLI repo** — `github.com/sigcomply/sigcomply-cli`, Go 1.25.8:
- ✅ L1-ish: per-operation `fakeAPI` stubs + field assertions in each `internal/sources/<p>/<s>/*_test.go`.
- ✅ L0: `internal/core/cloud_test.go` reflection test (no freeform field on wire type).
- ✅ Schema enforcement at the **collector** layer (`internal/collector/collector_validation_test.go`, `internal/evidence_types/schema_enforcement_test.go`); helpers `stubSource`/`memVault` in `internal/collector/collector_test.go`.
- ✅ Scheduled workflow precedent: `.github/workflows/security.yml` cron `0 0 * * 1` (mirror this for L3).
- ✅ Makefile: `test-unit` (`-short -race`), `test-full` (`-race`), `test-coverage` (80% floor), `e2e-setup`/`e2e-teardown` → `scripts/e2e/{setup,teardown}-aws.sh`, `lint` (golangci-lint v2.8.0), `ci`, `pre-commit`.
- ✅ Docs: `ARCHITECTURE.md`, `CLAUDE.md`, `docs/architecture/00-10*.md` (notably `04-source-plugins.md`, `04a-evidence-type-registry.md`, `07-extensibility.md`), `docs/configuration.md`.
- ❌ Gaps: **no cassettes/`testdata` for sources**, no go-vcr, no `//go:build integration|live`, **no spec snapshots**, no drift detection, no per-plugin conformance harness, **no `TESTING.md`/`CONTRIBUTING.md`**.

**E2E GitHub repo** — ACTIVE:
- ✅ `.github/workflows/soc2-compliance.yml` (push/PR/dispatch, OIDC, `setup-aws-cheap.sh`, `sigcomply check --no-cloud`, teardown `if: always()`), `.sigcomply.yaml`, `scripts/{setup,teardown}-aws{,-cheap}.sh`, `docs/{AWS_OIDC_SETUP,MANUAL_EVIDENCE}.md`, `tests/fixtures/`.
- ❌ Gaps: **runs the pipeline but never asserts expected per-policy outcomes** (just logs); no sweeper; runs on push (not cost-scheduled); no GCP/Azure variants.

**E2E GitLab repo** — SKELETON: only `CLAUDE.md`, `CLAUDE.local.md`, `README.md`. No `.gitlab-ci.yml`, no config, no scripts. Greenfield.

---

## 7. Phase 0 — Foundations (CLI repo)

Goal: write the canonical strategy doc + conventions, and install the safety gates everything else relies on.

### WU-0.1 — Author the canonical testing-strategy doc
- Repo: **CLI**
- [x] Create `docs/architecture/11-testing-strategy.md` (fits the numbered series) containing §2 layer model + §3 repo split + §4 conventions, adapted as in-repo guidance.
- [x] Create root `TESTING.md` that links to it and to the E2E repos.
- [x] Add a "Testing" pointer to `ARCHITECTURE.md` "Document map" and to `CLAUDE.md` "Documentation".
- Acceptance: docs render; cross-links valid. Docs-only, no code.
- Done 2026-06-18: CLI repo commit on `main`. Added `docs/architecture/11-testing-strategy.md` (layers L0–L4b, repo split, conventions, tooling), root `TESTING.md` (repo-split summary + E2E repo links + make targets), and pointers in `ARCHITECTURE.md` Document map + `CLAUDE.md` Documentation. All cross-links verified.

### WU-0.2 — Ratify conventions (testdata / cassettes / contracts / build tags)
- Repo: **CLI**
- [x] Document the §4 conventions concretely in `11-testing-strategy.md` (paths, naming, redaction policy, `//go:build live`, coverage exclusions).
- [x] Add empty `contracts/README.md` and `internal/sources/sourcetest/README.md` describing intended use.
- Acceptance: a contributor can read these and know exactly where a new cassette/snapshot/test goes.
- Done 2026-06-18: CLI repo commit on `main`. Made §4 concrete — cassette paths now distinguish multi-service (`<provider>/<service>/testdata/cassettes/`) from flat single-service providers (`github`/`gitlab`/`okta`/`manual`); added a redaction placeholder table + the exact WU-0.3 grep gate; documented the exact coverage mechanism (`test.yml` `COVERAGE_THRESHOLD: 80`, live-tagged files excluded by not being compiled in the default build); added a full worked directory-layout example. Created `contracts/README.md` (path scheme, per-provider spec sources, L2+L3 roles, refresh scripts) and `internal/sources/sourcetest/README.md` (RunConformance contract, cassette wiring, live gating). All cross-links verified; `go build ./...` clean (new dirs are README-only, not Go packages).

### WU-0.3 — Secret/PII grep gate over test fixtures
- Repo: **CLI**
- [x] Add `scripts/check-fixtures.sh` (or a Go test `internal/sources/sourcetest/fixture_hygiene_test.go`) that fails on ARNs, 12-digit account IDs, emails, bearer tokens, `AKIA…` in `testdata/`/`contracts/`.
- [x] Wire it into `test.yml` (and `make pre-commit`).
- Acceptance: a deliberately-planted secret in a temp fixture fails the check; clean tree passes.
- Deps: WU-0.2.
- Done 2026-06-18: CLI repo commit on `main`. Added `scripts/check-fixtures.sh` (portable POSIX-ERE grep gate over every `testdata/` dir + `contracts/`: catches `AKIA[0-9A-Z]{16}`, bare 12-digit account IDs, ARNs with a non-zero account, non-`example.{com,org,net}` emails, bearer tokens; token-level allowlisting of the §4 placeholders; skips `*.md` docs so the contracts `service@version.json` path scheme in READMEs doesn't false-positive). Wired as a fail-fast first step in `test.yml`'s unit-tests job + new `make check-fixtures` target folded into `make pre-commit`. TDD: `internal/fixturehygiene/` (doc.go + `check_fixtures_test.go`) drives the script over synthetic temp fixtures so `go test ./...` proves planted-secret-fails / placeholders+clean-pass. Also migrated 4 pre-existing `@acme.com` emails in `internal/spec/testdata/project_config/{valid_acmecorp,invalid_exception_no_reason}.yaml` to the reserved `example.com` so the real tree is clean. `make check-fixtures`, `go build/vet ./...`, `golangci-lint`, `shellcheck`, and `go test ./internal/{fixturehygiene,spec}` all green.
- Hardened 2026-06-28: the account-ID scan extracted *any* 12 consecutive digits, so a 64-hex sha256 hash / hex commit SHA with an embedded digit run false-positived (the `cloud_v3_golden.json` wire-contract golden had kept `main` red since it landed 2026-06-22). Fix: require the 12-digit run to stand alone (delimited by a non-alphanumeric or line edge); added a regression test for hashes with embedded digit runs. CLI commit on `main`.

---

## 8. Phase 1 — Per-PR backbone pilot on ONE plugin (CLI repo)

Goal: prove the L1+L2 pattern end-to-end on the **GitHub plugin** (plain HTTP = simplest seam, free account for recording), producing a template the rest copy. *Start here — this is the backbone everything hangs off.*

### WU-1.1 — Shared conformance harness `internal/sources/sourcetest/`
- Repo: **CLI**
- [x] TDD a `RunConformance(t, plugin, opts)` that, given a plugin + a way to feed canned responses, asserts: every emitted record validates against its evidence-type JSON Schema (reuse `internal/evidence_types`); **completeness** (no schema-defined field left zero/empty — CloudQuery-style); **determinism** (two runs → identical, ID-sorted output); metadata (`Type`, `SourceID`, `CollectedAt` set).
- [x] Drive the tests with an in-package fake plugin (no network).
- Acceptance: harness has its own tests; ≥80% coverage maintained.
- Deps: WU-0.2.
- Done 2026-06-18: CLI repo commit on `main`. Added `internal/sources/sourcetest/conformance.go`: `RunConformance(t, *Options)` (thin `*testing.T` wrapper) over a pure `checkConformance(ctx, *Options) ([]rec, []error)` so the harness's own negative cases assert rejection without failing the real T. Checks: determinism (two Collects → `reflect.DeepEqual`; nudges plugins to inject a clock instead of `time.Now`), ID-sorted, per-record metadata (`Type` ∈ `Emits()`, non-empty `ID`/`SourceID`, non-zero `CollectedAt`), schema conformance via `evidencetypes.Validate`, and CloudQuery-style completeness (every schema `properties` key present in payload; `Options.OptionalFields` exempts `field` or `type.field`; `AllowEmpty` for empty scenarios). `Options{Plugin, Request, EvidenceTypes, OptionalFields, AllowEmpty}`; `Request.AcceptedTypes` defaults to `Emits()`. Added `BuiltinEvidenceTypes(t)` (loads embedded schemas via `registry.NewSet()`+`evidencetypes.Register`). TDD via in-package fake plugin + synthetic `test_widget` type, one good case + 10 failure cases + optional/allow-empty/defaulting/builtin. Package coverage 88.6%; `go build/vet ./...`, `golangci-lint`, `gofmt`, `check-fixtures` all green. (go-vcr cassette wiring is WU-1.2, in a separate file.)

### WU-1.2 — Add go-vcr + HTTP cassette wiring
- Repo: **CLI**
- [x] Add `dnaeon/go-vcr` v4 to `go.mod`.
- [x] Add `sourcetest` helpers: load a cassette, wrap as `http.RoundTripper`, install redaction `BeforeSaveHook` (per §4.3).
- Acceptance: a sample cassette replays deterministically with no network.
- Deps: WU-1.1.
- Done 2026-06-18: CLI repo commit on `main`. Added `gopkg.in/dnaeon/go-vcr.v4 v4.0.6` (direct dep) and `internal/sources/sourcetest/cassette.go`: `ReplayClient(t, name)` (ModeReplayOnly + `WithReplayableInteractions(true)` so the same cassette serves a plugin hitting an endpoint twice AND the conformance harness's two Collect runs; errors on any unrecorded request → offline/deterministic) and `RecordClient(t, name, realTransport)` (ModeRecordOnce, installs the redaction hook). `RedactInteraction` is the exported `BeforeSaveHook` scrubbing headers (sensitive names→`REDACTED`), URL, and request/response bodies to the §4 placeholders via ordered regexes (AKIA key→`AKIAEXAMPLE0000000000`; `bearer …`→`Bearer REDACTED`; non-`example.*` emails→`user@example.com`; 12-digit runs→`000000000000`, which also zeroes ARN accounts). `MethodURLMatcher` (method+URL only — strict default would break on redacted-vs-live credential headers). Hand-authored sample cassette at `testdata/cassettes/sample.yaml` (v4 `version: 2`); tests prove offline replay (x2), unrecorded→error, matcher, and full redaction (reusing the WU-0.3 regexes to assert no identity survives). Package coverage 88.1%; `go test -race`, `golangci-lint`, `gofmt`, `check-fixtures` (scans the new cassette — clean), `go build/vet ./...` all green. Username/login scrubbing beyond email-style is left to a plugin-specific hook (documented).

### WU-1.3 — GitHub plugin: cassettes + conformance test
- Repo: **CLI**
- [x] Record sanitized cassettes against a **free** GitHub org/public repo into `internal/sources/github/testdata/cassettes/` (branch-protection present/absent; org member 2FA on/off).
- [x] Add `github_conformance_test.go` replaying them through `RunConformance` (asserts `git_repository` + `directory_user` records).
- Acceptance: passes offline; redaction verified by WU-0.3 gate.
- Deps: WU-1.2.
- Done 2026-06-28: CLI repo commit on `main`. Recorded one sanitized cassette `internal/sources/github/testdata/cassettes/org_collect.yaml` against the live `Sigcomply-test-org` (repos `e2e-protected` = branch-protected w/ 1 required reviewer + Dependabot on; `e2e-unprotected` = private, no protection, Dependabot off; one org member = admin, 2FA off). Recorded via a throwaway `//go:build record` driver using `sourcetest.RecordClient` (auth header → `REDACTED`, emails scrubbed by the §4.3 hook); then neutralized the real org/login (`Sigcomply-test-org`→`e2e-test-org`, `prasanth-sigcomply`→`e2e-admin`) since generic redaction doesn't scrub git logins (documented plugin responsibility). Added `github_conformance_test.go` (in-package, offline): builds `httpAPI` around `sourcetest.ReplayClient`, runs `RunConformance` **per evidence type** (the plugin sorts records within each type group; the harness's ID-sort check is per-type, not across the mixed `git_repository`+`directory_user` output), with `OptionalFields` for the 5 directory_user + 1 git_repository schema fields the GitHub org endpoints don't expose. Plus scenario assertions on protection/reviewers/Dependabot/visibility and is_admin/mfa/is_active/is_external. `go test -race ./internal/sources/github/...`, full `go test ./...`, `go build/vet`, `golangci-lint`, `gofmt`, and `check-fixtures.sh` (scans the new cassette — clean) all green. The recorder is not committed (re-record procedure documented in the test header); the cassette is the committed artifact.

### WU-1.4 — GitHub fixture-vs-spec conformance
- Repo: **CLI**
- [x] Snapshot the GitHub OpenAPI slices we use → `contracts/github/api.github.com@<date>.json` (from `github/rest-api-description`).
- [x] In the conformance test, validate each cassette **response body** against the spec schema → a stale cassette fails.
- Acceptance: hand-mutating a cassette to an off-spec shape fails the test.
- Deps: WU-1.3.
- Done 2026-06-28: CLI repo commit on `main`. Extracted the 5 operations `internal/sources/github` calls from GitHub's published OpenAPI (`github/rest-api-description` `descriptions/api.github.com/api.github.com.json`, openapi 3.0.3) plus the transitive `$ref` closure (16 component schemas, 67 KB) into `contracts/github/api.github.com@2026-06-28.json` — response components `minimal-repository`, `simple-user`, `org-membership`, `branch-protection`. Added a **reusable** `sourcetest` spec seam (used by future OpenAPI providers — GitLab/Okta/Azure): `NewSpecValidator` (kin-openapi `v0.134.0`, `LoadFromData` so internal refs resolve + we skip `doc.Validate` so a trimmed slice loads; honors OpenAPI 3.0 `nullable`/`allOf`, unlike draft-07 gojsonschema), `Check`/`CheckArray` (return the error so negatives can assert rejection), `LoadCassetteInteractions`, `DecodeJSONBody`; covered by `spec_test.go` (sourcetest 88.2%). Added `github_spec_conformance_test.go`: routes each recorded interaction (method+URL path) to its component and validates every 2xx JSON body against the snapshot, asserting per-component minimums so a cassette that stops covering an operation can't pass as a no-op; `TestSpecValidatorRejectsOffSpecBody` is the acceptance check (mutating `simple-user.id` int→string is rejected). Total coverage 87.3% (>80%). `go test ./...` (clean cache), `-race` on sources, `go build/vet`, `golangci-lint` (my files 0 issues), `gofmt`, `check-fixtures.sh` (scans the new contract — clean) all green.

### WU-1.5 — Document the "add-a-source-plugin testing checklist"
- Repo: **CLI**
- [x] Update `docs/architecture/04-source-plugins.md` and `07-extensibility.md`: every new plugin ships (a) conformance test via `sourcetest`, (b) cassettes, (c) a `contracts/` snapshot entry, (d) redaction-clean fixtures.
- Acceptance: checklist references the GitHub plugin as the worked example.
- Deps: WU-1.3, WU-1.4.
- Done 2026-06-28: CLI repo commit on `main`. Added a new **"Testing a source plugin (checklist)"** section to `04-source-plugins.md` (after the plugin-invariants checklist): a 4-row table mapping each required deliverable (a) `sourcetest.RunConformance` conformance test, (b) sanitized go-vcr cassettes (record/replay seam), (c) a `contracts/<provider>/...` spec snapshot + fixture-vs-spec test, (d) redaction-clean fixtures behind the `check-fixtures.sh` gate — each row links the **GitHub plugin as the worked example** (`github_conformance_test.go`, `org_collect.yaml`, `api.github.com@2026-06-28.json` + `github_spec_conformance_test.go`), plus the cloud-bootstrap / spec-too-thin / live-blocked fallbacks. Wired it into `07-extensibility.md`'s "Contributing back upstream" step 4 (in-tree tests now point at the checklist). All cross-links + the `#testing-a-source-plugin-checklist` anchor verified; referenced paths exist; docs-only (no code).

---

## 9. Phase 2 — Roll out L1+L2 across all plugins (CLI repo)

Goal: apply the Phase-1 template to every existing source. Each WU = one provider/group, one commit. **Cloud cassettes** are recorded during an L4b run or a one-off maintainer record (see §3 boundary rule); hand-authored fixtures from real responses are an acceptable bootstrap.

> **Handoff note — new plugins from the source-integrations plan (added 2026-06-18, WU-6.3 of `core_source_integrations_plan.md`).** Phase 2 was authored against the original source set (AWS · GCP foundation 4 · GitHub · Okta · Manual). The integrations plan since shipped **30 new source plugins** that also need L1/L2 (cassette + conformance) coverage — WU-2.10–2.13 below were added to absorb them. They are: **GitLab** (`gitlab` → `git_repository`, `directory_user`); **GCP expansion** — 14 plugins beyond the WU-2.7 foundation four (`gcp.directory`, `gcp.firewall`, `gcp.network`, `gcp.kms`, `gcp.secretmanager`, `gcp.logging`, `gcp.audit`, `gcp.asset`, `gcp.scc`, `gcp.artifactregistry`, `gcp.gke`, `gcp.firestore`, `gcp.backup`, `gcp.certs`); **Azure** — 15 plugins (`azure.entra`, `azure.storage`, `azure.sql`, `azure.network`, `azure.compute`, `azure.keyvault`, `azure.monitor`, `azure.defender`, `azure.acr`, `azure.aks`, `azure.cosmos`, `azure.backup`, `azure.certs`, `azure.policy`). Each currently ships only happy-path `fakeAPI` unit tests (the integrations plan deliberately deferred the deeper layers to this revamp). Also: **GitHub (WU-1.3/1.4) and Okta (WU-2.8) gained `is_admin`/`is_active`/`directory_user.v2` fields** — their conformance assertions must be extended to cover the new fields, not just re-run as-is. The authoritative per-plugin source→evidence-type map is the coverage matrix in `sigcomply-cli/docs/architecture/04-source-plugins.md`.

### WU-2.1 — AWS cassette wiring + per-protocol matcher
- Repo: **CLI**
- [x] Add `sourcetest` AWS seam (`config.WithHTTPClient`) and a body/`X-Amz-Target`-aware cassette matcher (query/json protocols collide on default matcher); ignore `X-Amz-Date`/signature.
- Acceptance: an IAM (query protocol) and an S3 (REST) cassette both replay correctly.
- Deps: WU-1.2.
- Done 2026-06-28: CLI repo commit on `main`. Added `sourcetest.AWSMatcher` (+ `ReplayClientWithMatcher`/`RecordClientWithMatcher`): after method+URL it disambiguates by `X-Amz-Target` (json protocol) else by request body (query protocol — IAM/STS POST every op to one identical URL), reading-and-restoring `r.Body` (go-vcr calls the matcher once per recorded interaction against the same request; AWS SDK/smithy never sets `GetBody`); deliberately ignores `Authorization`/`X-Amz-Date` (SigV4 sig+timestamp differ between record and replay). New seam package `internal/sources/aws/awstest` — `ReplayConfig(t,name)`/`RecordConfig(t,name)` build an `aws.Config` via `config.WithHTTPClient` + fixed region `us-east-1` + `aws.NopRetryer` (deterministic) + dummy static creds on replay (so SigV4 signing runs without error). Kept the AWS-SDK dependency out of the generic `sourcetest` (matcher is pure `net/http`); the SDK-specific config helper lives under `sources/aws`. Recorded `awstest/testdata/cassettes/{iam_query,s3_rest}.yaml` against AWS acct 935595347100 (read-only recorder creds) via a throwaway `//go:build record` driver: `iam_query` holds **two** same-URL query ops (`ListUsers`+`GetAccountSummary`) to prove body disambiguation; `s3_rest` is `ListBuckets` (REST, path-style). Redaction scrubbed the access key + `Authorization`; hand-neutralized the account's IAM usernames/UserIds + S3 canonical owner ID (public repo). Acceptance test `awstest_test.go`: both query ops replay+route correctly, a second `ListUsers` replays (replayable), an **unrecorded** `ListRoles` (same URL) is rejected (proves body-not-URL matching), and S3 `ListBuckets` replays. Plus `sourcetest` unit tests for `AWSMatcher` + body-restore. Coverage: sourcetest 88.1%, awstest 92.3%. Full `go test ./...`, `-race`, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green. **Unblocks WU-2.2–2.6** (AWS service groups build their clients from `awstest.ReplayConfig`).

### WU-2.2 — AWS identity group (iam, iam_access_key, password_policy)
- Repo: **CLI** · Deps: WU-2.1
- [x] Cassettes + conformance tests + `contracts/aws/*` snapshots for `directory_user(.v2)`, `iam_access_key`, `password_policy`.
- Done 2026-06-28: CLI repo commit on `main`. Recorded three sanitized IAM cassettes against acct 935595347100 via throwaway `//go:build record` drivers built on the WU-2.1 `awstest.RecordConfig` seam: `iam/testdata/cassettes/iam_users.yaml` (ListUsers + per-user MFA/keys/policies/groups + a **pre-warmed** credential report so the single `GetCredentialReport` returns ready — avoids the identical-body poll-loop colliding under the matcher), `accesskeys/.../access_keys.yaml`, `passwordpolicy/.../password_policy.yaml` (account has no policy → NoSuchEntity → weakest-posture record). In-package conformance tests wire `awsiam.NewFromConfig(awstest.ReplayConfig(...))` into each plugin's exported `Options.API`; assert `directory_user.v2` (3 records incl. synthetic root: 1 is_root, console-yes/MFA-no/keys-no; 2 users with programmatic access; MFA off account-wide), `iam_access_key` (2 distinct keys, active), `password_policy` (singleton, weakest posture). `contracts/aws/iam@2010-05-08.json` = the Smithy 2.0 model sliced to the 10 operations these plugins call + their shape closure (86 shapes; doc/example traits stripped so AWS's canonical `123456789012` example account doesn't trip the gate). **Two shared-redaction fixes landed here (both needed by AWS, benefit all):** (1) `redactAccessKey` now maps each distinct `AKIA…` to a *distinct deterministic* placeholder (was a single constant) — the iam_access_key source keys records on the access key ID, so collapsing them aliased records/requests; (2) `RedactInteraction` now also scrubs the recorded `Request.Form` (go-vcr persists the parsed form alongside Body; AWS query requests populate both — raw keys were leaking there). The credential-report **base64 CSV** is opaque to the regex hook, so it's decoded→scrubbed (account/usernames)→re-encoded by hand. **No in-test fixture-vs-spec for AWS** (unlike GitHub/Okta): the published model is Smithy, not JSON-Schema/OpenAPI, so there's no in-Go validator — the L2 contract check for AWS is the *real SDK deserializer* replaying the cassette (a drifted shape fails to deserialize → Collect errors → conformance fails); the Smithy snapshot feeds scheduled L3 `smithy diff`. Full `go test ./...`, `-race`, build/vet, `golangci-lint` (new files 0 issues), gofmt, `check-fixtures` all green.

### WU-2.3 — AWS data/storage group (s3, rds, dynamodb, kms, secretsmanager, backup)
- Repo: **CLI** · Deps: WU-2.1
- [x] Cassettes + conformance for `object_storage_bucket`, `managed_database_instance`, `nosql_table`, `kms_key`, `secret`, `backup_plan`.
- Done 2026-06-28: CLI repo commit on `main`. The e2e account was empty for storage (only an AWS-managed KMS key); per user decision, **provisioned minimal resources with admin creds, recorded, then tore everything down** (account verified clean; the one customer KMS key is in 7-day PendingDeletion). Provisioned + recorded: S3 bucket (SSE-KMS + versioning + public-access-block), DynamoDB table (SSE-KMS + PITR + deletion-protection), Secret (customer-KMS, never-rotated), Backup plan (retention rule), KMS customer key w/ rotation (cassette also captures the 2 AWS-managed keys → exercises the rotation-skip path). **RDS hand-authored** (skipped provisioning — cost/time): canned query-XML served via `httptest` and recorded through the recorder so the SDK's *real request bodies* are captured, then the localhost URL rewritten to the real RDS endpoint. Six in-package conformance tests wire `<svc>.NewFromConfig(awstest.ReplayConfig(...))` into each plugin's `Options.API`. **Two AWSMatcher/seam hardenings landed here:** (1) the matcher now compares the **request body for json-protocol too** (was X-Amz-Target-only) — KMS's per-key `DescribeKey` fan-out shares one X-Amz-Target and differs only in body, so the old matcher aliased keys 2/3 to key 1 *at record time* (had to re-record KMS after the fix); (2) confirmed query/REST still match. Scrubbed resource names (`sigcomply`→`e2e`); opaque resource UUIDs left (not PII/secret per §4.3; account/ARNs zeroed; keeping distinct KMS key UUIDs keeps the body-matcher working). No AWS in-test fixture-vs-spec (Smithy, not JSON-Schema — same rationale as WU-2.2); `contracts/aws/*` Smithy snapshots for these services deferred to WU-3.1. Full `go test ./...`, `-race`, build/vet, `golangci-lint` (new files 0 issues), gofmt, `check-fixtures` all green.

### WU-2.4 — AWS compute group (ec2, lambda, ecr, eks)
- Repo: **CLI** · Deps: WU-2.1
- [x] Cassettes + conformance for `compute_instance`, `serverless_function`, `container_registry`, `kubernetes_cluster`.
- Done 2026-06-28: CLI commit on `main`. Provisioned cheap+recorded+torn-down ec2 (t3.micro, encrypted root, public IP), lambda (role+tiny fn, tracing Active), ecr (scan-on-push + IMMUTABLE); **eks hand-authored** via httptest-record (control plane is costly/slow) — private endpoint + control-plane logging + KMS secrets encryption. Account verified clean after teardown. Conformance tests via `awstest.ReplayConfig`. Scrubbed the EC2 public IP (32.198.118.76→203.0.113.10 TEST-NET, dotted+DNS forms) and `sigcomply-e2e`→`e2e` names; account IDs auto-zeroed. All green.

### WU-2.5 — AWS logging/monitoring group (cloudtrail, cloudwatch, config)
- Repo: **CLI** · Deps: WU-2.1
- [x] Cassettes + conformance for `audit_log_trail`, `log_group`, `config_change_tracking`.
- Done 2026-06-28: CLI commit on `main`. Provisioned+recorded+torn-down cloudtrail (multi-region trail + log-file-validation, own S3 bucket) and cloudwatch (log group, 30-day retention); **config hand-authored** via httptest-record (a Config recorder needs role+delivery-channel+S3 and bills per item) — one recorder, recording all resource types. Account verified clean. Conformance via `awstest.ReplayConfig`; `sigcomply-e2e`→`e2e`, account IDs auto-zeroed. All green.

### WU-2.6 — AWS security group (guardduty, inspector, security_services, security_alert, security_group, vpc, acm)
- Repo: **CLI** · Deps: WU-2.1
- [x] Cassettes + conformance for `threat_detection_service`, `vulnerability_finding`, `security_service`, `security_alert`, `firewall_rule`, `network`, `tls_certificate`.
- Done 2026-06-28: CLI commit on `main`. 7 plugins. Recorded-as-is: vpc (default VPC), securitygroups (default SG open egress), securityservices (**multi-client** macie2+inspector2+securityhub in one cassette — services not enabled → graceful AccessDenied→is_enabled=false, 3 records). Provisioned+recorded+torn-down: guardduty (enabled detector), securityalert (**multi-client** cwl+cw — 2 metric filters [root-usage, unauthorized] wired to alarms with an SNS target). Hand-authored via httptest-record: acm (AMAZON_ISSUED cert, 45-day expiry), inspector (one HIGH active CVE finding). Multi-client recorders/tests build the unexported `awsClients`/`awsAPI` in-package from one shared `awstest` config. Account verified clean; `sigcomply-e2e`→`e2e`; account IDs auto-zeroed. **AWS rollout (WU-2.1-2.6) complete** — all ~23 AWS service plugins now have L1+L2. All green.

### WU-2.7 — GCP cassette wiring + plugins (compute, iam, sql, storage)
- Repo: **CLI** · Deps: WU-1.2
- [x] GCP `option.WithHTTPClient` seam; cassettes + conformance for `compute_instance`, `iam_binding`, `managed_database_instance`, `object_storage_bucket`; `contracts/gcp/*` Discovery snapshots.
- Done 2026-06-28: CLI commit on `main`. New reusable `internal/sources/gcp/gcptest` seam — `ReplayOptions`/`RecordOptions` wire a go-vcr cassette + `option.WithEndpoint` + `option.WithoutAuthentication` into any GCP SDK client (`google.golang.org/api/*` and `cloud.google.com/go/storage`). **No live GCP credential** (org blocks SA keys + impersonation per `CLAUDE.local.md`), so all 4 cassettes are **hand-authored via httptest-record**: canned Discovery-shaped JSON served from an httptest server at record time, captured by the recorder, then the localhost URL rewritten to the real googleapis endpoint (replay matches on method+URL — GCP gives each op a distinct URL, no body matcher needed). In-package conformance tests build the unexported real adapter (`realCompute`/`realCRM`/`realSQL`/`realGCS`) from the seam options. Records: compute (shielded/private/encrypted/running instance), iam (owner+viewer → 3 bindings, 1 broad-admin), sql (REGIONAL postgres, SSL-required, backups+PITR, deletion-protected), storage (uniform BLA + PAP-enforced + versioning + CMEK). **`contracts/gcp/{compute,cloudresourcemanager,sqladmin,storage}@v1.json`** Discovery snapshots added via a new `scripts/contracts/slice_discovery.py` (response-schema `$ref` closure; strips descriptions — they carry GCP example emails the gate forbids) wired into `contracts-fetch.sh` (Discovery docs are public, no auth). Total coverage 87.7%; `contracts-diff` reproducible/no-drift; full `go test ./...`, `-race`, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green.

### WU-2.8 — Okta plugin (directory_user, okta_app)
- Repo: **CLI** · Deps: WU-1.2
- [x] Cassettes + conformance; `contracts/okta/*` OpenAPI snapshot.
- Done 2026-06-28: CLI repo commit on `main`. Full GitHub-template mirror for Okta (raw net/http, injectable `httpAPI.client`). Recorded `internal/sources/okta/testdata/cassettes/org_collect.yaml` against the live trial org via a throwaway `//go:build record` driver + `sourcetest.RecordClient` (SSWS `Authorization` header scrubbed by the §4.3 hook; `prasanth@sigcomply.com`→`user@example.com`); neutralized the org subdomain `trial-7068441[.okta.com|_…]`→`example.okta.com`/`example-org` (opaque Okta IDs kept — not PII, and keeps list-body↔per-user-URL replay consistent). `okta_conformance_test.go` (per-type RunConformance for `directory_user` + `okta_app`; ground truth `users=3 active=1 admins=1 mfa=1 apps=7`, asserts those aggregates + SAML/OIDC→`mfa_required`). `okta_spec_conformance_test.go` reuses the WU-1.4 `sourcetest` spec seam against `contracts/okta/management@2026-06-28.json` (Okta's own OpenAPI 3.0.3, `management-minimal.yaml`; 165-schema `$ref` closure for `/users`,`/users/{id}/factors`,`/users/{id}/roles`,`/apps`). Validates `User` + `UserFactor` strictly; **`Application` is excluded from strict whole-body validation** — Okta's *own* schema marks `accessibility.{loginRedirectUrl,errorRedirectUrl}` non-nullable but the live API returns null (known Okta spec inaccuracy, on fields we don't consume) — the slice still ships `Application` for L3 drift; `/roles` is an inline oneOf (conformance-covered). Negative test: an invalid `User.status` enum is rejected. Full `go test ./...`, `-race` on okta, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green.

### WU-2.9 — Manual evidence plugin (signed_document)
- Repo: **CLI** · Deps: WU-1.1
- [x] Local-backend `testdata/` fixtures (PDF + each supported image type); conformance for `signed_document` incl. image→PDF merge. Use Azurite/fake-gcs-server only if exercising remote backends.
- Done 2026-06-28: CLI commit on `main`. Committed local `testdata/store/manual/…` fixtures (a real PDF + one of each supported image: png/jpg/gif/tif/bmp/webp) and `manual_conformance_test.go` driving the **real `local` backend** (filesystem, no network/cassette). `TestManualConformance` runs the full `sourcetest.RunConformance` harness on a single-PDF folder; `TestManualMultiFormatMerge` exercises image→PDF conversion for all 6 formats + the multi-file merge and schema-validates the record. **Finding (documented):** `pdfmerge.Merge` (pdfcpu) is **non-deterministic** — it embeds a fresh document ID, so a merged multi-file `file_hash` is not byte-stable (single-file is, merge being pass-through). The determinism harness runs only on the single-file case; latent product concern (re-collected manual evidence → different `file_hash` → carry-forward churn) worth a maintainer fix. All green.

### WU-2.10 — GitLab plugin (git_repository, directory_user)
- Repo: **CLI** · Deps: WU-1.2
- [x] Cassettes + conformance for `git_repository` and `directory_user` (the `gitlab` source mirrors GitHub; reuse the WU-1.3/1.4 GitHub template). Assert `is_admin`/`is_active`; document the `two_factor_enabled` group-owner-token caveat (see integrations-plan risk). ~~`contracts/gitlab/*` OpenAPI snapshot.~~ (no spec snapshot — GitLab's OpenAPI is too thin; see below.)
- Done 2026-06-28: CLI repo commit on `main`. (Initial blocker — the first fine-grained token 403'd even on `/user`; resolved once the user supplied a classic `read_api` PAT.) Recorded `internal/sources/gitlab/testdata/cassettes/group_collect.yaml` against the live `sigcomply-e2e` group via a throwaway `//go:build record` driver — the gitlab plugin uses the official `gitlab.com/gitlab-org/api/client-go` SDK, so the cassette client is injected via `gitlab.NewClient(token, gitlab.WithBaseURL, gitlab.WithHTTPClient(sourcetest.RecordClient(...)))` and the in-package test builds the unexported `sdkAPI{client,group}` directly. **Shared-infra fix:** GitLab authenticates with the **`PRIVATE-TOKEN`** header, which the generic `RedactInteraction` hook didn't scrub — added `Private-Token`+`Job-Token` to `sourcetest`'s `sensitiveHeaders` (+ a redaction-test assertion); verified the recorded token is `REDACTED`. Neutralized the group path `sigcomply-e2e`→`e2e-group` and member username `prasanth39`→`e2e-owner` (opaque numeric project/user IDs kept for replay consistency). `gitlab_conformance_test.go` (per-type RunConformance): asserts `e2e-group/e2e-protected` is branch-protected + private and `e2e-group/e2e-unprotected` is not, and the Owner member maps to `is_admin && is_active`. **No fixture-vs-spec layer:** GitLab's published OpenAPI is too thin (covers none of projects/members/protected_branches/users), per §2/§5 ("GitLab's spec is thin → lean on L4a live re-record diffs") — documented in the test header; GitLab's drift signal is the scheduled live re-record (Phase 4), not L3. As expected on gitlab.com SaaS, `two_factor_enabled`/instance-`is_admin` aren't exposed on `/users/{id}` so `mfa_enabled` is best-effort false (the group-owner-token caveat); `is_admin` still comes from the group AccessLevel (Owner=50). Full `go test ./...`, `-race` on gitlab+sourcetest, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green.

### WU-2.11 — GCP expansion plugins (Wave 1+2)
- Repo: **CLI** · Deps: WU-2.7
- [x] Extend the WU-2.7 GCP seam to the 14 plugins added by the integrations plan: `gcp.directory`, `gcp.firewall`, `gcp.network`, `gcp.kms`, `gcp.secretmanager`, `gcp.logging`, `gcp.audit`, `gcp.asset`, `gcp.scc`, `gcp.artifactregistry`, `gcp.gke`, `gcp.firestore`, `gcp.backup`, `gcp.certs`. Cassettes + conformance for their evidence types (see matrix); reuse `contracts/gcp/*` Discovery snapshots. Splittable into sub-WUs (identity/network, data/kms, logging/audit, container/registry, certs/backup) if a single commit is too large.
- Done 2026-06-28: CLI repo commits on `main` (5 sub-group commits a–e). All 14 plugins now have hand-authored cassettes (httptest-record via the WU-2.7 `gcptest` seam — no live GCP cred) + conformance: **(a)** directory_user (admin SDK, Customer seam), firewall_rule, network; **(b)** kms_key (location→keyRing→cryptoKey walk), secret (secrets+versions), nosql_table (Firestore); **(c)** log_group, config_change_tracking (Asset feeds), audit_log_trail (**multi-client** cloudresourcemanager v3 + logging v2, two real endpoints, per-interaction URL rewrite, one shared replay client); **(d)** kubernetes_cluster, container_registry (locations→repos→IAM walk), SCC's **3 evidence types** (threat/security_service/vuln; **multi-client** securitycenter v1 + v1beta2 on one host, run per evidence type); **(e)** tls_certificate (managed + self-managed), backup_plan. Multi-client recorders/tests build the unexported real adapters in-package and share one record/replay client across services (matcher keys on URL). Hit + fixed a goconst (reused the in-package `stateActive` const). Full `go test ./...`, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green; total coverage ~87%.
- ~~**Deferred (follow-up):** L3 Discovery snapshots for the new GCP APIs.~~ **CLOSED 2026-06-28** (commit `26695e8`): `contracts-fetch.sh` now snapshots every GCP API the 18 plugins read — 13 new APIs (cloudresourcemanager v3, cloudkms, secretmanager, logging, admin/directory_v1, cloudasset, securitycenter v1+v1beta2, artifactregistry, container, firestore, backupdr, certificatemanager) + Firewall/Network/Subnetwork seeds added to the compute slice. `fetch_discovery` falls back to the per-service `$discovery` endpoint for newer APIs absent from the legacy directory. contracts-diff reproducible/no-drift; gate clean.

### WU-2.12 — Azure ARM-plane group
- Repo: **CLI** · Deps: WU-1.2
- [x] New Azure cassette seam (azidentity + ARM `armXXX` `*ClientOptions` transport / `azcore` `policy.ClientOptions.Transport`; matcher ignores bearer-token/`x-ms-date`, keys on body + `x-ms-target`-equivalent). Cassettes + conformance for the 13 ARM-plane plugins: `azure.storage`, `azure.sql`, `azure.network`, `azure.compute`, `azure.keyvault`, `azure.monitor`, `azure.defender`, `azure.acr`, `azure.aks`, `azure.cosmos`, `azure.backup`, `azure.certs`, `azure.policy`. `contracts/azure/*` snapshots. Splittable by service group.
- Done 2026-06-28: CLI repo commits on `main` (5 sub-group commits a–e). New `internal/sources/azure/internal/azuretest` seam — a fake `azcore.TokenCredential` + `arm.ClientOptions` (`azcore.ClientOptions.Transport` = the go-vcr client; `Cloud` endpoint override for record). The Reader SP works but the **subscription is empty**, so all cassettes are hand-authored via httptest-record (the ARM SDK **refuses bearer auth over plain HTTP** → record server is `httptest.NewTLSServer` and the recorder is handed `srv.Client().Transport` to trust the self-signed cert; recorded `127.0.0.1` URL rewritten to `https://management.azure.com`). ARM gives each resource-type list a distinct URL, so the default method+URL matcher works (Authorization/`x-ms-date` ignored). All 13 plugins build the unexported `newReal<X>(subID, cred, *arm.ClientOptions)` adapter in-package — so both recorder and conformance test are SDK-import-free. Coverage: **(a)** object_storage_bucket, managed_database_instance (Azure SQL TDE + PG flexible; MySQL empty), compute_instance (VM + per-NIC); **(b)** firewall_rule+network (NSG+VNet), kms_key+secret (vault→keys→Get + secrets); **(c)** log_group+audit_log_trail (workspace + diagnostic settings), config_change_tracking (policy assignments); **(d)** Defender's 3 types (pricings→threat, CSPM security_service, sub-assessments→vuln), container_registry, kubernetes_cluster (cluster + per-cluster diag); **(e)** nosql_table (Cosmos), backup_plan (vault→policies), tls_certificate (App Service cert + cert order). Multi-type plugins run RunConformance per evidence type. Hit + fixed a wire-value bug in my fixture (keyvault rotation action type is lowercase `"rotate"` per the SDK enum, not `"Rotate"`). Full `go test ./...`, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green; total coverage 87.7%.
- ~~**Deferred (follow-up):** `contracts/azure/*` L3 swagger snapshots.~~ **MOSTLY CLOSED 2026-06-28** (commit `1abb021`): new `scripts/contracts/slice_swagger.py` (OpenAPI-2.0 definition-closure slicer) + **21 `contracts/azure/*` snapshots** wired into `contracts-fetch.sh`, covering **12 of the 13** ARM plugins' resource shapes (storage; sql servers/databases/TDE; network nsg/vnet/nic; compute; keyvault; operationalinsights; defender pricings; acr; aks; cosmos; recoveryservices + backup; app-service + cert-registration certs; pg/mysql flexible; policy). api-version+file pinned per RP (Azure publishes fragmented per-area/per-version swaggers; the `armXXX` SDK is go.mod-pinned, so this tracks upstream shape while L2 validates the wire). **Residual (2 secondary shapes, L2-covered):** monitor `DiagnosticSettingsResource` (audit_log_trail) and `Microsoft.Security` sub-assessments (vulnerability_finding) are buried in Azure's inconsistent layout — left unpinned. contracts-diff reproducible/no-drift; gate clean.

### WU-2.13 — Azure Entra group (directory_user)
- Repo: **CLI** · Deps: WU-2.12
- [x] `azure.entra` is Graph-plane (raw REST, not `msgraph-sdk-go`), a different seam from the ARM plugins — own cassette + conformance. Assert `mfa_enabled`/`is_admin`/`is_active` mapped from `userRegistrationDetails`; cover the P1/P2-report-inaccessible **error** path (must error, never emit false MFA). Pairs with the WU-4.5 Entra live test.
- Done 2026-06-28: CLI repo commit on `main`. `entra_conformance_test.go` builds the unexported `realGraph{base, client, cred}` in-package with a go-vcr `sourcetest.ReplayClient` + the existing in-package `fakeCred` (no `azuretest` needed — the plugin is raw `net/http`, so plain-HTTP record works without the ARM TLS-bearer guard). Hand-authored `testdata/cassettes/directory.yaml` (httptest-record, per the CLAUDE.local.md decision — the `userRegistrationDetails` MFA report is **Entra-ID-P2-gated** in this tenant, so live recording isn't possible): two `/reports/authenticationMethods/userRegistrationDetails` rows joined with `/users` → one admin with MFA + one standard user without; asserts `is_admin`/`mfa_enabled` mapped correctly, both `is_active`. The matcher keys on method+URL (the two Graph endpoints are distinct), Authorization scrubbed. **Note:** the P1/P2-report-inaccessible **error** path (plugin must error, never emit false MFA) is an existing unit test in `entra_test.go`, not re-covered here — this WU adds the L1/L2 happy-path cassette conformance. Full `go test ./...`, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green; total coverage ~87.7%.

---

## 10. Phase 3 — Drift detection (CLI repo, scheduled, $0)

Goal: the free mechanism that actually catches upstream API changes, decoupled from per-PR tests.

### WU-3.1 — Populate `contracts/` + `make contracts-fetch`
- Repo: **CLI** · Deps: WU-2.* (snapshots accrue as plugins land; this WU ensures full coverage + a refresh script)
- [x] `scripts/contracts-fetch.sh` pulls current specs for every used service (AWS smithy models, Azure `azure-rest-api-specs`, GCP Discovery, GitHub/Okta/GitLab OpenAPI) into `contracts/`.
- [x] `make contracts-fetch` target.
- Done 2026-06-28: CLI repo commit on `main`. Formalized the Phase-1/2 ad-hoc extractors into committed, reusable slicers — `scripts/contracts/slice_openapi.py` (GitHub/Okta: pull each used operation's 200 schema + transitive `$ref` closure) and `slice_smithy.py` (AWS: operation shape-closure + trimmed service shape; strips `documentation`/`examples`/`endpointRuleSet`/`endpointTests`/`smokeTests` traits — noise for shape-drift and the carrier of AWS's canonical `123456789012` example account that would trip the gate). `scripts/contracts-fetch.sh` (+ `make contracts-fetch`) downloads each upstream spec and re-slices **in place**, so `git diff contracts/` after a fetch is the raw drift signal (WU-3.2 classifies it). **Cleared the WU-2.3 snapshot debt** — now ships `contracts/aws/{iam,s3,rds,dynamodb,kms,secretsmanager,backup}@<api-version>.json` (versions derived from each Smithy service shape) alongside the existing github/okta. **Reproducibility verified:** re-running regenerates the committed github/okta snapshots byte-identical; the github/okta L2 spec tests still pass against the regenerated files. (The `iam@` snapshot shrank vs WU-2.2 — endpoint/test traits now stripped by the unified slicer; benign re-baseline.) **Scope:** pinned only services with a shipped plugin+cassette; **GitLab omitted** (thin spec → L4a re-record per §2), **GCP/Azure deferred** until their plugins land (structure ready to add). No shellcheck gate in CI (verified); `check-fixtures` scans all 9 contracts clean; `go test ./...`, build/vet, gofmt green.

### WU-3.2 — `make contracts-diff`
- Repo: **CLI** · Deps: WU-3.1
- [x] Wire `oasdiff` (OpenAPI providers), `smithy diff` (AWS), Discovery JSON diff (GCP) comparing committed snapshots vs. freshly fetched; classify breaking vs. non-breaking; output a report.
- Done 2026-06-28: CLI repo commit on `main`. `scripts/contracts-diff.sh` (+ `make contracts-diff`) fetches every spec fresh into a temp dir (via the new `CONTRACTS_DIR` override on `contracts-fetch.sh` — **non-destructive**, committed snapshots untouched) and structurally diffs each committed slice against fresh, exit 1 on any breaking change. **Deviation (deliberate, flagged):** instead of `oasdiff` (OpenAPI) + `smithy diff` (AWS, needs the Java Smithy CLI), used **one dependency-free structural JSON differ** `scripts/contracts/diff_contracts.py` for all providers. Rationale: both our slices are deterministic JSON we control; the differ classifies *removed/changed* (a removed/changed operation·shape·field·enum our mapper reads) as **breaking** and *added* keys as non-breaking, ignoring the `info` metadata block; this keeps the toolchain to python3 only (no Go-binary or Java install gate), and the plan's own "Discovery JSON diff (GCP)" precedent sanctions JSON-diff for non-OpenAPI. The L3 job is alert-only (a human triages), so the heuristic is sufficient; can be upgraded to `oasdiff` later if richer OpenAPI rules are wanted. **Verified:** clean re-fetch diffs to "no change" (exit 0); injecting a field into a committed slice that fresh lacks is reported `BREAKING removed …` for both the AWS-Smithy and OpenAPI paths (exit 1); working tree restored byte-identical. Build + `check-fixtures` green.

### WU-3.3 — Scheduled drift workflow (alert-only)
- Repo: **CLI** · Deps: WU-3.2
- [x] `.github/workflows/contract-drift.yml`, cron mirroring `security.yml` (`0 0 * * 1`); runs `contracts-fetch` + `contracts-diff`; on breaking diff **opens/updates a GitHub issue** (does not fail PRs).
- Acceptance: a simulated spec change produces an issue.
- Done 2026-06-28: CLI repo commit on `main`. Added `.github/workflows/contract-drift.yml` — `schedule` weekly `0 0 * * 1` (mirrors `security.yml`) + `workflow_dispatch`; **never triggers on push/PR**, so it can't block PRs. Runs `scripts/contracts-diff.sh` (which fetches fresh + diffs), captures report + exit code; on nonzero (1 = breaking, 2 = fetch/tooling failure) an `actions/github-script` step opens — or comments on an existing — issue labelled `contract-drift` with the diff report (pinned action SHAs + harden-runner per repo convention; job perms `contents: read` + `issues: write`). Acceptance: the alert keys on `contracts-diff` exit≠0, and WU-3.2 already proved an injected change yields `BREAKING …`/exit 1; the workflow itself was run via `workflow_dispatch` (clean tree → "no breaking drift", no issue). `github-script@v7.0.1` SHA verified; YAML validated.

### WU-3.4 — Drift triage runbook
- Repo: **CLI** · Deps: WU-3.3
- [x] Add `docs/architecture/11-testing-strategy.md` section / `docs/claude/recipes.md` entry: when drift fires → assess impact on mappers → re-record affected cassettes → update `contracts/` snapshot → fix mapper if needed.
- Done 2026-06-28: CLI repo commit on `main`. Added **§7 "Drift triage runbook"** to `docs/architecture/11-testing-strategy.md` (the doc the `contract-drift` workflow links): reproduce with `make contracts-diff` → classify additions (non-breaking) vs breaking (removed/changed field we read) → assess mapper impact (the `contracts/<provider>/<service>` path maps to `internal/sources/<provider>/<service>`) → fix mapper/schema + re-record the affected cassette → `make contracts-fetch` to re-baseline + commit → close the issue; with the "informational until proven breaking; never silence the differ" rule. Also aligned §5 tooling table to the shipped `diff_contracts.py`/`contracts-fetch.sh`. Docs-only.

---

## 11. Phase 4 — SaaS/Entra live tests (CLI repo, build-tagged, scheduled)

Goal: real-call confidence using **free** accounts; also re-records cassettes to keep L2 honest.

### WU-4.1 — Live test convention + env-gating helper
- Repo: **CLI** · Deps: WU-1.1
- [x] `//go:build live` convention; `sourcetest.RequireEnv(t, "GITHUB_TEST_TOKEN")` skip-if-absent helper; exclude `live` from coverage gate.
- Done 2026-06-28: CLI repo commit on `main`. Added `internal/sources/sourcetest/live.go`: `RequireEnv(t, keys...) map[string]string` skips (`t.Skipf`) unless every named env var is non-empty, else returns them keyed by name — factored over a pure `lookupEnv` so the gating logic is unit-tested (present/empty/absent partition + order; present-path return; absent-path skips-not-fails via a subtest). `live_test.go` covers it. **Coverage exclusion is automatic:** every Makefile/CI test target runs without `-tags live`, so live tests aren't compiled into `go test ./...`, the coverage gate, or CI's unit job — verified `go build/vet -tags live ./...` compiles and the default suite still totals 87.7%. Added `make test-live` (`go test -tags live -count=1 ./...`) and documented the convention in `docs/architecture/11-testing-strategy.md` (L4a section). This is the foundation for WU-4.2–4.6 (the actual per-provider live tests). Full `go test ./...`, build/vet, `golangci-lint` (0 issues), gofmt, `check-fixtures` all green.

### WU-4.2 — GitHub live test (free org/public repo)
- Repo: **CLI** · Deps: WU-4.1 — branch protection on a public repo; org 2FA via owner token.
- [x] Done 2026-06-28 (CLI commits `509c2de` fix + `0dc43d7` test on `main`). `github_live_test.go` (`//go:build live`) runs the real plugin via `NewFromToken(org, token)` against a live org (`RequireEnv(GITHUB_TEST_TOKEN, GITHUB_TEST_ORG)`), schema-validates every record (behavioral drift L3 can't see), and asserts ≥1 repo, ≥1 user, exactly 1 org policy with `two_factor_required=true`. **Validated green against the live `SigComply` org** (4 repos, 2 users, 1 policy, 6 dependabot findings). **🐞 Found + fixed a real bug:** the live run 400'd on `GET /orgs/{org}/dependabot/alerts?page=1` — GitHub's org Dependabot alerts endpoint is **cursor-paginated and rejects `page`**. `ListDependabotAlerts` now follows the `Link: rel="next"` URL (generalized `getJSONStatus` to take an absolute URL + return the next-link; `hasNextLink`→`nextLink`). The cassette never exercised this endpoint, so L1/L2 couldn't catch it — exactly the L4a value proposition. Full `go test ./...`, `-tags live` build, `golangci-lint` (0 issues), gofmt, gate green.

### WU-4.3 — GitLab live test (gitlab.com free or self-managed container)
- Repo: **CLI** · Deps: WU-4.1 — covers the provider whose spec is too thin for L3.
- [x] Done 2026-06-28 (CLI commit `444e1a2` on `main`). `gitlab_live_test.go` (`//go:build live`) runs the real SDK plugin via `NewFromToken(group, token, baseURL)` (`RequireEnv(GITLAB_TEST_TOKEN, GITLAB_TEST_GROUP)`, optional `GITLAB_TEST_BASE_URL` → gitlab.com), schema-validates every record, asserts ≥1 repo + ≥1 user. Since GitLab's OpenAPI is too thin for L3, this live run **is** GitLab's drift signal (per §2/§5). **Validated green against the live `sigcomply-e2e` group** (4 repos, 1 member). No bug surfaced. Full `go test ./...`, `-tags live` build, `golangci-lint` (0 issues), gofmt, gate green.

### WU-4.4 — Okta live test (Integrator Free Plan org)
- Repo: **CLI** · Deps: WU-4.1 — users, MFA factors, SAML/OIDC apps.
- [x] Done 2026-06-28 (CLI commit `78c6266` on `main`). `okta_live_test.go` (`//go:build live`) runs the real plugin via `NewFromConfig(orgURL, token)` (`RequireEnv(OKTA_TEST_TOKEN, OKTA_TEST_ORG_URL)`), schema-validates every record (users + MFA factors + SAML/OIDC apps), asserts ≥1 user + ≥1 app. **Compile- + skip-path-verified** (skips cleanly with no creds). **Live validation pending creds:** the Okta SSWS token wasn't in `CLAUDE.local.md`, and the auto-mode classifier (correctly) blocked recovering it from the session transcript — needs `OKTA_TEST_TOKEN`/`OKTA_TEST_ORG_URL` supplied to run green against the trial org (ground truth from WU-2.8: users=3, apps=7). `-tags live` build, `golangci-lint` (0 issues), gofmt green.

### WU-4.5 — Entra ID live test (M365 Developer tenant)
- Repo: **CLI** · Deps: WU-4.1. ~~+ Azure/Entra plugin exists~~ **Unblocked** — the `azure.entra` plugin shipped 2026-06-17 (integrations plan Phase 5). Users + MFA.
- [x] Done 2026-06-28 (CLI commit `d952a5c` on `main`). `entra_live_test.go` (`//go:build live`) builds the app-only credential from `AZURE_*` env (DefaultAzureCredential chain), asserts `VerifyCredential(ScopeGraph)` (real live auth), then runs the plugin. The MFA registration report is Entra-P1/P2-gated, so on a non-premium tenant the plugin errors by design (never emits false MFA) and the test treats that specific error (`"P1/P2"` hint) as a **clean skip with auth already proven**; on a P2 tenant it schema-validates the directory_user records (≥1 user). **Live-validated against the `sigcomply-e2e-graph` tenant** (creds in CLAUDE.local.md): Graph auth OK, the report 403'd with `RequestFromNonPremiumTenantOrB2CTenant` → SKIP as expected (consistent with the WU-2.13 P2-cassette-fallback decision). Full `go test ./...`, `-tags live` build, `golangci-lint` (0 issues), gofmt green.

### WU-4.6 — Scheduled live + cassette re-record workflow
- Repo: **CLI** · Deps: WU-4.2..4.4
- [x] `.github/workflows/live-saas.yml`, nightly cron; free-account tokens as secrets; runs `//go:build live` tests; ~~optional re-record mode~~ → see deviation.
- [x] Docs: free-account setup guide (`docs/architecture/11-testing-strategy.md` appendix).
- Done 2026-06-28 (CLI commit `c5da66e` on `main`). `.github/workflows/live-saas.yml` — nightly `0 3 * * *` + `workflow_dispatch`, never on PRs (mirrors `contract-drift.yml`). Runs `go test -tags live -run Live ./...` with per-provider creds as repo **secrets** (`GH_TEST_*` → `GITHUB_TEST_*` env, since secret names can't start with `GITHUB_`); each test skips when its secret is unset, so the job is green on pass-or-skip and opens/comments a `live-drift` issue only on a real failure (alert-only; pinned action SHAs + harden-runner + `contents:read`/`issues:write`). Added **testing-strategy §8** — the free-account setup guide (per-provider secrets table + how to mint each free credential). **Validated:** `workflow_dispatch` run went **green** (no secrets configured → all live tests skip → no issue), proving the workflow executes + the skip path; WU-4.2..4.5 already proved the live tests themselves (and the GitHub one caught a real bug). **Deviation (flagged):** the planned "optional re-record mode that regenerates cassettes" is **not** automated — cassette recorders are throwaway `//go:build record` drivers (per §4/§8), not committed, so an automated re-record path doesn't fit the architecture. The drift *signal* is the live tests + the L3 Contract Drift job; cassette re-record is the manual *remediation* (documented in §7/§8). YAML validated; `-run Live -tags live` confirmed to select the 4 live tests.

---

## 12. Phase 5 — E2E GitHub repo: assertions, cost discipline, sweepers (L4b)

Goal: close the biggest live-layer gap — the pipeline runs but never asserts — and make it cheap & self-cleaning.

### WU-5.1 — Expected-outcomes assertion harness
- Repo: **E2E GitHub** · Deps: none (can start once Phase 1 stabilizes the run output shape)
- [x] Define `expected-outcomes.yaml` (per-policy expected status, derived from the seed matrix: information_security_policy=pass, background_check=missing, board_security_oversight(.docx)=fail, control_monitoring=copy-paste-fail, plus AWS policy expectations).
- [x] Add an assertion step that parses the run result/vault after `sigcomply check` and **fails the job** if actual ≠ expected.
- Acceptance: flipping one expected value makes the job fail.
- Done 2026-06-28 (E2E GitHub repo, branch `feat/github-soc2-source`, commits `4bea442` + `21f1f68`). The pipeline ran `sigcomply check` but never asserted. Added: **`expected-outcomes.yaml`** — 15 deterministic per-policy expectations keyed by policy_id as it appears in the run summary (`[status] policy_id — control`): the 4 manual outcomes (pass/missing/invalid-type/copy-paste), the account password policy (4 passes set by the cheap setup), cheap-provisioned DynamoDB/ECR/versioned-bucket passes, and stable MFA/root fails — derived from a **real baseline run** (27497745357). **`scripts/assert_outcomes.py`** — dependency-free (no PyYAML); parses the `check.log` summary + the flat `policy_id: status` map, fails (exit 1) on any mismatch or absent policy (`pass` also accepts cadence `carried`). Wired an **"Assert expected outcomes"** step into `soc2-compliance.yml` after the check, before the `always()` teardown — the job now fails on unexpected outcomes. **Acceptance proven:** `tests/assert-outcomes-selftest.sh` (committed sample run `tests/fixtures/sample-check.log`) shows match → exit 0 and a flipped expectation → exit 1; also validated against the real baseline log (15/15 match). 🐞 **Found + fixed a pre-existing bug:** the workflow had been a **startup_failure on every push since `4d226bf`** because it requested `permissions: administration: read` — not a valid `GITHUB_TOKEN` scope (and unnecessary: org/branch reads use the `SIGCOMPLY_GH_TOKEN` PAT); removing it makes the workflow parse + schedule again. **Note:** the full E2E only runs green on **main pushes** (the 2026-06-14 success was push@main); feat-branch `pull_request`/`workflow_dispatch` runs now parse but fail at job-init (`steps=0`) due to a pre-existing repo branch/environment restriction — so the assert step will execute when this lands on `main`. Harness + acceptance are validated locally against real data.

### WU-5.2 — Minimize footprint / read-only collection
- Repo: **E2E GitHub** · Deps: WU-5.1
- [x] Default to `setup-aws-cheap.sh`; gate the full `setup-aws.sh` behind manual `workflow_dispatch` input only; confirm collection is read-only.
- Done 2026-06-28 (E2E GitHub repo, branch `feat/github-soc2-source`, commit `cc9b66c`). Added a `workflow_dispatch` boolean input **`full_setup`** (default false); provision + teardown each split into a **cheap (default)** path and a **FULL (manual-only)** path gated on `github.event.inputs.full_setup == 'true'`, so push/PR/normal-dispatch always use the cheap account-level set (a few cents) and the expensive EKS/RDS/MSK set ($50-200+/day) is opt-in only. **Read-only collection confirmed + documented** on the check step: `sigcomply check` issues only Describe/List/Get against infra (never mutates it); the only writes are to the customer's own S3 evidence vault (non-custodial model), with provisioning/teardown isolated to the setup/teardown steps. YAML validated. (Fixed 2026-06-29, E2E commit `16dc217`: both full scripts now default `EXPECTED_ACCOUNT_ID` to the current e2e account `935595347100`, overridable via `$E2E_ACCOUNT_ID`, keeping the wrong-account guard.)

### WU-5.3 — Sweeper
- Repo: **E2E GitHub** · Deps: WU-5.2
- [x] Add `scripts/sweep-aws.sh` (name-prefix `sigcomply-e2e-`, via `cloud-nuke`/`aws-nuke`) + a scheduled cleanup job as a leak backstop.
- Done 2026-06-28 (E2E GitHub repo, branch `feat/github-soc2-source`, commit `e9e152f`). `scripts/sweep-aws.sh` sweeps leaked `sigcomply-e2e-*` resources (S3 buckets, DynamoDB, ECR, KMS aliases, EC2 by Name tag, Lambda). **Deviation (deliberate, flagged):** hand-rolled targeted sweep instead of `cloud-nuke`/`aws-nuke` — an unscoped nuke on a **shared** AWS account (the recorder + admin live in 935595347100) is too dangerous. Safety: **dry-run by default** (`--force` to delete), **keeps** the persistent `sigcomply-e2e-vault`/`-manual` buckets, **age-guarded** (`SWEEP_AGE_HOURS`, default 2h, so an in-flight run isn't swept), **never** touches non-prefixed resources or account-level security toggles (GuardDuty/Security Hub — the run teardown owns those). `.github/workflows/sweep-aws.yml`: daily cron + `workflow_dispatch` (`force` input); scheduled runs delete, manual runs dry-run unless `force=true`; OIDC, skips if `AWS_ROLE_ARN` unset. **Validated:** dry-run runs clean against the real account (0 leaks — teardowns have been working) + the decision logic unit-checked (non-prefixed→ignore, persistent→keep, young→skip, old ephemeral→sweep). YAML validated; `bash -n` clean.

### WU-5.4 — Convert to scheduled + dispatch
- Repo: **E2E GitHub** · Deps: WU-5.1
- [x] Change `soc2-compliance.yml` trigger from push/PR to `schedule` (cron) + `workflow_dispatch`; keep teardown `if: always()`; add a budget-alert note.
- Done 2026-06-29 (E2E GitHub repo, branch `feat/github-soc2-source`, commit `1868c40`). `on:` changed from `push`/`pull_request` to **`schedule` (daily `0 5 * * *`) + `workflow_dispatch`** — each run spends real (small) AWS money, so it no longer fires per-commit; the leak sweeper (`sweep-aws.yml`) runs at 06:00 as a backstop. Teardown stays `if: always()`. Added a **budget-alert note** in the header: cheap set ≈ cents/run, the `full_setup` path is $50-200+/day → configure an AWS Budgets alarm so a stuck/leaked FULL run can't run up a silent bill. Scheduled runs carry no `inputs`, so they default to the cheap path. Bonus: this ends the noisy PR-context job-init failures (the pipeline only ever ran green on `main`). YAML validated.

### WU-5.5 — Docs
- Repo: **E2E GitHub** · Deps: WU-5.1..5.4
- [x] Update `CLAUDE.md`, `README.md`, `docs/AWS_OIDC_SETUP.md`; add `docs/EXPECTED_OUTCOMES.md` and a cost/cadence note; cross-link the CLI `11-testing-strategy.md`.
- Done 2026-06-29 (E2E GitHub repo, branch `feat/github-soc2-source`, commit `1729a42`). **`docs/EXPECTED_OUTCOMES.md`** (new): documents the assertion harness — `expected-outcomes.yaml`, `assert_outcomes.py`, the `[status] policy_id — control` parse, what's asserted + why it's deterministic (manual seed matrix + cheap-setup), the offline self-test, and how to re-baseline. **`README.md`**: scheduled+dispatch trigger, cheap-default/full-gated, read-only collection, the assertion step, + a "Cost & cadence" section (sweeper + budget alarm) + CLI testing-strategy cross-link. **`CLAUDE.md`**: How-It-Works (5 steps) + Workflow Environment Notes refreshed for the schedule, cheap default, sweeper, assertion step, read-only collection, account-suffixed-vs-persistent buckets, cost/cadence. **`docs/AWS_OIDC_SETUP.md`**: "Cost, cadence & cleanup" section + an `aws budgets create-budget` example. Cross-links to the CLI `11-testing-strategy.md` added (full URLs in the GitHub-rendered docs; relative path kept in CLAUDE.md per its sibling-repo convention).

### WU-5.6 — (Future) GCP + Azure E2E variants
- Repo: **E2E GitHub** · Deps: ~~GCP/Azure plugins shipped~~ **Unblocked** — the full GCP and Azure plugin sets shipped 2026-06-16/17 (integrations plan Phases 3–5); mirror WU-5.1..5.5.
- [x] Done 2026-06-29 (E2E GitHub repo, branch `feat/github-soc2-source`, commit `be673a4`) — **scaffolds** (live runs blocked by creds). Mirrored the Phase-5 AWS E2E for GCP + Azure: `.sigcomply.gcp.yaml` (18 gcp sources) + `gcp-compliance.yml` (WIF auth, skips without `GCP_WIF_PROVIDER`); `.sigcomply.azure.yaml` (13 ARM + entra) + `azure-compliance.yml` (SP/OIDC, skips without `AZURE_CLIENT_ID`); both **read-only** (neither can provision here), scheduled+manual, reuse `assert_outcomes.py` with `expected-outcomes-{gcp,azure}.yaml` baseline stubs (informational until a baseline row is added, then enforces); `docs/GCP_AZURE_E2E.md` documents the constraints + activation. **Blocked from live validation:** GCP org-locked (no SA key / impersonation / WIF here — L1/L2 cassettes cover the plugins); Azure authenticates (Reader SP) but the subscription is empty + no Contributor. YAML-validated.

---

## 13. Phase 6 — E2E GitLab repo from scratch (L4b)

Goal: bring the GitLab E2E repo to parity (it's currently a skeleton). Reuse GitHub patterns.

> **Phase 6 access note (2026-06-29):** the GitLab testing repo wasn't reachable from here — no authorized SSH key on gitlab.com, and the provided `glpat` is read-only (`read_repository`/`read_api`) scoped to the `sigcomply-e2e` *data* group, not the testing repo's namespace. So Phase 6 was **built locally** (clean per-WU commits in `/Users/sudo/Documents/sigcomply/sigcomply-cli-testing-project-gitlab`, a fresh `git init`) and is **pending the user's push** to the real GitLab repo (needs a write-scoped token or an authorized SSH key). All files validated locally.

### WU-6.1 — `.gitlab-ci.yml`
- Repo: **E2E GitLab** · Deps: WU-5.4 (pattern to copy)
- [x] Pipeline that `include:`s `sigcomply-cli/examples/gitlab-ci.yml`; OIDC via `$CI_JOB_JWT_V2`; scheduled pipeline; teardown always.
- Done 2026-06-29 (local commit `be4b8f6`). **Deviation (flagged):** did NOT `include:` `sigcomply-cli/examples/gitlab-ci.yml` — that example is **stale** (uses `--format json`/`--output` flags `check` no longer has + an `install.sigcomply.com` script). Instead mirrored the proven GitHub E2E flow in GitLab CI: one `soc2-compliance` job — installs the CLI release tarball + AWS CLI v2, OIDC via **`id_tokens`** (the modern replacement for the **removed** `CI_JOB_JWT_V2`; token written to a file the AWS SDK reads with `AWS_ROLE_ARN`), cheap AWS setup + manual seed in `before_script`, `sigcomply check` + assert in `script` (fails on drift), `teardown-aws-cheap.sh` in `after_script` (**always**). `workflow` rules gate to `schedule` + manual `web` only (never push/MR); an `AWS_ROLE_ARN` rule skips cleanly when OIDC isn't set up. A separate `sweep` job (`RUN_SWEEP=true` schedule) runs the leak backstop. YAML validated.

### WU-6.2 — `.sigcomply.yaml` (GitLab)
- Repo: **E2E GitLab** · Deps: WU-6.1
- [x] Policy-first vault layout; cloud submission **on** (per the repo's CLAUDE.md intent, unlike GitHub's `--no-cloud`).
- Done 2026-06-29 (local commit `df640e1`). `project.v1` config mirroring the GitHub E2E with the two intended differences: **`sources.gitlab: { group: sigcomply-e2e }`** (read_api PAT via `GITLAB_TOKEN`) replaces the GitHub source, and **`cloud: { enabled: true }`** (counts-only submission auto-authed by the CI OIDC token; `base_url` commented for the user to set). `gitlab-customer-simulation/` vault prefix separates evidence from the GitHub E2E in the shared account. AWS sources + manual + calendar-quarter period unchanged; bucket lines kept in the form the cheap-setup `sed` rewrites. YAML validated.

### WU-6.3 — Provisioning + teardown + sweeper
- Repo: **E2E GitLab** · Deps: WU-6.1
- [x] Adapt `scripts/*-aws*.sh` from the GitHub repo / `sigcomply-cli/scripts/e2e/`; add sweeper.
- Done 2026-06-29 (local commit `1b6e9f2`). Reused the proven, CI-agnostic AWS scripts (`setup-aws-cheap.sh`, `teardown-aws-cheap.sh`, `sweep-aws.sh`) — no GitLab changes needed (account derived at runtime, `sigcomply-e2e-` prefixed; cheap setup patches this repo's `.sigcomply.yaml` buckets + seeds the manual matrix). `.gitlab-ci.yml` calls setup/teardown around the check + runs the sweeper in the `sweep` job. `bash -n` clean. **Observed:** the `sigcomply-e2e` group holds two `*-deletion_scheduled-*` GitLab projects (GitLab-side leftovers) — read-only test data, not created by this repo's scripts, so the AWS sweeper leaves them.

### WU-6.4 — Assertion harness
- Repo: **E2E GitLab** · Deps: WU-6.2, WU-5.1
- [x] Reuse the `expected-outcomes.yaml` approach; assert per-policy outcomes (and, since cloud submission is on, optionally assert the `POST /api/v1/runs` payload shape is counts-only).
- Done 2026-06-29 (local commit `57bbddf`). Reused `expected-outcomes.yaml` + `scripts/assert_outcomes.py` + the self-test from the GitHub E2E (selftest passes here: match → exit 0, flip → exit 1). The deterministic **manual + AWS** expectations carry over (same cheap setup + seed matrix); the **gitlab-source** policy outcomes (branch protection/visibility from `e2e-protected`/`e2e-unprotected`) get added once a baseline GitLab run is captured. **Counts-only payload:** not re-asserted in the E2E by design — it's *structurally* guaranteed by the CLI submission type + the reflection test in `internal/core/cloud_test.go` (documented in CLAUDE.md), so the "optionally" is satisfied at the CLI layer.

### WU-6.5 — Docs
- Repo: **E2E GitLab** · Deps: WU-6.1..6.4
- [x] Fill `CLAUDE.md`, `README.md`; add OIDC/setup + cost docs mirroring the GitHub repo.
- Done 2026-06-29 (local commit `dcc7a76`). `README.md` + `CLAUDE.md` (GitLab flow: scheduled+manual, GitLab OIDC `id_tokens`, cheap-default, gitlab source, cloud-on, assertion step, sweeper, cost); `docs/AWS_OIDC_SETUP.md` (GitLab OIDC provider/trust/role + CI/CD variables + pipeline schedules + cost/cadence/budget); `docs/GITLAB_AUDIT.md` (read_api PAT + the `sigcomply-e2e` test-group data); reused `docs/EXPECTED_OUTCOMES.md` + `docs/MANUAL_EVIDENCE.md` (adapted to `.gitlab-ci.yml`). Cross-links the CLI `11-testing-strategy.md`.

---

## 14. Phase 7 — Consolidation & governance

Goal: make the new model the default and self-enforcing.

### WU-7.1 — Root cross-repo testing section
- Repo: **root** (`sigcomply-repositories/CLAUDE.md`)
- [x] Add a "Testing strategy (cross-repo)" section summarizing the layer/repo split and pointing to this plan + the CLI `11-testing-strategy.md`.
- Done 2026-06-29. Added a **"Testing Strategy (Cross-Repo)"** section to the root `CLAUDE.md` (`/Users/sudo/Documents/sigcomply/CLAUDE.md`): the L0–L4b layer table (what/cost/where), the CLI-owns-L0–L4a / E2E-repos-own-L4b split, the coverage-gate scope, and the add-a-plugin requirement; cross-links `11-testing-strategy.md` + this tracker. **Note:** that path's git toplevel is the user's home repo (`/Users/sudo`, no SigComply remote), so the edit is **not committed** to a versioned SigComply repo here — it's the canonical content for whatever hosts the root meta-CLAUDE.md.

### WU-7.2 — CONTRIBUTING / Development Rules update
- Repo: **CLI**
- [x] Add `CONTRIBUTING.md` (or extend `CLAUDE.md` Development Rules): a new source plugin MUST add L0/L1/L2 + cassettes + `contracts/` entry; PR template checkbox for "conformance test + cassette + spec snapshot added."
- Done 2026-06-29 (CLI commit `d2406eb` on `main`). `CONTRIBUTING.md`: dev-rules summary + the testing-layer→Make-target table + the **non-negotiable** requirement that a new/changed source plugin ship L0/L1 unit + an L2 conformance test with a scrubbed cassette + a `contracts/<provider>/<service>` snapshot in the same PR (cross-links `11-testing-strategy.md` + `recipes.md`). `.github/pull_request_template.md`: a checklist with the "conformance test + cassette + spec snapshot added" boxes (+ a counts-only guard for `internal/core/cloud*` changes).

### WU-7.3 — Finalize Makefile targets
- Repo: **CLI**
- [x] Add `test-contract`, `test-live` (build-tag `live`), `contracts-fetch`, `contracts-diff`; ensure `ci`/`pre-commit` exclude `live`.
- Done 2026-06-29 (CLI commit on `main`). Added **`make test-contract`** (`go test -run Conformance ./internal/sources/...` — 70 conformance tests, green). `test-live` (WU-4.1), `contracts-fetch`/`contracts-diff` (WU-3.1/3.2) already existed. Confirmed `ci` (`deps lint test build`) and `pre-commit` (`fmt-check vet lint check-fixtures test-unit`) carry **no `-tags live`**, so live is excluded from both.

### WU-7.4 — Coverage & gate policy
- Repo: **CLI**
- [x] Confirm `live`/E2E excluded from the 80% gate; document the policy in `11-testing-strategy.md`.
- Done 2026-06-29 (CLI commit on `main`). **Confirmed:** CI's coverage run (`go test -race -coverprofile … ./...`, threshold 80 in `test.yml`) and `make ci`/`pre-commit` carry no `-tags live`, so `//go:build live` tests aren't compiled into the coverage number and the L4b E2E suites are in separate repos — the floor measures exactly the L0–L3 in-repo tests. Made this explicit in `11-testing-strategy.md` §Coverage.

---

## 15. Tracking dashboard

> Update this table as the single at-a-glance status. Mirror each WU's inline checkbox.

| WU | Repo | Title | Deps | Status |
|----|------|-------|------|--------|
| 0.1 | CLI | Canonical testing doc | — | [x] |
| 0.2 | CLI | Ratify conventions | 0.1 | [x] |
| 0.3 | CLI | Secret/PII fixture gate | 0.2 | [x] |
| 1.1 | CLI | Conformance harness | 0.2 | [x] |
| 1.2 | CLI | go-vcr + HTTP wiring | 1.1 | [x] |
| 1.3 | CLI | GitHub cassettes + test | 1.2 | [x] |
| 1.4 | CLI | GitHub fixture-vs-spec | 1.3 | [x] |
| 1.5 | CLI | Plugin testing checklist (docs) | 1.3,1.4 | [x] |
| 2.1 | CLI | AWS cassette wiring | 1.2 | [x] |
| 2.2 | CLI | AWS identity group | 2.1 | [x] |
| 2.3 | CLI | AWS data/storage group | 2.1 | [x] |
| 2.4 | CLI | AWS compute group | 2.1 | [x] |
| 2.5 | CLI | AWS logging/monitoring group | 2.1 | [x] |
| 2.6 | CLI | AWS security group | 2.1 | [x] |
| 2.7 | CLI | GCP wiring + plugins | 1.2 | [x] |
| 2.8 | CLI | Okta plugin | 1.2 | [x] |
| 2.9 | CLI | Manual evidence plugin | 1.1 | [x] |
| 2.10 | CLI | GitLab plugin | 1.2 | [x] |
| 2.11 | CLI | GCP expansion (Wave 1+2) | 2.7 | [x] |
| 2.12 | CLI | Azure ARM-plane group | 1.2 | [x] |
| 2.13 | CLI | Azure Entra group | 2.12 | [x] |
| 3.1 | CLI | contracts/ + fetch | 2.* | [x] |
| 3.2 | CLI | contracts-diff | 3.1 | [x] |
| 3.3 | CLI | Drift workflow (alert) | 3.2 | [x] |
| 3.4 | CLI | Drift triage runbook (docs) | 3.3 | [x] |
| 4.1 | CLI | Live convention + gating | 1.1 | [x] |
| 4.2 | CLI | GitHub live | 4.1 | [x] |
| 4.3 | CLI | GitLab live | 4.1 | [x] |
| 4.4 | CLI | Okta live | 4.1 | [x] |
| 4.5 | CLI | Entra live | 4.1 (Azure `azure.entra` plugin now exists, 2026-06-17) | [x] |
| 4.6 | CLI | Live + re-record workflow | 4.2-4.4 | [x] |
| 5.1 | E2E-GH | Assertion harness | — | [x] |
| 5.2 | E2E-GH | Minimize footprint | 5.1 | [x] |
| 5.3 | E2E-GH | Sweeper | 5.2 | [x] |
| 5.4 | E2E-GH | Scheduled + dispatch | 5.1 | [x] |
| 5.5 | E2E-GH | Docs | 5.1-5.4 | [x] |
| 5.6 | E2E-GH | GCP+Azure variants | 5.1 (GCP + Azure plugins now exist, 2026-06-17) | [x] |
| 6.1 | E2E-GL | .gitlab-ci.yml | 5.4 | [x] |
| 6.2 | E2E-GL | .sigcomply.yaml | 6.1 | [x] |
| 6.3 | E2E-GL | Provision+teardown+sweep | 6.1 | [x] |
| 6.4 | E2E-GL | Assertion harness | 6.2,5.1 | [x] |
| 6.5 | E2E-GL | Docs | 6.1-6.4 | [x] |
| 7.1 | root | Cross-repo testing doc | — | [x] |
| 7.2 | CLI | CONTRIBUTING / rules | — | [x] |
| 7.3 | CLI | Makefile targets | 3.2,4.1 | [x] |
| 7.4 | CLI | Coverage policy | 4.1 | [x] |

**Suggested critical path:** 0.1 → 0.2 → 0.3 → 1.1 → 1.2 → 1.3 → 1.4 → 1.5 (backbone proven) → Phase 2 rollout (parallelizable) → Phase 3 (drift) → Phase 4 (live) → Phase 5 (E2E GH) → Phase 6 (E2E GL) → Phase 7 (governance). Phases 5/6 can proceed in parallel with Phase 2 once 5.1's run-output dependency is stable.

---

## 16. Risks, decisions & open questions

- **Recording cloud cassettes needs *some* live access.** Resolution: record during an L4b run or a one-off maintainer record; hand-authored fixtures from real responses are an acceptable bootstrap (refined later). This is the soft dependency between Phase 2 (AWS/GCP) and Phase 5.
- **Spec-diff catches shape, not behavior.** That gap is exactly what L4a/L4b cover. Keep both — never drop the live layer entirely.
- **Cassette staleness.** Mitigated by L2 fixture-vs-spec conformance (a moved spec fails the cassette) + the L4a scheduled re-record-and-diff.
- **LocalStack/Moto are NOT drift detectors** and LocalStack's free tier is restricted — use Moto/Azurite/fake-gcs-server only for storage list/merge logic, never as a contract oracle. (No L-layer depends on them.)
- ~~**Open — Entra/Azure ordering:** WU-4.5 and WU-5.6 are blocked on the Azure/GCP source plugins existing.~~ **Resolved 2026-06-18** — the source-integrations plan (`core_source_integrations_plan.md`) landed all GCP and Azure plugins first (Phases 3–5, done 2026-06-16/17), so WU-4.5 and WU-5.6 are now unblocked. The new plugins also need L1/L2 coverage — see WU-2.10–2.13.
- **Open — GitLab cloud submission in E2E:** WU-6.2 turns cloud submission on. Confirm the Rails test tenant + OIDC validator are ready to receive `POST /api/v1/runs` from the GitLab CI JWT before enabling.
- **Open — where do free-account secrets live?** GitHub/GitLab/Okta/Entra tokens for L4a must be stored as repo/org secrets with rotation. Decide ownership in WU-4.6.

---

## 17. Definition of done (whole revamp)

- Every source plugin has L0+L1+L2 coverage via `sourcetest`, with redaction-clean cassettes and a `contracts/` snapshot.
- A scheduled drift job opens an issue when any used vendor spec changes.
- A scheduled live job exercises every free-account vendor and re-records cassettes.
- Both E2E repos provision minimal real infra, run the released binary, and **assert expected per-policy outcomes**, with sweepers preventing leaks.
- Testing guidance is documented in the CLI repo, both E2E repos, and the root, and adding a new plugin without its tests is blocked by CONTRIBUTING + PR template.
- Per-PR CI stays fast, free, deterministic, and ≥80% covered; cost is confined to bounded scheduled jobs.
