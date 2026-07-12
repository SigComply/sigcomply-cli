# Development Workflow (end-to-end)

> **When to read**: Before starting any engineering task in this repo —
> "implement feature X", "fix bug Y", "add source/policy Z". This is the
> canonical procedure. [CLAUDE.md → Development Rules](../../CLAUDE.md#development-rules)
> is the one-paragraph summary; this doc is the expanded loop.

## How we work

The SigComply CLI's SDLC is run almost entirely by **Claude Code agents**
running in CMUX. There is no manual engineering: coding, tests, planning,
design, manual verification, and debugging are all performed by agents.
The human's role is to **direct, monitor, and verify** — not to type code.

Two facts shape every task:

- **Pre-launch.** The product has no users and no production service yet
  (an initial no-card trial for 2–3 early customers is months out). Until
  public launch, internal work commits **directly to `main`** once tests
  pass — no PRs, no reviews (see [Ship](#6-commit--push)). This changes to
  a PR + review flow at public launch; this doc gets revised then.
- **No web UI.** This is a CLI binary, not a service. "Verify" means
  *build the binary and run the affected command* (see
  [Verify](#4-verify)), never a browser click-through. There is no Render
  deploy, no database, no Sentry — do not import those assumptions from
  the Rails dashboard repo.

## The loop at a glance

1. **[Plan / design](#1-plan--design)** — read the relevant doc; if it feels complex, stop and ask.
2. **[Write tests first](#2-write-tests-first)** — unit → integration, per the L0–L4b strategy.
3. **[Implement](#3-implement)** — minimum code to pass.
4. **[Verify](#4-verify)** — `make test && make lint`, then build and exercise the CLI.
5. **[Update docs](#5-update-docs-definition-of-done)** — guideline **and** codebase docs. Not optional.
6. **[Commit & push](#6-commit--push)** — directly to `main` (pre-launch).

A change is **not done** until steps 4 and 5 both hold. "Green tests" alone
is not done; "docs left stale" is not done.

---

### 1. Plan / design

Read the architecture doc that owns the area you're touching **before**
writing anything ([`docs/architecture/`](../architecture/) index in
[ARCHITECTURE.md](../../ARCHITECTURE.md)). If the design feels overly
complex, that difficulty is a signal to **pause and ask**, not push
through. For an "add a source / policy / evidence type / framework / vault
backend" task, the step-by-step is [recipes.md](./recipes.md) — start
there.

Respect the [Sacred Invariants](../../CLAUDE.md#sacred-invariants). If a
plan would let a resource identifier reach the cloud payload, invent an
evidence sub-type in the evaluator, sign a hash, or make a policy name a
plugin — stop; it's an architectural break.

### 2. Write tests first

TDD is non-negotiable. Write the failing test before the implementation:

- **L0/L1 unit** first (fake API client, deterministic `Now` seam), then a
  happy-path integration test.
- New/changed **source plugins** additionally require an **L2 conformance
  test + scrubbed cassette** and an **L3 `contracts/` snapshot** in the
  same change — this is gated, not optional. See
  [CONTRIBUTING.md](../../CONTRIBUTING.md) and the layered strategy in
  [TESTING.md](../../TESTING.md) /
  [11-testing-strategy.md](../architecture/11-testing-strategy.md).
- Touching the cloud submission contract (`internal/core/cloud*`)? The
  counts-only reflection test (`internal/core/cloud_test.go`) must stay
  green, and you must check the matching Rails strong-params in the
  `../sigcomply/` repo (cross-repo step — see [Invariant #1](../../CLAUDE.md#sacred-invariants)).

### 3. Implement

Write the minimum code to pass the tests. Match the surrounding code's
idiom, naming, and comment density. Keep the change one logical unit.

### 4. Verify

Two gates, both required:

**Automated.**
```
make test && make lint
```
`make test` is the fast per-change backbone (L0/L1/L2, 80% coverage
floor); `make ci` mirrors the full per-PR gate locally.

**Manual — exercise the built binary.** There is no UI to click, so
verification is running the CLI and reading its output:
```
make build
```
then run the command your change affects and inspect the result:

| Change touches… | Run | Check |
|-----------------|-----|-------|
| a source/policy/evaluator | `sigcomply check` against a fixture/scratch project (or an [E2E repo](#e2e-repos)) | stdout run summary, **exit code** (0 pass / 1 violations / 2 exec error / 3 config error), vault artifacts under `{framework}/{period_id}/run_*/` |
| the manual-evidence catalog / SPA contract | `sigcomply evidence catalog -o json` | JSON matches `sigcomply-evidence-spa/src/types/catalog.ts` |
| the auditor read path | `sigcomply report` | snapshot renders from the vault |
| CLI scaffolding | `sigcomply init-ci` in a scratch dir | workflow files written as expected |
| version/build wiring | `sigcomply version` | version + commit + build time |

The `/verify` and `/run` skills automate "build and drive the CLI to see
the change working" — prefer them over ad-hoc invocation when the change
has a runtime surface.

<a id="e2e-repos"></a>For source-plugin or CI-integration changes that
need real infrastructure, the L4b E2E repos run the **released binary**
end-to-end:
[`sigcomply-cli-testing-project-github`](https://github.com/SigComply/sigcomply-cli-testing-project-github)
and
[`sigcomply-cli-testing-project-gitlab`](https://gitlab.com/sigcomply/sigcomply-cli-testing-project-gitlab)
(cloned at `../sigcomply-cli-testing-project-*`).

### 5. Update docs (definition of done)

**Document-driven development.** Every unit of work updates the docs it
touches — this is part of "done", not later cleanup. Update the *specific*
focused doc(s) your change affects; the just-in-time model means you touch
the one that owns the area, not a monolith:

- **New "add-a-thing" pattern or changed procedure** → [recipes.md](./recipes.md)
- **New/changed flag, env var, or config key** → [docs/configuration.md](../configuration.md)
- **Architecture / layer / contract change** → the relevant [`docs/architecture/`](../architecture/) doc **and** [ARCHITECTURE.md](../../ARCHITECTURE.md)
- **New command or changed command behavior** → the CLI Interface table in [CLAUDE.md](../../CLAUDE.md#cli-interface) + [docs/configuration.md](../configuration.md)
- **Cross-repo contract** (cloud payload, catalog export, OIDC claims) → note the matching change needed in `../sigcomply/` or `../sigcomply-evidence-spa/`
- **Process / workflow change** → this doc, [CONTRIBUTING.md](../../CONTRIBUTING.md), or [TESTING.md](../../TESTING.md)

If your change is purely internal with no behavioral or architectural
surface, a doc update may genuinely not be needed — but that is the
exception you justify, not the default you assume.

### 6. Commit & push

**Pre-launch (now): commit directly to `main`.** Once `make test && make
lint` are green and manual verification passes:

- Small **atomic** commits — one logical change each, all tests passing.
- Format `<type>: <description>` (`feat`/`fix`/`refactor`/`test`/`docs`/`chore`),
  with a `Co-Authored-By: Claude <model> <noreply@anthropic.com>` trailer.
- Push to `main`, then **confirm CI is green** (`gh run list` /
  `gh run view`). Never move on while CI is red — a red `main` blocks
  everyone.

**No backward-compatibility burden pre-launch.** There is no production
database and no released install base to protect. Cadence/scheduling state
files are recoverable by design (loss ⇒ next run = first-run), so there is
**no state-migration story** to write — do not add backfills or
compatibility shims for local state. **Exception — cross-repo contracts
still must stay in lockstep:** the counts-only cloud payload, the catalog
export, and OIDC claims are [Invariants](../../CLAUDE.md#sacred-invariants)
guarded by `contract-drift.yml` and the reflection test. Touch one side →
check the other.

**A push to `main` auto-cuts a release.** `auto-release.yml` runs on every
push to `main`: it derives the version bump from your commit's
conventional-commit prefix (`feat`→minor, `fix`/`refactor`/`perf`→patch,
`BREAKING CHANGE` in the body→major), tags, and runs GoReleaser to publish
binaries (with build-provenance attestations) to GitHub Releases. Your
commit **type** therefore chooses the version bump — pick it deliberately.
**Doc-only pushes** (`*.md`, `docs/**`) are path-ignored and cut no
release, so process/docs work never triggers a version bump.

**Post-launch (future): open a PR.** After public launch, internal work
moves to PRs with review, using the checklist in
[`.github/pull_request_template.md`](../../.github/pull_request_template.md).
That template already governs **external** contributions today. This doc
will be revised when the switch happens.

---

## Debugging a failing check or CI run

Agents own debugging too (no Render console, no Sentry — this is a Go CLI):

1. **Reproduce deterministically.** Turn the failure into a failing
   unit/contract test or replay the relevant scrubbed cassette
   (`make test-contract`). A bug without a reproducing test isn't
   understood yet.
2. **Read the run output.** `sigcomply check` writes a run log and a
   fixed text summary; the exit code localizes the class (2 = execution,
   3 = config). Vault artifacts under `{framework}/{period_id}/run_*/`
   show exactly what was collected, evaluated, and signed.
3. **CI failures:** `gh run list` → `gh run view <id> --log-failed`.
   Reproduce the same gate locally with `make ci`.
4. **End-to-end / real-infra failures** reproduce in the [E2E repos](#e2e-repos)
   against the released binary — that's where L4b lives.
5. Fix → re-run [Verify](#4-verify) → [update docs](#5-update-docs-definition-of-done)
   if behavior or architecture moved → commit.
