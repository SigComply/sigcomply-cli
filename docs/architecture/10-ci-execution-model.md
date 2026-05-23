# 10 — CI Execution Model

The CLI is a leaf invocation: it reads project config, fetches evidence,
evaluates policies, writes the vault, and submits aggregated counts.
Everything *above* the CLI — when each policy runs, on what cadence, in
which CI job — lives in CI workflow files inside the customer's repo.

This document specifies how the pieces fit together: the project ↔ repo
identity, the pipeline ↔ workflow correspondence, how cadence drives
scheduling without violating the stateless-CLI property, and the
canonical workflow set the framework ships.

---

## The execution hierarchy

```
Project    = one source-control repository (GitHub or GitLab)
   ↳ Pipelines = CI workflow files inside that repo, scheduled by cron
       ↳ Jobs   = individual CLI invocations within a pipeline
           ↳ Policy evaluations = per-policy fetch + check + persist
```

Reading top-down:

- **A project** maps 1:1 with a source-control repository. The repo's
  `org/name` is the project identity. The project's `.sigcomply.yaml`
  lives at the repo root. The project pursues exactly one compliance
  framework.
- **A project has multiple pipelines** — one per scheduling cadence
  the framework requires. The framework spec drives which cadences
  exist; the customer copies (or scaffolds) the matching workflow files
  into their repo.
- **A pipeline contains one or more jobs**. v1 ships one job per
  pipeline. v2 may shard for parallelism (see §Sharding).
- **A job runs one CLI invocation**. The invocation evaluates a set of
  policies filtered by cadence or explicit list.
- **A CLI invocation evaluates each requested policy independently**:
  fetch → check → persist. Per-policy failures never short-circuit
  others.

---

## One project = one framework

This is a hard rule for v1.

- A project's `.sigcomply.yaml` declares exactly one `framework:`.
- Every workflow file in the project invokes the CLI against that one
  framework.
- The vault under that project holds only evidence for that framework.

Customers pursuing multiple frameworks (SOC 2 + ISO 27001, or SOC 2 +
HIPAA) typically use **multiple repositories** — one per framework.
This is the cleanest separation: distinct CI scopes, distinct evidence
vaults, distinct auditor packages.

The less common alternative — two configs in one repo, invoked via
`--config .sigcomply-iso.yaml` from separate workflow files — is
possible but not the canonical pattern. It complicates auditor review
and risks cross-contamination between frameworks. The framework
scaffolding (`sigcomply init-ci`) assumes the canonical one-framework
shape.

---

## Cadence: the orchestration key

Every policy declares its natural **cadence** — how often it must be
evaluated. Values:

| Cadence | Meaning | Typical examples |
|---|---|---|
| `continuous` | On every commit / PR push | High-risk policies sensitive to code changes (e.g. branch protection rules) |
| `hourly` | At least every hour | Real-time security drift checks (rarely used) |
| `daily` | At least every day | Most automated checks: MFA enforced, encryption at rest, log forwarding |
| `weekly` | At least every week | Audit log retention drift, access review reminders |
| `monthly` | At least every month | Periodic config audits |
| `quarterly` | At least every quarter | Quarterly access reviews, vendor risk assessments |
| `annual` | At least once a year | Annual security training, BCP test, board approval of policies |

Each shipped policy declares one cadence as a sensible default.
Project config can override per policy:

```yaml
# .sigcomply.yaml (excerpt)
policy_cadences:
  soc2.cc6.1.mfa_enforced: hourly        # stricter than the shipped default (daily)
  soc2.cc6.1.access_review: monthly      # stricter than the shipped default (quarterly)
```

Cadence is **metadata**, not enforcement. The CLI accepts a filter
flag (`--cadence X` or `--on-push`) and runs only matching policies.
It never says "this policy already ran today, skip." That decision
belongs to the CI scheduler.

---

## How statelessness survives cadence

The hard question: if the CLI keeps no state across runs, how does a
project know that a quarterly policy doesn't need to re-run daily?

**Answer**: it doesn't, and it doesn't need to. The CI cron schedule
*is* the cadence enforcement.

- The daily-cadence policies run because the `compliance-daily.yml`
  workflow has `cron: '0 3 * * *'`.
- The quarterly-cadence policies run because the
  `compliance-quarterly.yml` workflow has `cron: '0 4 1 1,4,7,10 *'`.
- A quarterly policy doesn't re-run daily because there's no daily
  workflow that asks for it.

The CLI is asked to do less work in the quarterly cron than the daily
cron, because the workflow file passes `--cadence quarterly` and the
filter selects only the ~20 quarterly policies. The CLI doesn't need
to remember that those 20 policies "already ran" three months ago —
the next quarterly cron is three months away.

What about re-running after a fix? Operators trigger the workflow
manually (`workflow_dispatch` on GitHub, manual pipeline trigger on
GitLab). No CLI state involved. The new invocation produces a new run
folder in the vault; the period's roll-up reflects the latest result
(see [`05-vault-layout.md`](05-vault-layout.md) §Period state).

What about a CI scheduler that misses a cron (CI provider outage,
runner queue starvation)? The cadence is "*at least*" the declared
interval. If the daily cron misses Tuesday, Wednesday's run still
covers Tuesday's evidence — the period roll-up doesn't care which
specific day within the period produced the result. (For ultra-
sensitive policies, customers can also wire those into
`compliance-on-push.yml` so they run on every commit as well as on
cron.)

---

## The canonical workflow set per framework

When a customer runs `sigcomply init-ci --framework soc2 --ci github`,
the CLI scaffolds a set of workflow files calibrated to that
framework's cadence distribution. For SOC 2:

```
.github/workflows/
   compliance-on-push.yml      # PR + main push (~5 min target runtime)
   compliance-daily.yml        # 03:00 UTC daily cron
   compliance-weekly.yml       # Monday 04:00 UTC weekly cron
   compliance-monthly.yml      # 1st of month 04:00 UTC
   compliance-quarterly.yml    # Jan 1 / Apr 1 / Jul 1 / Oct 1 at 04:00 UTC
   compliance-annual.yml       # Jan 1 at 05:00 UTC
```

For ISO 27001, the set may differ if the framework has different
cadence distributions (e.g. no quarterly cadence in the shipped
policies).

Each workflow has the same shape:

- Triggered by a cron schedule (and `workflow_dispatch` for manual
  trigger)
- Sets up credentials via OIDC (no long-lived secrets)
- Calls `sigcomply check --cadence <X>` (or `--on-push` for the
  PR variant)

For GitLab CI, the structure is `rules: - if: $CI_PIPELINE_SOURCE ==
"schedule"` patterns inside `.gitlab-ci.yml`, or a multi-pipeline
setup with `include:`.

### Example: `compliance-daily.yml` (GitHub Actions)

```yaml
name: Compliance — Daily
on:
  schedule:
    - cron: '0 3 * * *'
  workflow_dispatch:

permissions:
  id-token: write    # for SigComply Cloud OIDC submission
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      - uses: SigComply/sigcomply-cli/.github/actions/check@v1
        with:
          cadence: daily
```

### Example: `compliance-on-push.yml`

```yaml
name: Compliance — On Push
on:
  push:
    branches: [main]
  pull_request:

permissions:
  id-token: write
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      - uses: SigComply/sigcomply-cli/.github/actions/check@v1
        with:
          on-push: true
```

The on-push variant typically completes in 3–10 minutes — fast
enough not to slow PRs down. Manual evidence policies are excluded
by the `--on-push` filter (they're marked `on_push: false` by default,
since uploading a PDF on every PR is not the workflow).

### Example: `compliance-quarterly.yml`

```yaml
name: Compliance — Quarterly
on:
  schedule:
    - cron: '0 4 1 1,4,7,10 *'  # Jan 1, Apr 1, Jul 1, Oct 1
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      - uses: SigComply/sigcomply-cli/.github/actions/check@v1
        with:
          cadence: quarterly
```

If the quarterly access-review PDF is missing, the CLI fails this job
with exit code 1 and a missing-evidence message (see
[`04-source-plugins.md`](04-source-plugins.md) §Missing evidence).
Operators upload the PDF and re-run the workflow via
`workflow_dispatch`. The framework does not assume the quarterly cron
date is when the human action happens — operators upload whenever
they need to and re-run the workflow.

---

## Filter flags: how the CLI knows what to run

Inside a job, exactly one of these flags drives policy selection:

| Flag | What it selects |
|---|---|
| `--cadence <X>` | Policies whose **effective** cadence equals `<X>`. Effective cadence = project override if present, else framework default. |
| `--on-push` | Policies whose `on_push` attribute is `true`. Defaults: `true` for automated policies, `false` for manual. |
| `--policies <id,...>` | Explicit list. Used for ad-hoc re-runs of specific policies. |
| `--controls <id,...>` | All policies contributing to the listed controls. |

If none is provided, the CLI evaluates **all** policies. Useful for
local development and full-coverage cron jobs; not recommended for
production CI.

These filters are exclusive — exactly one applies per invocation.
Combining them is not supported in v1 (avoid filter-composition
ambiguity).

---

## Policy result vs job result vs run state

Three distinct concepts. Confusing them produces bad CI ergonomics.

| Concept | Where it lives | Values | Affects what |
|---|---|---|---|
| **Policy result** | `policies/<id>/result.json` in the vault | `pass | fail | skip | error | na | waived` | Period roll-up state |
| **Run summary** | `summary.json` in the run folder | aggregate counts | Period roll-up; dashboard rendering |
| **Job exit code** | CLI process exit | `0 | 1 | 2 | 3` | CI pipeline pass/fail UI |

Within a CLI invocation:

1. Every requested policy runs to completion: fetch → check → persist
   envelope + result. Even when many fail, all run.
2. The vault always receives results, whether the run "passed" or
   "failed" overall.
3. The cloud submission (if enabled) happens whether the run passed
   or failed.
4. After all policies finish, the orchestrator computes the exit code
   from the run's aggregate statuses according to project config:
   - `ci.fail_on_violation: false` → always exit 0
   - `ci.fail_on_violation: true` (default) → exit 1 if any policy
     of severity ≥ `ci.fail_severity` failed; exit 0 otherwise

Exit codes:

| Code | Meaning |
|---|---|
| `0` | All policies passed (or were NA / waived) at the configured fail threshold. |
| `1` | At least one policy failed at-or-above the configured fail severity. |
| `2` | Unexpected execution error (panic, network catastrophe). |
| `3` | Configuration or planning error. |

A `1` is **not** a failure of the SigComply system; it's a successful
report of failing compliance state. The vault is fully populated. The
cloud submission is complete. The customer sees red in CI; they fix
the underlying issue; they re-run the workflow.

A `2` or `3` *is* a failure of the system. The vault may be incomplete
(planning errored before persistence) or the run may have crashed
mid-flight. These are exceptional and require operator investigation.

---

## Sharding (v1: none; v2: optional)

For v1, **one cadence = one CI job**. With ~200 daily-cadence policies
and per-policy fetching (no shared collection), a daily job typically
runs in 15–25 minutes. Acceptable for daily cron; tight for on-push.

If on-push runtime becomes an issue, v2 introduces sharding:

```yaml
# compliance-on-push.yml (v2 sketch)
jobs:
  check-aws:
    steps:
      - uses: SigComply/sigcomply-cli/.github/actions/check@v2
        with:
          on-push: true
          source-prefix: "aws.*"
  check-github:
    steps:
      - uses: SigComply/sigcomply-cli/.github/actions/check@v2
        with:
          on-push: true
          source-prefix: "github,okta"
  check-other:
    steps:
      - uses: SigComply/sigcomply-cli/.github/actions/check@v2
        with:
          on-push: true
          source-prefix: "!aws.*,!github,!okta"
```

Multiple jobs run in parallel; each writes its own run folder; the
period roll-up unions them. The vault layout already supports this
(see [`05-vault-layout.md`](05-vault-layout.md) §Per-run folder).
The CLI does not need to know about sharding peers — each shard is a
fully independent invocation.

Hash-based sharding (`--shard 1 --shard-count 4`) is also possible
but offers less semantic clarity than source-based sharding.

---

## Scaffolding: `sigcomply init-ci`

The CLI ships a scaffolding command:

```bash
sigcomply init-ci --framework soc2 --ci github
```

Effects:

1. Creates `.github/workflows/compliance-*.yml` files calibrated to
   the selected framework's cadence distribution.
2. Creates a `.sigcomply.yaml` skeleton at the repo root if none
   exists.
3. Prints next steps: configure secrets, configure the AWS role,
   commit.

For GitLab:

```bash
sigcomply init-ci --framework soc2 --ci gitlab
```

Produces `.gitlab-ci.yml` with the equivalent multi-pipeline structure.

The scaffolded files are starter templates. Customers can modify them
freely (cron times, runner types, env vars, additional steps). The
shipped templates assume:

- OIDC-based credential setup for AWS, GCP, Azure
- Single AWS account, single GCP project, single GitHub org (matching
  the single-scope v1 design)
- Vault credentials available via OIDC role assumption
- SigComply Cloud submission enabled (commented-out `--no-cloud`
  option for customers who don't want it)

---

## Identity: project, run, evidence

The CI layer establishes three identities the CLI consumes:

- **Project identity** (`org/name` from the CI's repo metadata) →
  stamped into vault paths and submission payload as `repository.name_slug`.
- **CI invocation identity** (`run_id` from the CI provider) →
  stamped into the run manifest under `ci_environment.run_id`. Lets
  auditors correlate vault folders with CI job logs.
- **Commit identity** (`commit_sha`, `commit_time` from git) → stamped
  into vault and submission. The commit time drives period derivation.

These identities flow from CI → CLI via environment variables or the
CI provider's API. Different providers expose them differently;
`internal/core/cli/environment.go` normalizes them.

---

## What the CI layer DOESN'T do

Things to keep out of the workflow files; the CLI handles them
internally:

- **Policy selection per CI event.** Workflow files set `cadence:` or
  `on-push: true`; the CLI does the policy filtering. Don't enumerate
  policies in YAML.
- **Per-policy retry.** The CLI handles partial failures; CI doesn't
  need retry logic at the job level.
- **Evidence collection coordination.** No shared evidence cache, no
  pre-fetch step. The CLI fetches per-policy inside the same job.
- **Period derivation.** The CLI computes the period from commit time
  and project config. Workflow files don't compute or pass the
  period.

The principle: CI files describe *when* to run; the CLI describes
*what* to run and *how*. Crossing this line creates implicit state
and breaks the stateless property.

---

## Auditor view of the CI layer

When an auditor evaluates a project's compliance posture, the CI
workflow files are part of what they review. Specifically:

- **Cadence verification**: does `compliance-quarterly.yml` actually
  run quarterly? Read the cron.
- **Coverage verification**: do all framework-required cadences have
  workflows in the repo? Compare against the shipped scaffold.
- **Modification detection**: have workflows been modified to skip
  certain policies? `git log` on the workflow files.
- **Exception traceability**: if a quarterly policy has been "skipped"
  for three quarters, did the workflow file change? Did a
  `policy_cadences:` override appear? Did an exception get added?

The workflow files, like `.sigcomply.yaml` and any custom policies
under `.sigcomply/`, are part of the project's audit trail and live
in git.

---

## See also

- [`01-conceptual-model.md`](01-conceptual-model.md) — the Project,
  Period, Run, and Policy cadence abstractions.
- [`03-policy-spec.md`](03-policy-spec.md) — `cadence` and `on_push`
  fields in `policy.yaml`.
- [`05-vault-layout.md`](05-vault-layout.md) — how multiple runs
  within a period interact.
- [`08-project-config.md`](08-project-config.md) — `policy_cadences:`
  overrides and CLI flags.
- [`09-implementation-roadmap.md`](09-implementation-roadmap.md) — the
  M19 milestone covers `init-ci` scaffolding and CI integration tests.
