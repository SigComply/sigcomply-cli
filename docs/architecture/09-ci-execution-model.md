# 09 — CI Execution Model

The CLI is a leaf invocation: it reads project config, fetches evidence,
evaluates policies, writes the vault, and submits aggregated counts.
Everything *above* the CLI — when each policy runs, on what cadence, in
which CI job — lives in CI workflow files inside the customer's repo.

This document specifies how the pieces fit together: the project ↔ repo
identity, the pipeline ↔ workflow correspondence, how cadence drives
scheduling without violating the stateless-CLI property, and the
per-cadence workflow set `sigcomply init-ci` scaffolds.

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
| `every:<duration>` | Custom interval (`every:6h`, `every:90m`) | Power-user tuning: tighter than `hourly`, gentler than `daily`. Floor: 5 minutes. |

Each shipped policy declares one cadence as a sensible default.
Project config can override per policy:

```yaml
# .sigcomply.yaml (excerpt)
policies:
  soc2.cc6.1.mfa_enforced:
    cadence: every:6h       # tighter than the shipped default (daily)
  soc2.cc6.1.access_review:
    cadence: monthly        # stricter than the shipped default (quarterly)
```

---

## How cadence enforcement actually works

Two complementary mechanisms drive cadence; the scaffolded templates
use the **per-cadence cron** approach.

1. **Per-cadence cron (what `init-ci` scaffolds).** One workflow per
   cadence, each firing on its own cron and passing the matching
   `--cadence <X>` filter (`--cadence daily` on the daily cron,
   `--cadence quarterly` on the quarterly cron, and so on). The cron
   schedule decides *when* the cadence's policy set is invoked; `--cadence`
   selects *which* policies that invocation evaluates. The scaffolded
   workflows do **not** pass `--scheduled`.
2. **State-gated `--scheduled` (available, not scaffolded).** A single
   workflow on a frequent cron can instead pass `--scheduled`: the CLI
   reads each policy's per-policy state shard and gates by
   cadence + content-hash + prior status, evaluating only the policies
   that are actually due and carrying the rest forward. This collapses the
   per-cadence template set into one workflow, at the cost of the CLI
   consulting state. It exists today; the shipped templates simply prefer
   the per-cadence-cron shape because it keeps each workflow stateless and
   makes "does the quarterly check actually run quarterly?" answerable by
   reading one cron line.

Run modes interact with the planner differently:

| Mode | When triggered | Loads state? | Gates by cadence? |
|------|----------------|--------------|-------------------|
| `--cadence <X>` | Per-cadence cron (scaffolded) | No | Selects by effective cadence; the cron is the schedule |
| `--scheduled` | Single frequent cron (optional) | Yes | Yes — due policies evaluate, others carry forward |
| `--on-push` | push / PR | No | No — every `on_push: true` policy runs |
| Default (no filter) | Local invocation | No | No — every in-scope policy runs |

The filter flags `--cadence`, `--cadences`, `--on-push`, `--pr`, and
`--scheduled` are **mutually exclusive** — at most one per invocation.

For PR runs, a workflow runs `sigcomply check --on-push` on every push /
pull request — that invocation only evaluates `on_push: true` policies, so
manual-evidence checks (which default to `on_push: false`) are excluded.

**Cadence enforcement lives in the CLI + the cron together.** Under
`--scheduled`, a quarterly policy carries forward from its prior signed
envelope until it is due, even if the workflow runs nightly. Under the
scaffolded per-cadence crons, the cron *is* the schedule (the quarterly
cron only fires on the quarter boundaries). Either way the CI cron is the
**upper bound** on cadence (you can't evaluate quarterly if you never run).

### What about re-running after a fix?

A failed policy is re-evaluated on the next run regardless of cadence —
under `--scheduled`, `IsDue` returns true whenever the prior terminal
status was not `pass`, so the next scheduled run picks up the fix with no
manual action. Under per-cadence crons, just re-run the relevant workflow
(`workflow_dispatch`).

### What about a missed CI run?

If CI is broken for an extended window, the planner emits a
`gap-detected: N policies have no evaluation in the last 30d`
warning at the next run. The CLI does NOT fabricate retroactive
evaluations to fill the gap. Auditors will see the gap in the
period history, which is the correct posture (compare Airflow's
`catchup=false`).

Full design: [`10-cadence-model.md`](10-cadence-model.md).

---

## The scaffolded workflow set per framework

When a customer runs `sigcomply init-ci --framework soc2 --ci github`,
the CLI scaffolds one standalone workflow file per cadence into
`.github/workflows/`:

```
.github/workflows/
   compliance-on-push.yml      # push to main + pull_request
   compliance-daily.yml        # 02:00 UTC daily cron
   compliance-weekly.yml       # 02:00 UTC every Monday
   compliance-monthly.yml      # 02:00 UTC on the 1st of every month
   compliance-quarterly.yml    # 02:00 UTC on Jan 1 / Apr 1 / Jul 1 / Oct 1
   compliance-annual.yml       # 02:00 UTC on January 1
```

Each is a fully self-contained workflow — there is **no** reusable
`workflow_call` workflow and **no** `.github/actions/*` composite action.
The templates live at `cmd/sigcomply/templates/github/` and carry an
`# Generated by sigcomply init-ci. Customize freely.` header. Each one:

- Triggers on its own cron (`schedule:`) plus `workflow_dispatch`, except
  `compliance-on-push.yml`, which triggers on `push` to the default branch
  and `pull_request`.
- Requests `id-token: write` + `contents: read` permissions (the OIDC
  token for SigComply Cloud submission).
- Installs the CLI by `curl`-ing the release tarball from GitHub Releases
  (`https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/sigcomply_${ver}_linux_amd64.tar.gz`)
  and extracting the `sigcomply` binary, resolving `latest` via the GitHub
  releases API when `SIGCOMPLY_VERSION` is `latest`.
- Configures cloud credentials via `aws-actions/configure-aws-credentials@v4`
  with `audience: https://api.sigcomply.com`.
- Runs `sigcomply check --cadence <X>` (or `sigcomply check --on-push`
  for the on-push workflow).

The shipped cron expressions are exactly:

| Workflow | Cron | Filter flag |
|---|---|---|
| `compliance-daily.yml` | `0 2 * * *` | `--cadence daily` |
| `compliance-weekly.yml` | `0 2 * * 1` | `--cadence weekly` |
| `compliance-monthly.yml` | `0 2 1 * *` | `--cadence monthly` |
| `compliance-quarterly.yml` | `0 2 1 1,4,7,10 *` | `--cadence quarterly` |
| `compliance-annual.yml` | `0 2 1 1 *` | `--cadence annual` |
| `compliance-on-push.yml` | `push` + `pull_request` | `--on-push` |

`continuous` and `hourly` policies fold into the on-push / daily workflows;
the scaffold does not emit a dedicated workflow per named cadence beyond
the six above. v1-alpha ships cadence templates for **SOC 2 only** —
`init-ci` for any other framework (including ISO 27001) exits `3` with a
"not supported in v1-alpha" error (`frameworkSupported()` in
`cmd/sigcomply/init_ci.go` returns true only for `soc2`). ISO 27001
templates are planned but not yet shipped.

### Example: `compliance-daily.yml` (GitHub Actions, scaffolded)

```yaml
# Generated by `sigcomply init-ci`. Customize freely.
name: Compliance — Daily

on:
  schedule:
    - cron: '0 2 * * *'    # 02:00 UTC every day
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

env:
  SIGCOMPLY_VERSION: latest
  AWS_REGION: us-east-1
  AWS_ROLE_ARN: arn:aws:iam::000000000000:role/REPLACE_ME

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - name: Install SigComply CLI
        run: |
          set -eu
          version="${SIGCOMPLY_VERSION:-latest}"
          if [ "$version" = "latest" ]; then
            tag=$(curl -fsSL https://api.github.com/repos/SigComply/sigcomply-cli/releases/latest | jq -r .tag_name)
          else
            tag="$version"
          fi
          ver="${tag#v}"
          curl -fsSL "https://github.com/SigComply/sigcomply-cli/releases/download/${tag}/sigcomply_${ver}_linux_amd64.tar.gz" -o /tmp/sigcomply.tar.gz
          tar -xzf /tmp/sigcomply.tar.gz -C /usr/local/bin sigcomply
          chmod +x /usr/local/bin/sigcomply
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ env.AWS_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}
          audience: https://api.sigcomply.com
      - name: Run SigComply
        run: sigcomply check --cadence daily
```

The `compliance-on-push.yml` workflow is identical except for its trigger
(`push: { branches: [main] }` + `pull_request`, no cron) and its final
step (`sigcomply check --on-push`). Manual-evidence policies are excluded
from on-push runs because they default to `on_push: false` — uploading a
PDF on every PR is not the workflow.

If the quarterly access-review PDF is missing when `compliance-quarterly.yml`
runs, the CLI fails the job with exit code 1 and a missing-evidence message
(see [`04-source-plugins.md`](04-source-plugins.md) §Missing evidence).
Operators upload the PDF and re-run via `workflow_dispatch` — the framework
does not assume the quarterly cron date is when the human action happens.

### GitLab CI

`sigcomply init-ci --framework <fw> --ci gitlab` writes a single
`.gitlab-ci.yml` (template at `cmd/sigcomply/templates/gitlab/.gitlab-ci.yml`)
in which each cadence is one job gated by a `rules:` clause. The on-push
job runs on merge requests and default-branch pushes; the cadence jobs run
only on scheduled pipelines whose `CADENCE` variable matches:

```yaml
# excerpt — one job per cadence, all sharing an OIDC id_tokens block
compliance:on_push:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - sigcomply check --on-push

compliance:daily:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule" && $CADENCE == "daily"'
  script:
    - sigcomply check --cadence daily
# … weekly / monthly / quarterly / annual jobs follow the same shape
```

Operators create one GitLab pipeline schedule per cadence and set that
schedule's `CADENCE` variable to the matching value. There is no
first-class packaged GitLab CI component yet — this template (and the
copy-paste example below) is the supported path.

### Copy-paste examples

For projects that prefer to author CI by hand rather than scaffold, the
repo ships ready-to-copy examples:

- `examples/github-actions/basic.yml` — minimal single-workflow setup.
- `examples/github-actions/multi-environment.yml` — multiple accounts /
  environments in one workflow.
- `examples/gitlab-ci.yml` — GitLab pipeline mirroring the scaffolded
  template's `rules:` structure.

---

## Filter flags: how the CLI knows what to run

Inside a job, at most one of these flags drives policy selection:

| Flag | What it selects |
|---|---|
| `--cadence <X>` | Policies whose **effective** cadence equals `<X>`. Effective cadence = project override if present, else framework default. |
| `--cadences <X,Y,…>` | Union of multiple cadences in one invocation (e.g. `--cadences daily,weekly`). |
| `--on-push` | Policies whose `on_push` attribute is `true`. Defaults: `true` for automated policies, `false` for manual. |
| `--pr` | PR-feedback selection (the on-push set, run for pull-request events). |
| `--scheduled` | All policies, gated per-policy by cadence + state (see §How cadence enforcement actually works). |

If none is provided, the CLI evaluates **all** in-scope policies. Useful
for local development and full-coverage runs.

There is **no** `--policies`, `--controls`, or `--framework` flag on
`check`; the framework is fixed by config / `SIGCOMPLY_FRAMEWORK`. These
filter flags are mutually exclusive — passing more than one is a
configuration error (exit 3).

---

## Policy result vs job result vs run state

Three distinct concepts. Confusing them produces bad CI ergonomics.

| Concept | Where it lives | Values | Affects what |
|---|---|---|---|
| **Policy result** | `policies/<id>/result.json` in the vault | `pass | fail | skip | error | na | waived | carried_forward` | Period roll-up state |
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

If on-push runtime becomes an issue, a future version could shard the
on-push set across parallel jobs — each job a separate `sigcomply check`
invocation, each writing its own run folder, with the period roll-up
unioning them. The vault layout already supports this (see
[`05-vault-layout.md`](05-vault-layout.md) §Per-run folder); the CLI does
not need to know about sharding peers. No source-prefix / shard flags exist
on `check` today — this remains a v2 direction, not a shipped capability.

---

## Scaffolding: `sigcomply init-ci`

The CLI ships a scaffolding command:

```bash
sigcomply init-ci --framework soc2 --ci github
```

Effects:

1. Writes the per-cadence `compliance-*.yml` files into
   `.github/workflows/` (override the location with `--out`). `--framework`
   defaults to the `.sigcomply.yaml` framework, else `soc2`.
2. Prints next steps: replace the `AWS_ROLE_ARN` placeholder with the IAM
   role configured for OIDC role assumption
   (`aud: https://api.sigcomply.com`), then commit.

`init-ci` does **not** generate a `.sigcomply.yaml` — the project config is
authored separately (see [`08-project-config.md`](08-project-config.md)).

For GitLab:

```bash
sigcomply init-ci --framework soc2 --ci gitlab
```

Writes a single `.gitlab-ci.yml` with one cadence-keyed job per cadence
(driven by the `CADENCE` schedule variable, as shown above).

The scaffolded files are starter templates carrying a "Customize freely"
header. The shipped templates assume:

- OIDC-based AWS credential setup (`aws-actions/configure-aws-credentials@v4`
  with `audience: https://api.sigcomply.com`); adapt for GCP / Azure.
- Single AWS account / region (matching the single-scope v1 design).
- SigComply Cloud submission enabled (it auto-enables when the OIDC token
  is present; pass `--no-cloud` to opt out).

---

## Identity: project, run, evidence

The CI layer establishes three identities the CLI consumes. The cloud
`SubmissionPayload` (schema `sigcomply.cloud.v3`,
[`internal/core/cloud.go`](../../internal/core/cloud.go)) carries them as:

- **Project identity** (`org/name` from the CI's repo metadata) →
  `repository.provider` (`github`/`gitlab`) and `repository.name_slug`.
- **CI invocation identity** → top-level `run_id` on the payload, plus
  `environment.provider` (`github_actions`/`gitlab_ci`/`local`). Lets
  auditors correlate vault folders with CI job logs.
- **Commit identity** → `commit_sha` and `branch` (plus `commit_time`,
  which drives period derivation), alongside `cli_version`.

These identities flow from CI → CLI via environment variables (or the CI
provider's API) and are normalized in the orchestrator
([`internal/orchestrator/orchestrator.go`](../../internal/orchestrator/orchestrator.go))
before aggregation. None of these is customer evidence — every field is
already public via the git remote or the CI system's own job metadata.

---

## What the CI layer DOESN'T do

Things to keep out of the workflow files; the CLI handles them
internally:

- **Policy selection per CI event.** Workflow files pass `--cadence <X>`
  or `--on-push`; the CLI does the policy filtering. Don't enumerate
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
  for three quarters, did the workflow file change? Did a per-policy
  `cadence:` override appear? Did an exception get added?

The workflow files, like `.sigcomply.yaml` and any custom policies
under `.sigcomply/`, are part of the project's audit trail and live
in git.

---

## See also

- [`01-conceptual-model.md`](01-conceptual-model.md) — the Project,
  Period, Run, and Policy cadence abstractions.
- [`03-policy-spec.md`](03-policy-spec.md) — the `cadence` and `on_push`
  fields on a policy spec.
- [`05-vault-layout.md`](05-vault-layout.md) — how multiple runs
  within a period interact.
- [`08-project-config.md`](08-project-config.md) — per-policy `cadence`
  overrides (under `policies:`) and the `check` flag reference (via
  `docs/configuration.md`).
- [`10-cadence-model.md`](10-cadence-model.md) — the per-policy decision
  rule and per-policy state shards.
