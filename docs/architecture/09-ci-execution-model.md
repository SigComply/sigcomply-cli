# 09. CI execution model

The CLI is a leaf invocation: it reads the project config, collects evidence, evaluates policies,
writes the vault and, if cloud submission is configured, submits counts. Everything above it
(which policies run when, in which CI job) lives in CI workflow files in the customer's repo.
This doc covers how those pieces fit. The cadence decision rule and the period clock are owned by
[10-cadence-model.md](10-cadence-model.md).

## Execution hierarchy

```
Project    = one source-control repository (GitHub or GitLab), one framework
   -> Pipelines = CI workflow files in that repo, scheduled by cron
       -> Jobs   = one `sigcomply check` invocation each
           -> Policy evaluations = per-policy collect + check + persist
```

- A project maps 1:1 to a repository. The repo's `org/name` is the project identity, and
  `.sigcomply.yaml` sits at the repo root.
- A project pursues exactly one framework (`framework:` in the config). Every workflow evaluates
  that framework, and the vault holds evidence for it alone. A customer with two frameworks uses
  two repositories. Two configs in one repo (`--config .sigcomply-iso.yaml`) work, but `init-ci`
  does not scaffold that shape.
- Each policy evaluates independently. One policy's failure never stops another.

## Cadence drives scheduling

Each policy declares a cadence (`continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`,
`annual`, `every:<duration>`); a project overrides it under `policies.<id>.cadence`. Values and
intervals: [10](10-cadence-model.md#cadence-dsl). To see which cadences a framework uses, grep
`cadence:` in `internal/frameworks/<fw>/builders.go` and the `policies_*.go` files.

Two ways to turn cadence into runs:

1. **Per-cadence crons (what `init-ci` scaffolds).** One workflow per cadence, each passing
   `--cadence <X>`. The cron decides when; `--cadence` decides which policies. No state is read.
2. **`--scheduled` (available, not scaffolded).** One workflow on a frequent cron. The CLI loads
   per-policy state shards and evaluates only the policies that are due, carrying the rest
   forward ([10](10-cadence-model.md#the-decision-rule)).

Either way the CI cron is the upper bound: a quarterly policy cannot be evaluated quarterly if
nothing runs.

## Filter flags

`check` accepts at most one of these. They are mutually exclusive through cobra
(`MarkFlagsMutuallyExclusive` in `cmd/sigcomply/check.go`); passing two exits 2.

| Flag | Selects | Mode |
|---|---|---|
| (none) | every in-scope policy | `ModeManual` |
| `--cadence <X>` | policies whose effective cadence equals `<X>` exactly | `ModeManual` |
| `--cadences <X,Y>` | effective cadence in the set; the virtual value `on_push` adds every `on_push: true` policy | `ModeManual` |
| `--on-push` | policies with `on_push: true` | `ModeManual` |
| `--pr` | the `on_push` set, with a longer per-slot retry budget (`collector.RetryPR`) | `ModePR` |
| `--scheduled` | every policy, gated by state | `ModeScheduled` |

Rules that follow from `planner.filterAccepts`:

- `--cadence` matches exactly. `--cadence daily` does not select `hourly`, `continuous` or
  `every:` policies. No scaffolded cron selects those cadences; they run only in the on-push
  workflow (when `on_push: true`), under `--scheduled`, or with no filter.
- Effective cadence is the project override if set, else the framework default.
- `on_push` defaults to `true` for automated policies and `false` for manual ones, so on-push runs
  never require manual evidence.
- `check` has no `--policies`, `--controls` or `--framework` flag. The framework comes from the
  config only.

## Scaffolded workflows (`sigcomply init-ci`)

```bash
sigcomply init-ci --framework soc2 --ci github   # or --ci gitlab
```

- `init-ci` accepts only `soc2` (`frameworkSupported` in `cmd/sigcomply/init_ci.go`); any other
  framework exits 3. The templates name no framework; the gate exists because only SOC 2 has
  been exercised against them.
- `--framework` defaults to the config's `framework:`, else `soc2`. `--out` overrides the output
  location. `init-ci` does not write `.sigcomply.yaml`.
- The templates live in `cmd/sigcomply/templates/` (`github/compliance-*.yml`,
  `gitlab/.gitlab-ci.yml`), with golden copies in `cmd/sigcomply/testdata/`. Read them for the
  exact YAML; this doc describes only the mechanism.

### GitHub Actions

One standalone workflow per cadence in `.github/workflows/`. There is no reusable
`workflow_call` workflow and no composite action.

| Workflow | Trigger | Command |
|---|---|---|
| `compliance-on-push.yml` | `push` to `main`, `pull_request` | `sigcomply check --on-push` |
| `compliance-daily.yml` | `0 2 * * *` | `sigcomply check --cadence daily`, then `sigcomply evidence due --within-days 30` (non-failing) |
| `compliance-weekly.yml` | `0 2 * * 1` | `sigcomply check --cadence weekly` |
| `compliance-monthly.yml` | `0 2 20 * *` | `sigcomply check --cadence monthly` |
| `compliance-quarterly.yml` | `0 2 20 3,6,9,12 *` | `sigcomply check --cadence quarterly` |
| `compliance-annual.yml` | `0 2 20 12 *` | `sigcomply check --cadence annual` |

Every workflow:

- runs on its cron plus `workflow_dispatch` (on-push has no `workflow_dispatch`);
- requests `id-token: write` and `contents: read`;
- installs the CLI by downloading the release tarball for `SIGCOMPLY_VERSION` from GitHub Releases
  (resolving the newest tag through the releases API when the value is `latest`);
- gets AWS credentials with `aws-actions/configure-aws-credentials` and
  `audience: https://api.sigcomply.com`.

`init-ci` renders `SIGCOMPLY_VERSION` as the running binary's own release tag (`v<semver>`) when
the binary is a clean semver build, and as `latest` otherwise (dev builds). Golden tests set the
version explicitly. A scaffolded project stays on the version it was scaffolded with until the
operator edits the value.

A cadence with no policies still gets a workflow; it evaluates nothing until a project override
moves a policy onto that cadence.

### GitLab CI

`--ci gitlab` writes one `.gitlab-ci.yml`. A shared hidden job installs the CLI and requests a
GitLab ID token (`SIGCOMPLY_ID_TOKEN`, audience `https://api.sigcomply.com`) for cloud
submission. Each cadence is a job gated by `rules:`:

- `compliance:on_push` runs on merge requests and default-branch pushes.
- `compliance:<cadence>` runs only on a scheduled pipeline whose `CADENCE` variable matches. The
  operator creates one pipeline schedule per cadence and sets `CADENCE`.
- The daily job also runs `sigcomply evidence due --within-days 30 || true`.

AWS credentials come from web identity: the template writes a GitLab ID token to a file and
exports `AWS_WEB_IDENTITY_TOKEN_FILE` with `AWS_ROLE_ARN`, which the AWS SDK default credential
chain uses to assume the role. The CLI itself performs no `AssumeRoleWithWebIdentity` call. There
is no packaged GitLab CI component.

### What the templates assume

- AWS is the cloud. GCP and Azure projects replace the credential step.
- One AWS account and region.
- Cloud submission happens only when the config sets `cloud.base_url` (or `--cloud-url` is
  passed) and the job has an OIDC token; `--no-cloud` turns it off. See
  [`../claude/auth.md`](../claude/auth.md).

### Copy-paste examples

`examples/github-actions/basic.yml`, `examples/github-actions/multi-environment.yml` and
`examples/gitlab-ci.yml` are hand-written alternatives. They install `latest` and tell the user to
pin a version. Only the `init-ci` templates carry the `evidence due` step.

## Why the crons fire on the twentieth

The audit period comes from the HEAD commit's timestamp, not the wall clock
([10](10-cadence-model.md#period-freeze-rule)). A cron at 02:00 on the first day of a quarter lands
in whichever period HEAD falls in. If someone pushed to `main` after the boundary, the run looks in
the new period's manual folder, which cannot hold valid evidence yet: the temporal-window check
rejects files uploaded before the period starts. The job fails and no operator action could have
prevented it.

The monthly, quarterly and annual crons therefore fire on the twentieth day of the month, inside the period. HEAD is
then inside the period being evaluated, and the operator has had most of the period to upload.

## Missing manual evidence

If a manual entry's folder is empty when its cadence run fires, the policy fails with `manual
evidence not found; expected files in: <folder>` (`internal/evaluator/manual_check.go`) and the
job exits 1. The operator uploads the file and re-runs the workflow (`workflow_dispatch`, or a
manual pipeline on GitLab).

The earlier signal is `sigcomply evidence due` in the daily workflow. It lists entries whose
current folder is still empty. It exits 0 whatever it finds and 3 on a config error
([10](10-cadence-model.md#manual-evidence-due-sigcomply-evidence-due),
[commands](../reference/commands.md#sigcomply-evidence-due)).

## Plan warnings in scaffolded runs

Scaffolded runs never pass `--scheduled`, so no state is loaded. Every scaffolded run therefore
logs `first-run: N policies will evaluate for the first time this run`, and never logs
`gap-detected`. A missed cron leaves a gap in the run folders; the CLI does not back-fill it.
Details: [10](10-cadence-model.md#day-1-warnings).

## Results and exit codes

| Concept | Where | Values |
|---|---|---|
| Policy result | `policies/<id>/result.json` in the run folder | `pass`, `fail`, `skip`, `error`, `na`, `waived`, `carried_forward` |
| Run summary | `summary.json` in the run folder | counts |
| Exit code | CLI process | `0`, `1`, `2`, `3` |

Within one `check`:

1. Every selected policy runs to completion and its result is persisted, whatever the others did.
2. The vault receives results whether the run passed or failed.
3. Cloud submission, if configured, happens either way.
4. `renderAndExitCode` (`internal/orchestrator/orchestrator.go`) then picks the exit code.

| Code | When |
|---|---|
| `0` | No policy errored, none failed, declared scope complete; or failures with `ci.fail_on_violation: false` |
| `1` | At least one policy `fail`, or declared `required_sources` incomplete, and `ci.fail_on_violation` is true (the default) |
| `2` | At least one policy has status `error` (checked before failures), a run-level execution failure, or invalid or conflicting flags |
| `3` | Configuration or planning error, before collection |

Any `fail` exits 1; there is no severity threshold (`ci.fail_severity` was removed). The customer
reference is [`../reference/commands.md`](../reference/commands.md).

Exit 1 is a successful report of failing compliance state: the vault and the submission are
complete. Exit 2 is common in practice (for example, a 403 from a source or a `pass_when` field
the record lacks) and means at least one result is not a verdict.

## Identities in the payload

The CI layer supplies three identities, carried in `SubmissionPayload`
([`internal/core/cloud.go`](../../internal/core/cloud.go); schema history in
[06](06-aggregation.md)):

- project: `repository.provider` (`github`, `gitlab`) and `repository.name_slug`;
- run: `run_id` and `environment.provider` (`github_actions`, `gitlab_ci`, `local`);
- commit: `commit_sha`, `branch`, `commit_time`, plus `cli_version`.

All of them are already visible through the git remote or the CI system. None is customer
evidence.

## Keep out of workflow files

- Policy selection: pass a filter flag, never a list of policies.
- Retry: the collector retries 429 and 5xx within its budget and fails 401/403 at once
  (`internal/collector/retry.go`). A job-level retry repeats a failure the CLI already judged
  permanent.
- Evidence caching or pre-fetch steps: collection happens inside the job.
- Period computation: the CLI derives the period; workflows never pass one.

Workflow files describe when to run; the CLI decides what and how. They are part of the audit
trail: an auditor reads the crons to check cadence and `git log` to see whether a workflow was
changed to skip policies.

## See also

- [01-conceptual-model.md](01-conceptual-model.md): project, period, run.
- [03-policy-spec.md](03-policy-spec.md): `cadence` and `on_push` on a policy.
- [05-vault-layout.md](05-vault-layout.md): run folders.
- [10-cadence-model.md](10-cadence-model.md): decision rule, state shards, period clock.
- `docs/guides/ci-github.md`, `docs/guides/ci-gitlab.md`: customer setup steps.
