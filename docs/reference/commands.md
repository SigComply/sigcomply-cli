# Commands

Every `sigcomply` command, its flags and its exit codes. `sigcomply <command> --help` prints the
same flags.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `check`: no policy failed, or `ci.fail_on_violation: false` is set. |
| `1` | `check`: a policy failed, or a source declared under `experimental.scope` is incomplete. Set `ci.fail_on_violation: false` to exit `0` instead. `report --view integrity`: a run failed verification. |
| `2` | Execution error, including any policy with status `error`, a credential the provider rejected, a failed write of the run's results, summary or manifest to the vault, and a flag the command does not know, a flag value of the wrong type, or two flags that cannot be combined. |
| `3` | Configuration error: a missing or invalid config, an unknown framework, a listed source whose credentials are missing, a missing required flag value such as `report --period`, or a value a flag does not accept (`report --view bogus`, `report --format xml`, `init-ci --ci jenkins`, `evidence -o csv`). For `report`, also a vault path that does not exist or a period with no runs. |

A missing credential exits `3` before any collection starts. A credential the provider rejects
can only be found during collection, so the affected policies end as `error` and the run exits
`2`.

## Framework resolution

| Command | Where the framework comes from, in order |
|---|---|
| `check` | `framework:` in the config only. No flag; `SIGCOMPLY_FRAMEWORK` is ignored. Missing: exit `3`. |
| `init`, `evidence catalog` | `-f/--framework`, then `SIGCOMPLY_FRAMEWORK`, then `soc2` |
| `evidence due` | `-f/--framework`, then `framework:` in the config. The config must set `framework:`, so `SIGCOMPLY_FRAMEWORK` never applies. |
| `init-ci` | `--framework`, then the `framework:` line of the config, then `soc2` |
| `report` | `-f/--framework`, then `framework:` in the config. Neither: exit `3`. |

## `sigcomply check`

```sh
sigcomply check [flags]
```

Plans the framework's policies for the current period, collects evidence from the configured
sources, evaluates each policy, writes signed envelopes, results and a signed run manifest to
the vault, and submits counts to SigComply Cloud when cloud submission is on.

The period is taken from the run's start time in UTC (set `period.time_basis: commit` to take it
from the HEAD commit instead). The first summary line prints it, for example
`SigComply check soc2/2026-Q4`.

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--cadence <value>` | | | Only evaluate policies whose effective cadence matches: `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual` |
| `--cadences <list>` | | | Comma-separated cadence set; a policy matches if any of its cadences is in the set. `on_push` selects on-push policies. |
| `--on-push` | | | Only evaluate policies whose `on_push` attribute is true |
| `--pr` | | | Pull request mode: on-push policies. A slot that fails with a throttling, `5xx` or network error is tried up to 5 times, with about 3 minutes of waits in total. |
| `--scheduled` | | | Run whichever cadences are due according to the vault's execution state, then advance the state |
| `--cloud` | | | Submit even outside CI. Needs an OIDC token and `cloud.base_url` (or `--cloud-url`); without a URL it warns and skips. |
| `--no-cloud` | | | Never submit |
| `--cloud-url <url>` | | `cloud.base_url` | SigComply Cloud base URL. Setting it turns submission on, like `cloud.base_url`. Without `cloud.project_id` in the config, `check` warns; the project ID has no flag. |
| `--capture-cloud-payload <file>` | | | Write the submission payload to this file instead of sending it. A failed write exits `2`. |
| `--config <path>` | `-c` | `.sigcomply.yaml` | Config file |
| `--verbose` | `-v` | `false` | Verbose logging |

`--cadence`, `--cadences`, `--on-push`, `--pr` and `--scheduled` are mutually exclusive;
combining two exits `2`. A `--cadence` or `--cadences` value that is not a cadence (or
`every:<duration>`, or `on_push` in `--cadences`) exits `3` and lists the valid values. `check`
has no `--framework` flag.

Without `--cloud` or `--no-cloud`, the CLI submits only when all of these hold: a base URL is
set, the run is in GitHub Actions or GitLab CI, and an OIDC token is available. A failed
submission does not change the exit code. The base URL must be `https://` (plain `http://` only
for `localhost`), or the run exits `3` before collecting.

The run ends with the vault folder it wrote and the command that reads it back:

```
Results written to ./.sigcomply/vault/soc2/2026-Q4/run_20261026T201203Z_14f82a86
Next: sigcomply report --period 2026-Q4 (add --view integrity to verify the signatures)
```

Only a run that covers every policy submits: `check` with no filter, or `--scheduled`. A run with
`--cadence`, `--cadences`, `--on-push` or `--pr` prints `cloud submission skipped: this run
evaluates a subset of policies` and sends nothing (`--capture-cloud-payload` still writes the
file). A `--pr` run also leaves the cadence state in the vault unchanged, so a pull request's
result is never carried forward by a later `--scheduled` run. So does any run in a pull-request
pipeline (`GITHUB_EVENT_NAME` is `pull_request` or `pull_request_target`) or a GitLab merge
request pipeline (GitLab sets `CI_MERGE_REQUEST_IID`), whatever its flags.

## `sigcomply init`

```sh
sigcomply init [flags]
```

Writes a commented `.sigcomply.yaml` for the framework. It runs as written: three AWS sources
(`aws.iam`, `aws.iam_access_key`, `aws.password_policy`) with every other `aws.*` source listed
commented out, a local `manual.pdf` source in `./evidence`, and a local vault. Unless the
directory's `.gitignore` already mentions `.sigcomply/`, it prints a reminder to ignore the
local vault.

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--framework <value>` | `-f` | `$SIGCOMPLY_FRAMEWORK`, then `soc2` | `soc2` or `iso27001` |
| `--out <path>` | `-o` | `.sigcomply.yaml` | Output path |
| `--force` | | `false` | Overwrite an existing file. Without it, an existing file exits `3`. |

## `sigcomply init-ci`

```sh
sigcomply init-ci --ci <github|gitlab> [flags]
```

Writes CI files that install the CLI release, after checking the archive against the release's
`checksums.txt`, and run `check`.

- `--ci github` writes `compliance-scheduled.yml` (daily at 02:00 UTC and on demand,
  `sigcomply check --scheduled`) and `compliance-on-push.yml` (pull requests and pushes to
  `main`, `sigcomply check --pr`) to `.github/workflows/`.
- `--ci gitlab` writes one `.gitlab-ci.yml` with a `compliance:scheduled` job that runs
  `sigcomply check --scheduled` in any scheduled pipeline, and a `compliance:on_push` job that
  runs `sigcomply check --pr` on merge requests and pushes to the default branch. Create one
  daily pipeline schedule.

Only the scheduled run submits to SigComply Cloud. The scheduled workflow (GitHub) and job
(GitLab) also run `sigcomply evidence due` as a step that cannot fail the job.

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--ci <value>` | | | Required. `github` or `gitlab`. Missing: exit `3`. |
| `--framework <value>` | | config, then `soc2` | Framework. Only `soc2` is accepted. |
| `--out <path>` | | `.github/workflows/` (github), repository root (gitlab) | Output directory |
| `--force` | | `false` | Overwrite existing files. Without it, any existing target file exits `3`. |
| `--config <path>` | `-c` | `.sigcomply.yaml` | Config used to default `--framework` |

Any framework other than `soc2` exits `3`. The workflows don't name a framework (`check` reads
it from the config), so an ISO 27001 project can run `init-ci --ci github --framework soc2` and
keep `framework: iso27001` in its config.

## `sigcomply build`

```sh
sigcomply build [flags]
```

Compiles a binary that includes the Go extensions under `.sigcomply/` (source plugins, vault
backends, manual readers). With no Go extensions it does nothing and needs no `go.mod`; YAML
policies, Rego rules, evidence-type JSON schemas and the local vault under `.sigcomply/` are not
Go extensions. YAML policies, Rego rules and schemas load at every `check` without a build.

Extensions import `github.com/sigcomply/sigcomply-cli/plugin`, and the project's `go.mod` must
require the CLI module at the version of the binary you build with. An extension's top-level
files may not import `os/exec`, `net` or `net/*`; this import check is not a sandbox. A Go rule
package or Go evidence-type package compiles but is never loaded, and `build` prints a warning
for each. Details: [Extensibility](../architecture/07-extensibility.md).

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--project <dir>` | | `.` | Directory that contains `.sigcomply/` |
| `--output <path>` | | `./bin/sigcomply` | Output binary |
| `--tags <list>` | | | Go build tags, comma-separated |
| `--ldflags <value>` | | | Passed to `go build -ldflags` |
| `--verbose` | `-v` | `false` | Verbose output |

## `sigcomply report`

```sh
sigcomply report --period <period-id> [flags]
```

Reads the vault and prints one view of a period. It never writes to the vault, never contacts
SigComply Cloud and needs no OIDC token.

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--period <id>` | | | Required. Period ID such as `2026-Q4`, or `soc2/2026-Q4` as the first line of `check` prints it. Missing: exit `3`. |
| `--view <value>` | | `latest` | `latest`, `exceptions`, `integrity`, `scope`, `coverage` or `soa` |
| `--format <value>` | | `text` | `text`, `json` or `csv`. Any other value exits `3` before `--out` is opened. |
| `--out <file>` | | stdout | Output file. Required for `json` and `csv`. |
| `--config <path>` | `-c` | `.sigcomply.yaml` | Config file. Not read when both `--vault` and `--framework` are set, unless you pass `-c`. |
| `--vault <uri>` | | config | Vault location: a path, `file://<path>`, `s3://bucket[/prefix][?region=<region>]`, `gs://bucket[/prefix]` or `az://<account>/<container>[/prefix]` |
| `--framework <value>` | `-f` | config | Framework |

An `s3://` URI without `?region=` takes the region from `AWS_REGION`, then
`AWS_DEFAULT_REGION`, then `vault.region` in the config when that vault is S3. Other S3 settings
(`endpoint`, `force_path_style`) can only come from the config.

A local vault path that does not exist exits `3`; `report` does not create it. A period with no
runs exits `3` and lists the periods the vault holds, so a mistyped period or vault never reads
as a clean result. The `soa` view is the exception: it renders with no runs, and every control
then reads "not evaluated".

| View | Shows |
|---|---|
| `latest` | Each policy's latest status in the period, with the reason for a failure or error |
| `exceptions` | Waivers and not-applicable declarations |
| `integrity` | Each run's signature and manifest check, `pass` or every failing file: a hash mismatch, a listed file that is missing, or a file in the run folder the manifest does not list. Exits `1` when any run fails. |
| `scope` | The declared estate (`experimental.scope`) and every control the latest run did not evaluate, with the reason |
| `coverage` | For each control, whether automated or manual checks are mapped to it, whether the automated checks inspected anything, and whether documents exist for the period |
| `soa` | The ISO 27001 Statement of Applicability: one row per Annex A control with applicability, justification and status |

`--view coverage` covers every control in the framework, including controls whose cadence did
not run this period. It splits controls into two kinds, which the score counts the same: backed
only by document checks, or with at least one automated check mapped.
For SOC 2, 29 of 43 criteria are the first kind. The kind comes from the mapped policies, not
from what ran, so `This period` splits the automated controls by what their automated checks
did:

- inspected: at least one automated check examined resources. It ended `pass` or `fail`, was
  `waived` after evaluation because every violation matched a resource-scoped exception, or
  ended `carried_forward` from an earlier pass.
- skipped: no automated check was inspected or errored, and at least one ended `skip`, usually
  because no configured source emits the evidence the check reads.
- waived or not applicable: every automated result was `na`, or `waived` by an exception that
  covers the whole policy. Neither collects anything.
- not evaluated or errored: the rest.

Sample output from a SOC 2 project with only the manual evidence source configured:

```
43 of 43 catalog controls have a check
  14 automated  — an automated check is mapped; "This period" shows whether it ran
  29 manual     — only document checks are mapped; their contents are not inspected

This period
  43 evaluated, 0 not evaluated
  14 automated control(s): 0 inspected, 14 skipped, 0 waived or not applicable, 0 not evaluated or errored
  0 manual control(s) with evidence on file, 29 without
```

`--format json`, like `result.json` in the vault, uses Go field names as keys (`PolicyID`,
`Status`); some nested objects use `snake_case`. `--format csv` uses `snake_case` column names
throughout.

`--view soa` needs the project config, because applicability decisions exist only in
`.sigcomply.yaml`. If you pass both `--vault` and `--framework`, the config is read only when you
also pass `-c <path>`; without it the view exits `3`.
It is built for ISO 27001; for SOC 2 it lists the criteria. How to read and fill it:
[ISMS clauses and the SoA](../guides/isms-clauses.md). The other views:
[Verify evidence](../guides/verify-evidence.md).

## `sigcomply evidence catalog`

```sh
sigcomply evidence catalog [-f <framework>] [-o text|json]
```

Prints the framework's manual-evidence catalog. Needs no project config. Text output has the
columns `ID`, `CONTROL`, `TYPE`, `FREQUENCY` and `NAME`; `-o json` prints
`{framework, version, entries[]}` with every field, the format the Evidence SPA reads. The
catalog spells the annual frequency `yearly`.

The flags belong to the parent `evidence` command, so `--help` lists them as global flags.

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--framework <value>` | `-f` | `$SIGCOMPLY_FRAMEWORK`, then `soc2` | Framework |
| `--output <value>` | `-o` | `text` | `text` or `json` |

## `sigcomply evidence due`

```sh
sigcomply evidence due [flags]
```

Lists manual-evidence entries whose folder for the current period is empty, with the folder to
upload to. An entry disappears once its folder has a file. Each entry's period is its own
cadence window (an annual entry's runs to 31 December), measured on the same clock as
`check`. A per-vendor entry is listed once per vendor that owes a document.

It only lists the storage. It downloads nothing, writes nothing and contacts no cloud API.

When empty folders exist but none closes within `--within-days`, it says so, for example
`2 of 50 entries have no upload for the current period; none closes within 30 days`; it prints
an all-clear only when every folder has a file. The `DUE IN` column counts to the end of the
entry's period. Upload during the period: once it ends, runs read the next period's folder, so a
late upload into the old folder is never checked.

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--config <path>` | `-c` | `.sigcomply.yaml` | Config file |
| `--framework <value>` | `-f` | see [Framework resolution](#framework-resolution) | Framework |
| `--output <value>` | `-o` | `text` | `text` or `json` |
| `--within-days <n>` | | `30` | Only list entries whose period ends within this many days. `0` lists entries whose period ends less than a day away. A negative value lists every empty folder. |
| `--all` | | `false` | List every empty folder, ignoring `--within-days` |

Exit codes: `0` whenever the scan completes, whatever it finds. If the storage cannot be opened
or listed, it prints why and still exits `0`. `3` for a missing or invalid config, an unknown
framework or an invalid `-o`.

In GitHub Actions it also writes `::warning` annotations (at most ten) and a table to the job
summary. Annotations don't change the job result.

## `sigcomply version`

```sh
sigcomply version
```

Prints `sigcomply <version> (commit <commit>, built <time>)`. No flags.

## `sigcomply completion`

```sh
sigcomply completion <bash|zsh|fish|powershell>
```

Prints a shell completion script. `sigcomply completion <shell> --help` explains how to load it.

## Commands that don't exist

`collect`, `evaluate`, `config`, `evidence init` and `evidence path` are not commands.

## See also

- [Configuration](../configuration.md): every `.sigcomply.yaml` key and environment variable.
- [Frameworks](frameworks.md): framework IDs and counts.
