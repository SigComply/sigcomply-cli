# Commands

Reference for every wired `sigcomply` command, its flags, and its exit codes.

Back to the [documentation hub](../README.md).

## Exit codes (all commands)

| Code | Meaning |
|---|---|
| `0` | Passed — no violations |
| `1` | Violations found |
| `2` | Execution error |
| `3` | Configuration error |

## Framework resolution differs by command

| Command | How the framework is chosen |
|---|---|
| `init`, `evidence catalog` | `-f/--framework` flag → `SIGCOMPLY_FRAMEWORK` env → `soc2` default |
| `evidence due` | `-f/--framework` flag → `framework:` from config → `SIGCOMPLY_FRAMEWORK` env → `soc2` default |
| `check` | `framework:` from the loaded config **only** (no flag, ignores `SIGCOMPLY_FRAMEWORK`); missing → exit 3 |
| `init-ci`, `report` | Default framework from config |

## `sigcomply check`

```bash
sigcomply check [flags]
```

Runs the full pipeline: plan policies for the framework and period, collect evidence from bound sources, evaluate each policy, persist signed envelopes + per-policy results + run manifest to the vault, and optionally submit aggregated counts to the cloud.

The run-mode flags `--cadence`, `--cadences`, `--on-push`, `--pr`, and `--scheduled` are **mutually exclusive**.

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--cadence <value>` | | | Run one cadence: `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual` |
| `--cadences <csv>` | | | Intersect multiple cadences (comma-separated); `on_push` is a virtual value |
| `--on-push` | | | Push-mode run (on_push filter) |
| `--pr` | | | PR-mode: on_push filter with a ~8 min/slot retry budget |
| `--scheduled` | | | Consult per-framework execution state, run due cadences, advance state |
| `--cloud` | | | Force cloud submission (requires OIDC) |
| `--no-cloud` | | | Disable cloud submission |
| `--cloud-url <url>` | | | Override the cloud endpoint |
| `--capture-cloud-payload <file>` | | | Write the submission payload to a file instead of POSTing (auditor escape hatch) |
| `--config <path>` | `-c` | `.sigcomply.yaml` | Config file path |
| `--verbose` | `-v` | `false` | Verbose output |

`check` has **no** `--framework` flag and ignores `SIGCOMPLY_FRAMEWORK`.

Exit codes: `0` passed · `1` violations (when `ci.fail_on_violation` is set) · `2` execution error · `3` config error (including a missing `framework:`).

## `sigcomply init`

```bash
sigcomply init [flags]
```

Writes a ready-to-edit `.sigcomply.yaml` that runs out of the box (local vault, auto-binding).

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--framework <value>` | `-f` | `$SIGCOMPLY_FRAMEWORK` → `soc2` | Framework: `soc2` or `iso27001` |
| `--out <path>` | `-o` | `.sigcomply.yaml` | Output path |
| `--force` | | `false` | Overwrite an existing file (otherwise refuses → exit 3) |

## `sigcomply init-ci`

```bash
sigcomply init-ci --ci <github|gitlab> [flags]
```

Scaffolds CI workflow files calibrated to the framework's cadence distribution.

- **GitHub**: writes one workflow per cadence under `.github/workflows/`: `compliance-daily.yml`, `compliance-weekly.yml`, `compliance-monthly.yml`, `compliance-quarterly.yml`, `compliance-annual.yml`, `compliance-on-push.yml`.
- **GitLab**: writes a single `.gitlab-ci.yml` at the repo root with cadence-keyed jobs driven by pipeline schedules (`$CADENCE`).

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--ci <value>` | | | **Required.** `github` or `gitlab` |
| `--framework <value>` | | Config framework → `soc2` | Framework |
| `--out <path>` | | `.github/workflows/` (github), repo root (gitlab) | Output location |
| `--force` | | `false` | Overwrite existing files |
| `--config <path>` | `-c` | `.sigcomply.yaml` | Config file path |

**SOC 2 only in v1-alpha.** Any other framework → exit 3 (`framework %q not supported in v1-alpha`).

## `sigcomply build`

```bash
sigcomply build [flags]
```

Compiles a project-tailored binary that includes Go extensions under `.sigcomply/`; a no-op if none exist. Extensions cannot import `os/exec` or `net`/`net/*` (security boundary). Most customers never need this command.

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--project <dir>` | | `.` | Project directory |
| `--output <path>` | | `./bin/sigcomply` | Output binary path |
| `--tags <csv>` | | | Extra Go build tags |
| `--ldflags <str>` | | | Extra linker flags |
| `--verbose` | `-v` | `false` | Verbose output |

## `sigcomply report`

```bash
sigcomply report [flags]
```

Read-only vault snapshot. Never writes to the vault, never calls the cloud, never needs OIDC.

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--config <path>` | `-c` | `.sigcomply.yaml` | Config file path |
| `--vault <uri>` | | | Vault location — paths or `s3://`, `gs://`, `az://`, `file://` |
| `--framework <value>` | `-f` | Config framework | Framework |
| `--period <id>` | | | **Required** (e.g. `2026-Q1`); missing → exit 3 |
| `--view <value>` | | `latest` | `latest`, `exceptions`, `integrity`, or `scope` |
| `--format <value>` | | `text` | `text`, `json`, `csv`, `pdf` (`pdf` deferred to v1.x → exit 3 if used) |
| `--out <file>` | | | Required for non-text formats (else exit 3); text goes to stdout |

Views: `latest` = current pass/fail state per policy; `exceptions` = the waivers/NA register; `integrity` = run-by-run signature/manifest verification; `scope` = what the run was supposed to cover and what it actually evaluated.

`--view scope` answers the question the other views assume away: *did this
run look at everything it should have?* It shows the declared estate and
how each declared source fared (for projects that set
`experimental.scope`), plus every control the latest run did **not**
evaluate, with the reason. That second half renders whether or not an
estate was declared — a skipped control leaves the compliance-score
denominator entirely, so it is exactly what an all-green run can hide.

## `sigcomply evidence catalog`

```bash
sigcomply evidence catalog [-f <framework>] [-o <text|json>]
```

Prints the framework's manual-evidence catalog. Works without a project config. `-o json` matches the Evidence SPA's Catalog contract.

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--framework <value>` | `-f` | `$SIGCOMPLY_FRAMEWORK` → `soc2` | Framework |
| `--output <value>` | `-o` | `text` | `text` or `json` |

## `sigcomply evidence due`

```bash
sigcomply evidence due [-c <config>] [-f <framework>] [-o <text|json>] [--within-days <n>] [--all]
```

Lists manual-evidence catalog entries whose folder for the **current period** is
still empty, so the upload can happen before a scheduled run needs it.

An entry is reported only when its folder is genuinely empty. Once the file is
uploaded the entry disappears from the report — the notice never nags about work
already done, which is what keeps it worth reading.

The period is derived from the HEAD commit's timestamp, exactly as `check`
derives it, so the folder reported here is the folder the next run will read.

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--config <path>` | `-c` | `.sigcomply.yaml` | Project config |
| `--framework <value>` | `-f` | config → `$SIGCOMPLY_FRAMEWORK` → `soc2` | Framework |
| `--output <value>` | `-o` | `text` | `text` or `json` |
| `--within-days <n>` | | `30` | Only report entries whose period ends within this many days. Overdue entries always report. |
| `--all` | | `false` | Report every entry with an empty folder, ignoring `--within-days` |

**Exit codes.** `0` whenever the scan completes, *including* when evidence is
overdue — this command is advisory and is never the reason a build goes red.
`3` for a missing or invalid config, an unknown framework, or a bad `-o`. If the
evidence store cannot be opened or listed (missing credentials, for instance) it
says so and still exits `0`: an unverifiable folder is an unknown, and reporting
unknowns as deadlines is how a warning loses its meaning.

**Access.** Read-only. It issues `LIST` calls only — no file bytes are
downloaded, nothing is written, no cloud API is contacted, and no OIDC token is
needed.

Under GitHub Actions (`GITHUB_ACTIONS=true`) it additionally emits `::warning`
annotations, capped at GitHub's ten-per-step limit with an overflow line, and
appends a Markdown table to `$GITHUB_STEP_SUMMARY`. Annotations never change a
job's conclusion. GitLab has no workflow-command equivalent, so there the output
stays plain text.

`sigcomply init-ci` wires this into the daily workflow as a non-failing step.

## `sigcomply version`

```bash
sigcomply version
```

Prints version, commit, and build time. No flags.

## Not available

These commands are not wired and must not be used: `collect`, `evaluate`, `config`, `evidence init`, `evidence path`.

## See also

- [Configuration](../configuration.md) — full `.sigcomply.yaml` schema and env vars.
- [Frameworks](frameworks.md) — shipped frameworks and policy/catalog overview.
- [Documentation hub](../README.md).
