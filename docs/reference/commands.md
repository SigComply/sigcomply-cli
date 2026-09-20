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

Compiles a project-tailored binary that includes Go extensions under `.sigcomply/`; a no-op if none exist. Extensions cannot directly import `os/exec` or `net`/`net/*` — a deny-list over the direct imports of each extension directory's top-level files, not a sandbox. Most customers never need this command.

Two caveats worth knowing before you reach for it:

- **Go extensions currently need a fork.** The plugin APIs a Go extension must import (`core.SourcePlugin`, `sources.RegisterFactory`, `vault.RegisterBackend`, `manual.Reader`) live under `internal/`, and this command compiles your package inside *your* module — so `go build` rejects the import. Project-local **YAML policies**, **Rego rules**, and **evidence-type JSON schemas** need no build step at all: they load at every `check`. See [`07-extensibility.md`](../architecture/07-extensibility.md) §Status.
- **Two discovered kinds are compiled but never loaded.** A Go rule package (`.sigcomply/policies/<id>/rules/`) and a Go evidence-type package (`.sigcomply/evidence_types/<id>/`) have no registration hook, so the build prints `warning: … is compiled in but has no registration hook and will not be loaded` for each. Use a `rule.rego` and an `evidence_types/<id>.v<n>.json` instead.

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
| `--view <value>` | | `latest` | `latest`, `exceptions`, `integrity`, `scope`, `coverage`, or `soa` |
| `--format <value>` | | `text` | `text`, `json`, `csv`, `pdf` (`pdf` deferred to v1.x → exit 3 if used) |
| `--out <file>` | | | Required for non-text formats (else exit 3); text goes to stdout |

Views: `latest` = current pass/fail state per policy; `exceptions` = the waivers/NA register; `integrity` = run-by-run signature/manifest verification; `scope` = what the run was supposed to cover and what it actually evaluated; `coverage` = what kind of check stands behind each control; `soa` = the ISO 27001 Statement of Applicability.

`--view scope` answers the question the other views assume away: *did this
run look at everything it should have?* It shows the declared estate and
how each declared source fared (for projects that set
`experimental.scope`), plus every control the latest run did **not**
evaluate, with the reason. That second half renders whether or not an
estate was declared — a skipped control leaves the compliance-score
denominator entirely, so it is exactly what an all-green run can hide.

`--view coverage` answers what the compliance score cannot: *is this
control actually inspected, or does it merely have a document on file?*
A policy satisfied by a PDF sitting in the evidence folder and one that
inspected live infrastructure both pass, and both count the same toward
the score. For SOC 2, 27 of 43 criteria are the first kind — the whole
CC1–CC5 governance spine. The view reports, per control, which kind of
check stands behind it, how many of each, and whether the evidence exists
for this period.

It is framework-scoped rather than run-scoped on purpose. Cadence is
independent of the audit period: a control checked annually produces no
result at all in three quarters out of four, so a view built only from the
period folder would show a clean bill of health over whatever happened to
run. Every declared control gets a row; one with no result says so and
names its cadence, so "annual, expected" is distinguishable from "daily,
broken". A control whose evidence mode the project overrode is marked.

```bash
sigcomply report --period 2026-Q3 --view coverage
```

```
43 of 43 catalog controls have a check
  16 automated  — verified by inspecting your infrastructure
  27 manual     — a document is on file; its contents are not inspected

This period
  41 evaluated, 2 not evaluated
  0 manual control(s) with evidence on file, 27 without
```

The `KIND` column separates the two things a framework calls a control. For
ISO 27001 it is `catalog` for the 93 Annex A controls and `mgmt-system` for the
16 clause 4-10 requirements, and the headline counts them apart — sixteen ISMS
documents nobody has uploaded must not read as coverage of the Annex A catalog.
SOC 2 has no management-system requirements, so every row there is `catalog`.

`--view soa` generates the **Statement of Applicability** that ISO/IEC
27001:2022 clause 6.1.3 d requires and a Stage 1 auditor asks for first. It
answers four questions per Annex A control — is it necessary, why, is it
implemented, and if it was left out, why — by joining the framework's control
catalog, the project's applicability decisions, and the period's results.

Only catalog controls are listed. The clause 4-10 management-system
requirements are not selectable — an organization cannot decline to have an
internal audit program — so they are counted in the note and never given a
row. Status is derived from this period's results and never from the catalog: a
control whose checks did not run reports `not evaluated`, which is not the same
as implemented. A policy resolved to `na` counts as a check that did not run and
abstains from the roll-up; a carried-forward policy counts as the pass it
inherits.

**`--view soa` requires the project config.** The applicability decisions are
authored in `.sigcomply.yaml` and exist nowhere else — not in the vault, not in
the framework — so a run with only `--vault` and `--framework` would report
every control as applicable and silently turn a deliberate exclusion into an
inclusion. It exits `3` instead. Pass `-c <path to .sigcomply.yaml>`, or drop
`--vault`/`--framework` so the config is read.

Record the inclusion reasoning with `controls.<id>.justification` in
`.sigcomply.yaml`; where it is absent SigComply derives one from the checks
standing behind the control and marks it `(derived)`, so an auditor can tell a
reasoned inclusion from a default one. An excluded control uses `reason`
instead — setting both is a config error.

```bash
sigcomply report --period 2026-Q3 --view soa
sigcomply report --period 2026-Q3 --view soa --format csv --out soa.csv
```

```
93 catalog controls: 91 applicable, 2 excluded

Of the 91 applicable
  24 implemented           — every check that ran passed
   2 partially implemented — some checks passed, some did not
   3 not implemented       — every check that ran failed
  62 not evaluated         — no check ran this period

Note: 16 management-system requirements (clauses 4-10) are outside the Statement of Applicability and cannot be excluded; see report --view coverage. 62 applicable controls produced no result this period — not evaluated is not implemented. 88 inclusions carry a derived justification; set controls.<id>.justification to record the organization's own reasoning.

CONTROL  NAME                               APPLICABLE  STATUS           ASSURANCE  JUSTIFICATION
A.5.1    Policies for information security  yes         implemented      manual     (derived) Applicable — no exclusion declared. Evidenced by 1 manual evidence item.
A.5.15   Access control                     yes         not implemented  automated  (derived) Applicable — no exclusion declared. Verified by 2 automated checks.
A.7.1    Physical security perimeters       no          excluded         none       Fully remote; no corporate premises in scope.
A.8.5    Secure authentication              yes         implemented      automated  MFA on the cloud console is our primary control against credential theft.
...
```

`--format csv` gives the spreadsheet auditors expect: one row per Annex A
control with `control_id`, `name`, `applicable`, `justification`,
`justification_derived`, `status`, `assurance`, `evaluated`, `policies`, and
`approved_by`.

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

A **fan-out** entry is listed once per member of its declared set, named so the
row says which one is missing (`vendor_assurance [Acme Cloud Platform]`) rather
than that one of them is. Members that owe no artifact — a `low`-tier vendor,
which discharges its obligation with a recorded rationale and approver — have no
deadline and are not listed. See
[Vendor and third-party risk](../guides/vendor-risk.md).

| Flag | Shorthand | Default | Meaning |
|---|---|---|---|
| `--config <path>` | `-c` | `.sigcomply.yaml` | Project config |
| `--framework <value>` | `-f` | config → `$SIGCOMPLY_FRAMEWORK` → `soc2` | Framework |
| `--output <value>` | `-o` | `text` | `text` or `json` |
| `--within-days <n>` | | `30` | Only report entries whose period ends within this many days. `0` reports only what closes today; a negative value reports everything. Each entry's period is its own cadence window — an annual entry's ends 31 December, a quarterly entry's ends with the quarter. |
| `--all` | | `false` | Report every entry with an empty folder, ignoring `--within-days` |

**Exit codes.** `0` whenever the scan completes, whatever it finds — this
command is advisory and is never the reason a build goes red.
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
