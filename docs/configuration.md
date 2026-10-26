# Configuration reference

`sigcomply check` reads one YAML file, `.sigcomply.yaml`, from the current directory. Pass
`-c/--config <path>` to read another file. There is no home-directory fallback. A missing file
stops the run with `no config file found at <path>` and exit code `3`. Run `sigcomply init` to
write a starter file.

The file sets the framework, the audit period, where evidence is stored, which sources to read,
and per-policy and per-control decisions. Credentials come from environment variables and each
cloud SDK's credential chain, not from this file. Command-line flags select the run mode; they
are listed in [Commands](reference/commands.md). Per-source keys, credentials, and permissions
are in the [source reference](reference/sources.md).

## Minimal example

```yaml
schema_version: project.v1
framework: soc2
sources:
  manual.pdf:
    path: ./evidence
```

This loads and runs with no credentials. Without an API source, every automated policy is
skipped. A full example is at the [end of this page](#full-example).

## How the file is checked

| Block | Unknown key | Wrong value |
|---|---|---|
| Top level, `period`, `policies`, `controls`, `cloud`, `output`, `ci`, `extensions` | Config error, exit `3` | Config error, exit `3` |
| `sources.<id>` | Warning: `unrecognized key ..., so it was ignored` | Warning for a non-string value; the source's own check may then fail with exit `3` |
| `vault` | Ignored with no warning | The backend reports missing required keys, exit `3` |
| `experimental.scope`, `.vendors`, `.risks`, `.roster` | Warning | See each block |

A policy ID or control ID that the framework does not define is a config error with a "did you
mean" suggestion.

## Top-level keys

| Key | Type | Default | Effect |
|---|---|---|---|
| `schema_version` | string | none, required | Must be `project.v1`. |
| `framework` | string | none, required | The one framework this project evaluates: `soc2` or `iso27001`. Any other value is a config error. `check` reads only this key; it ignores `SIGCOMPLY_FRAMEWORK`. |
| `period` | map | calendar quarters, commit time | How the audit period is derived. See [`period`](#period). |
| `vault` | map | `backend: local`, `path: ./.sigcomply/vault` | Where signed evidence, results and the run manifest are written. See [`vault`](#vault). |
| `sources` | map | none | The sources to read. See [`sources`](#sources). |
| `policies` | map | none | Per-policy bindings, cadence, evidence mode, and exceptions. See [`policies`](#policies). |
| `controls` | map | none | Per-control applicability decisions. See [`controls`](#controls). |
| `cloud` | map | none | SigComply Cloud submission. See [`cloud`](#cloud). |
| `ci` | map | `fail_on_violation: true` | Exit-code behaviour. See [`ci`](#ci). |
| `experimental` | map | none | Declarations for scope, vendors, risks, and the identity roster. See [`experimental`](#experimental). |
| `output.format` | string | none | Accepted; has no effect. Must be `text`, `json` or `junit` if set. |
| `output.json_path` | string | none | Accepted; has no effect. |
| `output.verbose` | bool | `false` | Accepted; has no effect. Use the `-v` flag. |
| `ci_environment` | map | none | Accepted; has no effect. The run's CI metadata comes from [CI variables](#ci-and-git-context). |
| `extensions.path` | string | none | Accepted; has no effect. `sigcomply build` always reads `.sigcomply/`. |

## `period`

| Key | Type | Default | Allowed values | Effect |
|---|---|---|---|---|
| `period.fiscal_calendar.type` | string | `calendar_quarter` | `calendar_quarter`, `fiscal_year`, `custom` | Sets the run's period ID: `2026-Q1`, `FY2026`, or a custom `id`. |
| `period.fiscal_calendar.starts` | string | `january` | Month name, any case | First month of the fiscal year. Read only for `fiscal_year`. `FY2026` is the year that starts in that month of 2026. |
| `period.fiscal_calendar.periods` | list | none | `{id, start, end}`, dates `YYYY-MM-DD` | Required for `custom`. `end` is inclusive. A run whose clock falls in no listed period fails. |
| `period.time_basis` | string | `commit` | `commit`, `wall_clock` | `commit` takes the period from the HEAD commit's time, so re-running an old commit gives the same period. `wall_clock` uses the run's start time. |

The run's period names the vault folder for the run and the period sent to SigComply Cloud.
Manual evidence folders use each catalog entry's own cadence window instead (for example `2026`
for an annual entry). See [Manual evidence](guides/manual-evidence.md).

## `vault`

`vault` is one flat map: `backend` plus that backend's keys, with no nested sub-blocks. Omit the
block to write to `./.sigcomply/vault`. Keys per backend are in
[Storage backends](#storage-backends).

| Key | Type | Default | Allowed values |
|---|---|---|---|
| `vault.backend` | string | `local` | `local`, `s3`, `gcs`, `azure_blob` |

For tamper resistance, the bucket must be write-once or versioned at the storage layer. The CLI
does not configure this. See [SECURITY.md](../SECURITY.md).

## `sources`

`sources` maps a source key to that source's settings:

```yaml
sources:
  aws.iam:
    region: us-east-1
  github:
    org: acme
```

| Rule | Detail |
|---|---|
| Source key | A source ID from the [source reference](reference/sources.md), optionally followed by `[instance]`. Letters, digits, `.`, `_` and `-` only; the key becomes part of evidence file paths. |
| Settings | Each source's keys are listed in the [source reference](reference/sources.md). Values are strings unless the reference says otherwise. Quote numeric IDs: `project_id: "12345"`. |
| Binding | The CLI binds every configured source to every policy slot that accepts a type the source emits. Narrow this with [`policies.<id>.bindings`](#policies). |
| Credentials | Each listed source resolves its credentials before collection. Missing or unusable credentials are a config error, exit `3`. |
| `manual.pdf` | The manual-evidence source. One per project; it takes no `[instance]` suffix. If it is not configured, every manual policy ends with status `error` and the run exits `2`. |
| AWS region | An `aws.*` source without `region` uses `vault.region` when the vault sets one, then the AWS SDK's own region setting (`AWS_REGION`). |

### Multiple instances of one source

A bracket suffix configures the same source a second time, for a second account, organization or
directory:

```yaml
sources:
  aws.iam:
    region: us-east-1
  "aws.iam[staging]":
    region: us-east-1
    role_arn: arn:aws:iam::210987654321:role/SigComplyAudit
  "github[labs]":
    org: acme-labs
    token_env: GITHUB_TOKEN_LABS
```

| Rule | Detail |
|---|---|
| One key, one source | An instance covers only the source it names. To read `aws.s3` in a second account too, add `"aws.s3[staging]"` with the same `role_arn`. |
| Identity | The full key (`aws.iam[staging]`) is the source's identity in `bindings`, in each record's `source_id`, and in evidence file names. |
| Resource IDs | Records from an instanced source carry the instance in their ID: `aws.iam[staging]/account`. A `resource_id` exception must use that form. `resource_pattern: "aws.iam[staging]/*"` scopes an exception to one instance. |
| Roster matching | `experimental.roster` `aliases` and `non_human` entries match the prefixed or the bare ID. |
| Separate credentials | `aws.*`: `role_arn` (plus optional `external_id`, `role_session_name`). `github`, `gitlab`, `okta`, `active_directory`: `token_env` naming an environment variable, or the token key. |
| One identity only | `gcp.*` and `azure.*` use one ambient identity per run. Instances vary only the project, organization, or subscription queried. |
| Region | Two `aws.*` instances that differ only by `region` read the same account twice. |
| Not allowed | `manual.pdf[...]`; a bracketed source as `experimental.roster.source`. |

### Source key warnings

Before credentials are resolved, the CLI warns about keys a source does not read and about
values that are not strings:

```text
[warn] source-config: sources.aws.iam: unrecognized key "role_am", so it was ignored; aws.iam reads [external_id region role_arn role_session_name]
[warn] source-config: sources.gcp.compute: "project_id" is int, not a string, so it reads as unset; quote it (project_id: "12345")
```

Warnings never stop a run. Two sources produce warnings that are wrong:

| Source | Warning | What to do |
|---|---|---|
| `manual.pdf` | `region`, `endpoint`, `force_path_style`, `account` and `container` are reported as ignored. | Ignore it. The `s3` and `azure_blob` backends read these keys. |
| `active_directory` | `start_tls`, `page_size`, `timeout` (as seconds) and `service_account_ous` are reported as not strings. | Ignore it. Keep these values unquoted; quoting them makes the source fail with exit `3`. |

### Source caveats

Some sources emit a field they cannot read, with a default value that can fail a policy but
never pass it. The plan prints a `source-caveat:` warning naming the affected policies. The list
of caveats is in the [source reference](reference/sources.md#source-caveats).

## `policies`

`policies` maps a policy ID to its settings. Every key is optional. Each `check` summary prints
the policy IDs it evaluated.

| Key | Type | Default | Effect |
|---|---|---|---|
| `bindings` | map of slot name to list | every source whose types the slot accepts | Limits a slot to the listed sources. An entry is a source key (`okta`) or a map `{source: okta, slot_params: {...}}`. `slot_params` are passed to that source for this binding. Slot names appear in the `check` output, for example `(slot "evidence")`. |
| `parameters` | map | none | Overrides a parameter the policy declares. Shipped SOC 2 and ISO 27001 policies declare none, so this works only for project-local policies. An unknown parameter is a config error. |
| `cadence` | string | the framework's cadence | How often the policy is re-evaluated. See [cadence values](#cadence-values). For a manual policy, it does not move the upload folder. |
| `evidence_mode` | string | the framework's mode | `automated` or `manual`. Switches the policy to the other flow. The result records that the mode was overridden. |
| `catalog_entry` | string | none | Required when `evidence_mode: manual`; not allowed otherwise. The manual-evidence entry (folder name) to read. |
| `exceptions` | list | none | Waivers and not-applicable declarations. See below. |

### Exceptions

| Key | Type | Default | Effect |
|---|---|---|---|
| `state` | string | none, required | `waived` or `na`. |
| `reason` | string | none, required | Why the exception exists. Stored in the vault. |
| `scope.resource_id` | string | none | Applies to failures on this one resource. |
| `scope.resource_pattern` | string | none | Applies to resources whose ID matches. A trailing `*` matches any suffix; otherwise the match is exact. |
| `approved_by` | string | none | Who approved it. |
| `approved_at` | string | none | `YYYY-MM-DD`. |
| `expires_at` | string | none | `YYYY-MM-DD`, inclusive. After this day the exception is ignored and the policy is evaluated normally. |

Without a scope, the exception applies to the whole policy: the policy's status becomes `waived`
or `na` and it is not evaluated. With a scope, matching failures are removed; if none remain, the
status becomes `waived`. Only the first unexpired exception in the list applies.

### Cadence values

| Value | Re-evaluated after |
|---|---|
| `continuous` | every run |
| `hourly` | every run |
| `daily` | 23 hours |
| `weekly` | 6 days 23 hours |
| `monthly` | 29 days 23 hours |
| `quarterly` | 89 days 23 hours |
| `annual` | 364 days 23 hours |
| `every:<duration>` | the Go duration given, at least `5m`: `every:6h`, `every:2h30m` |

The interval counts from the policy's last pass. A policy that failed, or whose definition
changed, is re-evaluated on the next run. Which runs gate on cadence is set by the run-mode flags
in [Commands](reference/commands.md).

## `controls`

`controls` maps a control ID (`CC6.4`, `A.5.1`) to a decision. `sigcomply report --view soa`
reads these keys.

| Key | Type | Default | Effect |
|---|---|---|---|
| `applicability` | string | applicable | `applicable` or `not_applicable`. `not_applicable` sets every policy mapped to the control to `na`. |
| `reason` | string | none | Required with `not_applicable`: why the control is excluded. |
| `justification` | string | none | Why an applicable control is included. Not allowed with `not_applicable`. |
| `approved_by` | string | none | Who approved the decision. |

ISO 27001 clause controls (IDs starting with `C.`) cannot be `not_applicable`; that is a config
error.

## `cloud`

| Key | Type | Default | Effect |
|---|---|---|---|
| `cloud.base_url` | string | none | SigComply Cloud endpoint. Set `https://sigcomply.com` to submit. With no value and no `--cloud-url` flag, nothing is submitted. |
| `cloud.enabled` | bool | none | Accepted; has no effect. |

A run submits when `cloud.base_url` (or `--cloud-url`, which overrides it) is set, the run is in
CI, and an OIDC token is available. `--no-cloud` turns submission off. Only per-policy counts are
sent. Setup: [Cloud dashboard](guides/cloud-dashboard.md).

## `ci`

| Key | Type | Default | Effect |
|---|---|---|---|
| `ci.fail_on_violation` | bool | `true` | When `true`, a failing policy or an incomplete `experimental.scope` exits `1`. When `false`, those runs exit `0`. Errors still exit `2`. |
| `ci.fail_severity` | string | none | Accepted; has no effect. Must be `info`, `low`, `medium`, `high` or `critical` if set. |

## `experimental`

The loader does not check these blocks itself; each feature reads its own key and reports its
own errors. An unknown sub-key prints a warning.

<a id="experimentalscope--declaring-the-estate"></a>

### `experimental.scope`

Declares the sources this project claims to cover. Without it, a source you never configured
causes skipped policies, not failures.

| Key | Type | Effect |
|---|---|---|
| `declared_by` | string | Who made the declaration. Stays in the vault. |
| `declared_at` | string | `YYYY-MM-DD`. |
| `required_sources` | list of source keys | Each must be configured, bound to at least one policy slot, and return at least one record. Otherwise the run prints `SCOPE INCOMPLETE` and exits `1` (see `ci.fail_on_violation`). |

A malformed block (empty `required_sources`, bad date) prints
`[warn] scope: ignoring experimental.scope` after collection and the run continues as if the
block were absent. The verdict is written to `summary.json` and shown by
`sigcomply report --view scope`.

<a id="experimentalvendors--declaring-the-third-party-register"></a>

### `experimental.vendors`

Declares third-party vendors. Vendor-assurance manual entries then expect one folder per vendor:
`{prefix}{entry}.{vendor_id}/{period}/`. Walkthrough: [Vendor risk](guides/vendor-risk.md).

| Key | Type | Required | Effect |
|---|---|---|---|
| `declared_by`, `declared_at` | string | no | Audit trail; `declared_at` is `YYYY-MM-DD`. |
| `register[].id` | string | yes | 1 to 40 characters of `a-z`, `0-9`, `_`, `-`, starting with a letter or digit. Used in folder names. |
| `register[].name` | string | yes | Display name. |
| `register[].tier` | string | yes | `critical`, `high`, `moderate` or `low`. |
| `register[].tier_rationale` | string | for `low` | Why the vendor is low tier. |
| `register[].approved_by` | string | for `low` | Who approved the low tier. |
| `register[].subservice` | bool | no | Marks a SOC 2 subservice organization. |
| `register[].services` | string | no | What the vendor provides. |
| `register[].assurance_period_end` | string | no | `YYYY-MM-DD`, the last day the vendor's report covers. The check fails when it is more than 15 months before the audit period starts. |
| `register[].providers` | list | no | Configured sources this vendor supplies: a provider (`aws`) or a source key (`aws.iam`). A configured source no vendor claims prints a plan-time warning. |

<a id="experimentalrisks--declaring-the-risk-register"></a>

### `experimental.risks`

Declares the risk register. `sigcomply report --view soa` then names the risks each control
treats. Walkthrough: [ISMS clauses](guides/isms-clauses.md).

| Key | Type | Required | Effect |
|---|---|---|---|
| `declared_by`, `declared_at` | string | no | Audit trail; `declared_at` is `YYYY-MM-DD`. |
| `register[].id` | string | yes | 1 to 40 characters of `a-z`, `0-9`, `_`, `.`, `-`, starting with a letter or digit. |
| `register[].description` | string | yes | The risk. |
| `register[].owner` | string | yes | Risk owner. |
| `register[].level` | string | yes | `critical`, `high`, `moderate` or `low`. |
| `register[].treatment` | string | yes | `modify`, `retain`, `avoid` or `share`. `mitigate`, `reduce` and `decrease` mean `modify`; `accept` means `retain`; `transfer` means `share`. |
| `register[].controls` | list | for `modify` | The control IDs that treat the risk. An unknown control prints a warning. |
| `register[].residual_level` | string | yes | Same values as `level`. |
| `register[].accepted_by` | string | for `retain` | Who accepted the risk. |
| `register[].acceptance_rationale` | string | for `retain` | Why it was accepted. |
| `register[].assessed_at` | string | yes | `YYYY-MM-DD`. More than 18 months before the period start prints a warning. |

<a id="experimentalroster--designating-the-identity-roster"></a>

### `experimental.roster`

Names the source that lists your people, for the policies that check accounts in other systems
against it. Without this block those policies are skipped. Walkthrough:
[Identity roster](guides/identity-roster.md).

| Key | Type | Required | Effect |
|---|---|---|---|
| `source` | string | yes | A configured, unbracketed source that emits `roster_entry`: `okta`, `azure.entra`, `gcp.directory`, `active_directory` or `aws.identity_center`. |
| `aliases` | map of source key to `{account: roster_email}` | no | Links accounts that have no email, or a different one. Matched case-insensitively against the record's ID, username, or IAM principal. |
| `non_human` | map of source key to list | no | Accounts that are not people, such as bots and deploy users. |

These are config errors (exit `3`): `source` missing, bracketed, not configured, or not emitting
`roster_entry`; an `aliases` or `non_human` key that is not a configured source; an empty alias;
one account aliased to two emails. Alias and `non_human` entries that match no account print
`unused-alias:` and `unused-non-human:` lines.

## Environment variables

### SigComply

| Variable | Read by | Effect |
|---|---|---|
| `SIGCOMPLY_FRAMEWORK` | `init`, `evidence catalog`, `evidence due` | Framework when `-f` is not given (and, for `evidence due`, the config sets none). `check` ignores it. |
| `SIGCOMPLY_ID_TOKEN`, `ID_TOKEN` | `check` | OIDC token for SigComply Cloud in GitLab CI. Define an `id_tokens:` entry with one of these names. |
| `ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | `check` | Set by GitHub Actions when the job has `id-token: write`; the CLI uses them to request an OIDC token. |
| `SIGCOMPLY_AD_BIND_PASSWORD` | `active_directory` source | Bind password when the config sets neither `bind_password` nor `token_env`. |

### Source credentials

| Variable | Used by |
|---|---|
| `GITHUB_TOKEN` | `github`, when the config sets neither `token` nor `token_env` |
| `GITLAB_TOKEN` | `gitlab`, when the config sets neither `token` nor `token_env` |
| `OKTA_API_TOKEN` | `okta`, when the config sets neither `api_token` nor `token_env` |
| Any name in `token_env` | the source that names it; an empty or unset variable is an error |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `AWS_REGION`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` | `aws.*` sources, `s3` vault and `manual.pdf` backend, through the AWS SDK credential chain |
| `GOOGLE_APPLICATION_CREDENTIALS` | `gcp.*` sources, `gcs` vault and `manual.pdf` backend, through Application Default Credentials |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_FEDERATED_TOKEN_FILE` | `azure.*` sources, `azure_blob` vault and `manual.pdf` backend, through `DefaultAzureCredential` |

### CI and git context

| Variable | Effect |
|---|---|
| `GITHUB_SHA`, then `CI_COMMIT_SHA` | Commit SHA recorded for the run. Without either, the CLI runs `git rev-parse HEAD`. |
| `GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP` | Commit time, which sets the audit period when `time_basis: commit`. Without it, the CLI runs `git show -s --format=%cI HEAD`; if that fails, it uses the current time. |
| `GITHUB_REF_NAME`, then `CI_COMMIT_REF_NAME`, then `GIT_BRANCH` | Branch recorded for the run. |
| `CI`, `GITHUB_ACTIONS`, `GITLAB_CI` | Any of these marks the run as in CI, which cloud submission requires. |
| `GITHUB_WORKFLOW`, `GITHUB_RUN_ID`, `GITHUB_REPOSITORY` | GitHub Actions workflow name and run URL recorded for the run. |
| `CI_JOB_NAME`, `CI_JOB_URL` | GitLab CI job name and URL recorded for the run. |
| `GITHUB_STEP_SUMMARY` | `evidence due` appends its report to this file. When `GITHUB_ACTIONS=true` it also prints workflow annotations. |

## Storage backends

`vault` and `sources.manual.pdf` use the same backend names and similar keys, but they are read
separately and their key sets differ. Credentials come from each provider's ambient chain; no
storage block takes credential keys.

| Backend | `vault` keys | `manual.pdf` keys |
|---|---|---|
| `local` | `path` (default `./.sigcomply/vault`) | `path` (required); `prefix` (default `manual/`); `bucket` (defaults to `path`; files are always read from under `path`) |
| `s3` | `bucket`, `region` (required); `prefix` (default none); `endpoint`, `force_path_style` (bool) for S3-compatible stores | `bucket`, `region` (required; `region` falls back to `vault.region`); `prefix` (default `manual/`); `endpoint`, `force_path_style` |
| `gcs` | `bucket` (required); `prefix` | `bucket` (required); `prefix` (default `manual/`) |
| `azure_blob` | `account`, `container` (required); `prefix` | `account`, `container` (required); `prefix` (default `manual/`) |

`backend` defaults to `local` in both blocks. The vault adds a trailing `/` to a `prefix` that
lacks one. `manual.pdf` uses its `prefix` as written: manual evidence is read from
`{prefix}{evidence_catalog_id}/{period_id}/` under the bucket (or `path`), so end the prefix with
`/`. See [Manual evidence](guides/manual-evidence.md).

## Sources by provider

Each provider's source IDs, keys, credentials, permissions and caveats are in the source
reference.

## AWS

See [AWS in the source reference](reference/sources.md#aws).

## GCP

See [GCP in the source reference](reference/sources.md#gcp).

## Azure

See [Azure in the source reference](reference/sources.md#azure).

## GitHub

See [GitHub in the source reference](reference/sources.md#github).

## GitLab

See [GitLab in the source reference](reference/sources.md#gitlab).

## Okta

See [Okta in the source reference](reference/sources.md#okta).

## Active Directory

See [Active Directory in the source reference](reference/sources.md#active-directory).

<a id="folder-layout-per-evidence-id"></a>

## Manual evidence

See [Manual evidence in the source reference](reference/sources.md#manual-evidence) for the
`manual.pdf` keys, and the [Manual evidence guide](guides/manual-evidence.md) for the folder
layout.

## Full example

```yaml
schema_version: project.v1
framework: soc2

period:
  fiscal_calendar:
    type: fiscal_year
    starts: april
  time_basis: commit

vault:
  backend: s3
  bucket: acme-sigcomply-evidence
  region: us-east-1
  prefix: vault/

sources:
  aws.iam: {}
  aws.s3: {}
  "aws.iam[staging]":
    role_arn: arn:aws:iam::210987654321:role/SigComplyAudit
    external_id: acme-sigcomply
  "aws.s3[staging]":
    role_arn: arn:aws:iam::210987654321:role/SigComplyAudit
    external_id: acme-sigcomply
  github:
    org: acme
  "github[labs]":
    org: acme-labs
    token_env: GITHUB_TOKEN_LABS
  okta:
    org_url: https://acme.okta.com
  manual.pdf:
    backend: s3
    bucket: acme-sigcomply-evidence
    region: us-east-1
    prefix: manual/

policies:
  soc2.cc6.1.mfa_enforced_all_users:
    bindings:
      evidence: [okta]
  soc2.cc8.1.default_branch_protected:
    cadence: weekly
    exceptions:
      - scope:
          resource_pattern: "github[labs]/*"
        state: waived
        reason: Labs org holds prototypes only; no production code.
        approved_by: ciso@acme.example
        approved_at: "2026-07-01"
        expires_at: "2026-12-31"

controls:
  CC6.4:
    applicability: not_applicable
    reason: Cloud-only company; physical security is inherited from AWS.
    approved_by: ciso@acme.example

cloud:
  base_url: https://sigcomply.com

ci:
  fail_on_violation: true

experimental:
  scope:
    declared_by: ciso@acme.example
    declared_at: "2026-07-01"
    required_sources: [aws.iam, github, okta]
  roster:
    source: okta
    aliases:
      github: { jdoe: jane.doe@acme.example }
    non_human:
      github: [acme-ci-bot]
  vendors:
    register:
      - id: acme_hosting
        name: Acme Hosting
        tier: critical
        providers: [aws]
```

The `aws.*` sources take their region from `vault.region`. More worked files are in
[`docs/architecture/examples/`](architecture/examples/).
