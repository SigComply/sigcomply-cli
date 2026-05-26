# 08 — Project Config

The `.sigcomply.yaml` at the repo root is the customer's source of
truth. It declares the framework, the fiscal calendar, the source
plugins and their configuration, policy bindings, parameter overrides,
exceptions, and the vault location.

Everything in this file is versioned in git. Auditors read it.
Reviewers ask "why?" on changes. It is intentionally human-authored
and human-reviewed.

---

## File discovery

The CLI resolves the project config in this order:

1. The path passed to `--config <path>`.
2. `./.sigcomply.yaml` (current working directory).
3. `$HOME/.sigcomply.yaml` (user defaults — discouraged for projects).

If none exists, the CLI errors with exit code 3.

The shape is intentionally one file. A project that wants modularity
authors a single file with section comments; splitting into multiple
files is not supported in v1.

---

## Complete schema

```yaml
schema_version: project.v1

# ---- Required ----

framework: soc2                    # framework ID (one per project; one per invocation)

# ---- Period model ----

period:
  fiscal_calendar:
    type: calendar_quarter         # calendar_quarter | fiscal_year | custom
    # for fiscal_year:
    # starts: april                # any month name; default january
    # for custom:
    # periods:
    #   - { id: 2026-P01, start: 2026-01-04, end: 2026-01-31 }
    #   - { id: 2026-P02, start: 2026-02-01, end: 2026-02-28 }
  time_basis: commit               # commit | wall_clock (default: commit)

# ---- Vault ----

vault:
  backend: s3                      # local | s3 | gcs | azure_blob
  bucket: acme-evidence
  region: us-east-1
  prefix: sigcomply/               # optional; default empty
  # s3-specific:
  endpoint: ""                     # for on-prem MinIO etc.
  force_path_style: false
  # local-specific:
  # path: /var/sigcomply/vault

# ---- Sources ----

sources:
  aws.iam:
    region: us-east-1
    # role_arn: arn:aws:iam::111111111111:role/SigComplyAuditor
  aws.s3:
    region: us-east-1
  aws.cloudtrail:
    region: us-east-1
  okta:
    domain: acme.okta.com
    # token_env: OKTA_TOKEN (default)
  github:
    org: acme
  # manual.pdf is a project-level singleton — exactly one instance.
  # No bracket-suffix variants permitted for this plugin.
  manual.pdf:
    backend: s3
    bucket: acme-evidence
    prefix: manual/
    region: us-east-1

  # Multiple instances of API plugins: bracket suffix.
  # (Does not apply to manual.pdf — see above.)
  "aws.iam[backup]":
    region: us-west-2
    role_arn: arn:aws:iam::222222222222:role/SigComplyAuditor

# ---- Bindings ----

bindings:
  soc2.cc6.1.mfa_enforced:
    user_directory: [aws.iam, okta]

  soc2.cc6.1.access_key_rotation:
    access_keys: [aws.iam, "aws.iam[backup]"]

  soc2.cc6.1.access_review:
    review_document: [manual.pdf:access_review_quarterly]

  acme.custom.cc6.1.contractor_review:
    review_document: [manual.pdf:contractor_review]

# ---- Policy parameter overrides ----

policy_parameters:
  soc2.cc6.1.access_key_rotation:
    max_age_days: 60               # stricter than the framework default (90)
  soc2.cc6.1.inactive_users:
    inactive_days: 30
  soc2.cc6.1.mfa_enforced:
    exempt_service_accounts: false  # require MFA on machine identities too

# ---- Policy cadence overrides ----

policy_cadences:
  soc2.cc6.1.mfa_enforced: hourly         # stricter than the framework default (daily)
  soc2.cc6.1.access_review: monthly       # stricter than the framework default (quarterly)
  soc2.cc1.4.security_training_annual: annual   # explicit override matching default

# ---- Exceptions ----

exceptions:
  - policy: soc2.cc6.1.mfa_enforced
    scope:
      resource_id: "iam_user_legacy_svc"
    state: waived
    reason: |
      Legacy service account; credential vaulted in 1Password, rotated
      quarterly. CTO-approved.
    approved_by: jane.doe@acme.com
    approved_at: 2026-01-15
    expires_at: 2026-07-15

  - policy: soc2.cc6.1.access_key_rotation
    state: na
    reason: "Federated SSO only; no long-lived access keys exist."

# ---- Cloud submission ----

cloud:
  enabled: true                    # default true in CI, false locally
  base_url: https://api.sigcomply.com
  # For self-hosted dashboards:
  # base_url: https://compliance.acme-internal.com

# ---- CI/CD environment overrides (rarely needed) ----

ci_environment:
  # Override auto-detected values. Useful only for niche CI providers.
  # provider: gitlab
  # repository_slug: acme/infrastructure

# ---- Output ----

output:
  format: text                     # text | json | junit | sarif
  json_path: ./compliance-report.json
  verbose: false

# ---- CI behavior ----

ci:
  fail_on_violation: true          # if true, exit 1 on any failure
  fail_severity: high              # info | low | medium | high | critical
                                   # only failures at-or-above this level
                                   # affect the exit code

# ---- Discovery overrides for project-local extensions ----

extensions:
  # Override default discovery path. Default is ./.sigcomply/
  # path: ./compliance-extensions
```

---

## Section reference

### `framework` (required)

Selects exactly one framework for this invocation. Multi-framework
runs are handled by invoking the CLI multiple times in CI (one job
per framework). Valid values are the IDs of frameworks registered in
the binary (e.g. `soc2`, `iso27001`).

### `period`

Controls how the run is tagged with a period. See
`01-conceptual-model.md` §Period for the model.

| Field | Default | Notes |
|---|---|---|
| `fiscal_calendar.type` | `calendar_quarter` | Or `fiscal_year`, `custom`. |
| `fiscal_calendar.starts` | `january` | Only for `fiscal_year`. |
| `fiscal_calendar.periods` | n/a | Required for `custom`. List of explicit period boundaries. |
| `time_basis` | `commit` | `commit` (preferred) or `wall_clock`. |

### `vault`

The customer's evidence storage. The backend selection is mandatory;
each backend has additional fields.

| Backend | Required fields | Optional |
|---|---|---|
| `local` | `path` | — |
| `s3` | `bucket`, `region` | `prefix`, `endpoint`, `force_path_style`, `profile`, `role_arn` |
| `gcs` | `bucket` | `prefix` |
| `azure_blob` | `account`, `container` | `prefix` |

Credentials are not in the config: the backend reads them from the
environment (`AWS_*`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_*`).

### `sources`

A map of source plugin instance ID → config. The instance ID is
either the plugin's canonical ID (`aws.iam`) or a bracketed variant
for multiple instances (`"aws.iam[backup]"`). Each plugin's
`config_schema` (declared in its manifest) determines what fields are
valid here.

Bracketed instance suffixes are arbitrary identifiers chosen by the
customer; they appear in bindings exactly as written.

**`manual.pdf` is a project-level singleton.** It accepts exactly one
config entry under `sources.manual.pdf`. The bracket-suffix pattern
used for API plugins (`"aws.iam[backup]"`, `"github[secondary]"`) does
not apply: declaring `"manual.pdf[anything]"` is rejected at config
validation with exit 3. A project has one manual-evidence bucket, one
prefix, and one set of credentials. See
[`04-source-plugins.md`](04-source-plugins.md) §The manual.pdf plugin
for the rationale and path-resolution scheme.

### `bindings`

The most important section. Maps `policy_id.slot_name → [source_id, ...]`.

```yaml
bindings:
  soc2.cc6.1.mfa_enforced:
    user_directory: [aws.iam, okta]
```

For manual sources, the binding includes the manual catalog entry ID
after a colon:

```yaml
bindings:
  soc2.cc6.1.access_review:
    review_document: [manual.pdf:access_review_quarterly]
```

For per-slot parameters:

```yaml
bindings:
  soc2.cc6.1.admin_mfa_enforced:
    user_directory:
      - source: aws.iam
        slot_params:
          filter_admins_only: true
```

Both shapes (string list and object list) are valid; mixing within a
slot is allowed. The planner validates that every bound source is
registered and emits the slot's declared evidence type.

Bindings are also where customers exclude framework policies: a
policy with no binding for a required slot is reported as `error`
(missing binding) at plan time. To intentionally skip a policy, use
an exception with `state: na`.

### `policy_parameters`

Per-policy parameter overrides. Keys are policy IDs; values are
maps of parameter name → value. The CLI validates each value against
the policy's parameter spec (`min/max/enum/pattern/type`) at plan
time. Out-of-bounds values cause a planning error.

Effective parameters are stamped into each run's `manifest.json` so
auditors see the exact thresholds.

### `policy_cadences`

Per-policy cadence overrides. Each framework spec declares a default
cadence for every policy (e.g. `mfa_enforced: daily`,
`access_review: quarterly`). Allowed values: one of the seven named
cadences (`continuous`, `hourly`, `daily`, `weekly`, `monthly`,
`quarterly`, `annual`) or a custom interval `every:<duration>`
(`every:6h`, `every:90m`, floor 5 minutes). This section lets a
project tighten (or loosen) those defaults per policy.

```yaml
policy_cadences:
  soc2.cc6.1.mfa_enforced_admin: every:6h     # tighter than framework default
  soc2.cc6.1.access_review: monthly
  soc2.cc1.4.security_training_annual: annual
```

Overrides are exact-match by policy ID. Unknown IDs are caught at
plan time. `every:24h` is NOT equivalent to `daily` — the named
cadence has 1h cron-drift slack baked in; `every:24h` is exactly 24h
since the last pass and drifts time-of-day across runs.

**The CLI enforces cadence in scheduled mode.** When invoked with
`sigcomply check --scheduled`, the CLI reads per-policy state
shards from the vault at `state/{framework}/policies/
{policy_id}.json` and decides per-policy whether to re-evaluate or
emit a carry-forward result that references the prior signed
envelope. PR mode (`--pr`) and manual mode evaluate every in-scope
policy without cadence gating.

The decision rule is layered: operator filter > content-hash >
on_fail_retry > cadence-elapsed. See
[`11-cadence-model.md`](11-cadence-model.md) §The decision rule for
the full algorithm.

Effective cadences (after overrides) are stamped into the per-policy
state shard's `ConfiguredCadence` field and into each run's
`PolicyResult`.

### `exceptions`

Declarative waivers and N/A declarations. Each exception:

| Field | Required | Description |
|---|---|---|
| `policy` | yes | Policy ID. May include `*` wildcard suffix for grouping (e.g. `soc2.cc8.*`). |
| `scope.resource_id` | no | Match a specific resource. Omit to apply to the entire policy. |
| `scope.resource_pattern` | no | Glob or regex matching multiple resources. |
| `state` | yes | `waived` (policy fails but is treated as compliant with documented compensating control) or `na` (policy does not apply to this project). |
| `reason` | yes | Plain-English justification. Required for audit. |
| `approved_by` | recommended | Email or username of the approver. |
| `approved_at` | recommended | ISO 8601 date of approval. |
| `expires_at` | recommended | ISO 8601 date after which the exception is ignored. |

The evaluator applies exceptions after rule evaluation: a `waived`
exception reclassifies failing violations as waived but otherwise
preserves the rule's findings (so the operator can still see what the
exception is masking). An `na` exception causes the policy to short-
circuit to `na` status without invoking the rule at all.

Expired exceptions are ignored (the rule's actual result wins),
surfaced in run output as a warning.

### `cloud`

Cloud submission settings. Defaults:

| Field | Default | Effect |
|---|---|---|
| `enabled` | `true` in CI with OIDC available; `false` otherwise | Master switch |
| `base_url` | `https://api.sigcomply.com` | Submission endpoint |

Customers opting out entirely set `enabled: false`. Self-hosted
dashboards set `base_url` to their endpoint.

### `output`

| Field | Default | Values |
|---|---|---|
| `format` | `text` | `text`, `json`, `junit`, `sarif` |
| `json_path` | unset | If set, also writes JSON to this path |
| `verbose` | `false` | Verbose human output |

### `ci`

| Field | Default | Description |
|---|---|---|
| `fail_on_violation` | `true` | If true, exit code 1 on any failure (subject to `fail_severity`). |
| `fail_severity` | `info` | Only failures at-or-above this severity affect exit code. |

These exist because CI consumers often want fine-grained control over
when a compliance run blocks the pipeline. `info` failures probably
shouldn't block; `critical` failures probably should.

### `extensions`

Rarely used. Overrides the default `.sigcomply/` discovery path.

---

## Precedence

For any value, the CLI resolves in this order (later overrides
earlier):

1. **Defaults** baked into the binary.
2. **Project config** (`.sigcomply.yaml`).
3. **Environment variables** (see §Env var bindings).
4. **CLI flags**.

The effective values used during a run are stamped into
`manifest.json` so the run is self-describing.

**Stateless cadence.** Precedence applies to values, not to scheduling.
The CLI does not consult prior runs to decide what to run *now*: it
takes its policy set from exactly one filter flag (`--policies`,
`--controls`, `--cadence`, or `--on-push` — they are mutually
exclusive), applies the effective `policy_cadences` overrides on top of
framework defaults, runs that set, and exits. Cadence enforcement
(running daily policies every day, quarterly policies every quarter)
belongs to the CI scheduler — typically a cron-triggered GitHub Actions
workflow or GitLab CI scheduled pipeline that invokes the CLI with the
right `--cadence` value. See
[`10-ci-execution-model.md`](10-ci-execution-model.md).

---

## Env var bindings

Every section that's safe to read from the environment supports a
parallel env var. Convention: `SIGCOMPLY_<section>_<field>`.

| Env var | Maps to |
|---|---|
| `SIGCOMPLY_FRAMEWORK` | `framework` |
| `SIGCOMPLY_VAULT_BACKEND` | `vault.backend` |
| `SIGCOMPLY_VAULT_BUCKET` | `vault.bucket` |
| `SIGCOMPLY_VAULT_REGION` | `vault.region` |
| `SIGCOMPLY_VAULT_PATH` | `vault.path` |
| `SIGCOMPLY_OUTPUT_FORMAT` | `output.format` |
| `SIGCOMPLY_CLOUD_ENABLED` | `cloud.enabled` |
| `SIGCOMPLY_CLOUD_URL` | `cloud.base_url` |
| `SIGCOMPLY_CI_FAIL_ON_VIOLATION` | `ci.fail_on_violation` |
| `SIGCOMPLY_CI_FAIL_SEVERITY` | `ci.fail_severity` |
| `AWS_REGION` | falls back to `sources.aws.*.region` if unset there |
| `GOOGLE_PROJECT_ID` | falls back to `sources.gcp.*.project` if unset there |
| `GITHUB_TOKEN` | credential for `sources.github` |
| `OKTA_TOKEN` | credential for `sources.okta` (unless `token_env` overrides) |

Plugin-specific env vars come from the plugin's manifest (`token_env`
field convention). Secrets never appear in the config file.

---

## CLI flag overrides

The `sigcomply check` subcommand exposes a focused set of flags:

```
--config <path>                Override config file location
--policies <ids>               Comma-separated policy IDs to run (filter)
--controls <ids>               Comma-separated control IDs to run (filter)
--cadence <value>              Filter to policies with this effective cadence
                               (continuous|hourly|daily|weekly|monthly|
                               quarterly|annual). Effective cadence is the
                               framework default overridden by
                               policy_cadences. Intended for CI schedules.
--on-push                      Filter to policies tagged for on-push
                               execution (typically all automated policies
                               suitable for PR feedback). Intended for
                               push/PR-triggered CI jobs.
--output <format>              text|json|junit|sarif
--json-output <path>           Also write JSON output to file
--cloud / --no-cloud           Force cloud submission on/off
--vault-backend <backend>      Override vault backend
--vault-bucket <bucket>        Override vault bucket
--capture-cloud-payload <path> Write cloud payload to file without sending
--period <id>                  Override computed period (rarely used)
--backfill                     Mark this run as a backfill
--reopen-period                Allow writes to a closed period (logged)
--dry-run                      Plan only; do not collect, evaluate, or submit
-v, --verbose                  Verbose output
```

`--cadence`, `--on-push`, `--policies`, and `--controls` are
**mutually exclusive** — at most one of these may be passed per
invocation. Passing none means "all policies in the framework."
Combining filters is rejected at plan time with exit code 3. This
matches the CI workflow pattern: each cron-scheduled workflow uses
exactly one filter (`--cadence daily`, `--cadence quarterly`, etc.),
and ad-hoc re-runs typically use `--policies <id>` alone. See
[`10-ci-execution-model.md`](10-ci-execution-model.md) for the full
CI workflow pattern.

Other commands (`sigcomply evidence`, `sigcomply test`, `sigcomply build`,
`sigcomply report`, `sigcomply version`) have their own flag sets,
documented in `cmd/sigcomply/<command>.go`.

**Subcommand: `sigcomply init-ci --framework <fw> --ci <provider>`.**
Not a flag of `check`; a separate subcommand that scaffolds CI workflow
files for the project. `--framework` selects the compliance framework
(e.g. `soc2`, `iso27001`); `--ci` selects the provider — `github`
(writes `.github/workflows/*.yml`) or `gitlab` (writes `.gitlab-ci.yml`
or an `include:`-able fragment). The generated workflows wire up the
cadence/on-push schedule described in
[`10-ci-execution-model.md`](10-ci-execution-model.md).

---

## Validation

The CLI validates `.sigcomply.yaml` at startup in three passes:

1. **Schema validation.** YAML must parse to the declared shape. Unknown
   top-level keys cause a warning (forward-compat with future versions);
   unknown subkeys under known sections cause an error.
2. **Reference resolution.** Every referenced source plugin must exist
   in the registry; every referenced policy ID must exist; every
   parameter must be declared on its policy; every binding's source
   must emit the slot's declared type.
3. **Bounds checking.** Parameter values, exception expiry dates,
   period configurations, and vault paths are checked for validity.

Any validation error aborts the run with exit code 3 and a clear
message indicating which field failed and why.

---

## Worked example

A complete `.sigcomply.yaml` for AcmeCorp's SOC 2 pursuit lives at
[`examples/acmecorp.sigcomply.yaml`](examples/acmecorp.sigcomply.yaml).
A narrative walkthrough is in
[`examples/acmecorp-walkthrough.md`](examples/acmecorp-walkthrough.md).
