# Changelog

All notable changes to the SigComply CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-release binaries and auto-generated notes are published on
[GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases); this file
tracks the human-curated highlights.

## [Unreleased]

### Added

- **Multiple instances of one source — a project can now cover several cloud
  accounts.** A bracket suffix on a source key (`"aws.iam[staging]"`)
  configures the same plugin a second time. This was documented but had never
  worked: the factory lookup was exact, so a bracketed key failed with "not
  registered", and had it got past that, both instances would have collided on
  the plugin's hardcoded ID. Instance identity is now real — it is the registry
  key, what a `bindings:` entry names, each record's `source_id`, and the
  evidence envelope's filename — so two accounts produce two independently
  verifiable sets of evidence. An instance key naming something unconfigured is
  a hard error, never silently resolved to the default instance.
- **Per-instance AWS credentials (`role_arn`, `external_id`,
  `role_session_name`).** Region is not an account boundary: every AWS plugin
  previously resolved one ambient identity, so two instances returned the same
  account's resources under two names. An instance now assumes its own role
  from whatever credentials the runner holds. The role is resolved at
  construction, so a misconfigured instance fails the run instead of reporting
  an account that merely looks empty. There is deliberately no `profile` key —
  the AWS chain resolves environment credentials ahead of a profile, so in CI a
  profile would be silently ignored.
- **`token_env` for `github`, `gitlab` and `okta`** — names a per-instance
  environment variable for the credential. Without it a second instance falls
  back to the same process-global `GITHUB_TOKEN` as the first and collects the
  same org twice. A `token_env` that is set but empty is an error rather than a
  fall-through, so an instance can never silently borrow another's identity.
- **Declared estate / scope completeness.** A new opt-in
  `experimental.scope.required_sources` block in `.sigcomply.yaml` lets you
  declare the sources a project asserts coverage over. Any declared source that
  is not configured, not bound by a policy slot, or returns no records makes the
  run report `SCOPE INCOMPLETE` and exit `1`. This closes a false-green: because
  a policy with no configured source is skipped and skips leave the
  compliance-score denominator, forgetting to wire a platform previously *raised*
  your score instead of lowering it. Entirely opt-in — with no declaration there
  is no new output, no new exit code, and `summary.json` keeps its previous
  shape. The verdict is written to `summary.json` (covered by the run manifest
  signature) and never crosses the aggregation boundary.
- **`sigcomply report --view scope`.** Shows the declared estate and how each
  declared source fared, plus every control the latest run did *not* evaluate
  and why. The skip half renders even with no declaration — skipped controls
  leave the compliance score, so they are exactly what an all-green run hides.
- `check` now prints a short banner naming the sources it will collect from (and
  their region/backend) before making any API call, so it's clear the run reaches
  real infrastructure. Credentials are never printed.
- `check` surfaces a concise, actionable reason line under each failing or errored
  policy in the terminal summary (e.g. `manual evidence not found; expected files
  in: <path>`), instead of only writing it to the vault `result.json`.
- `sigcomply init` now scaffolds a `manual.pdf` evidence source (local `./evidence`
  backend) so a framework's manual-evidence controls bind and report `fail`
  ("evidence not found") rather than erroring out.

### Changed

- **Source keys and `catalog_entry` values are now validated** against a
  restrictive grammar (letters, digits, dot, dash, underscore, plus an optional
  `[instance]` suffix). Both become part of an evidence file's object key in the
  vault, and only the local backend rejects path escapes — S3, GCS and Azure
  concatenate keys directly. Existing configs are unaffected: every shipped
  source ID and every documented example already conforms.
- **A `pass_when` clause naming a slot the policy does not declare is now a
  load-time error.** Previously the slot lookup missed, yielded an empty record
  set, and `all`/`none` passed vacuously — one mistyped slot name silently turned
  a real check into a permanent green tick. Affects customer-authored policies
  under `.sigcomply/policies/` only; every shipped policy sets the slot name
  itself and cannot hit this.
- **Passes that examined no resource are now reported.** `all`/`none` are true of
  the empty set, so a clause whose slot is empty or whose filter matched nothing
  passes. That is often correct ("no public bucket is unencrypted" when none are
  public), so it is still a pass — but results now carry
  `diag.vacuous_clauses` and `check` explains such a pass inline. Previously
  `resources_evaluated` reported the *pre-filter* population, so a policy that
  filtered 500 records to zero rendered as "all 500 resources passed".
- CI examples and `init-ci` templates now default `SIGCOMPLY_VERSION` to a pinned
  release tag instead of `latest`, so a new release can't auto-propagate to every
  tester's next CI run. Set it to `latest` to opt back into always-newest.
- Error output no longer dumps the full command usage/flags block after a runtime
  error; the one-line message is shown on its own (`SilenceUsage`).

### Fixed

- A fresh `sigcomply init -f <framework> && sigcomply check` now exits `1`
  (findings to remediate), not `2`, and prints zero `[error]` lines.
- `init-ci` with a missing required `--ci` flag now exits `3` (configuration error)
  to match the exit-code taxonomy, instead of cobra's default `2`.
- `--cloud` with no `cloud.base_url` (or `--cloud-url`) configured now warns that
  submission was skipped, instead of silently doing nothing.
- Malformed-YAML config errors now include a plain-language hint (indentation,
  tabs, unknown keys) alongside the raw parser message.

## [0.64.38]

Baseline release for the beta-readiness changelog. For the complete history of
earlier tags, see the auto-generated notes on
[GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases).

[Unreleased]: https://github.com/SigComply/sigcomply-cli/compare/v0.64.38...HEAD
[0.64.38]: https://github.com/SigComply/sigcomply-cli/releases/tag/v0.64.38
