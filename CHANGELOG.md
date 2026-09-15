# Changelog

All notable changes to the SigComply CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-release binaries and auto-generated notes are published on
[GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases); this file
tracks the human-curated highlights.

## [Unreleased]

### Added

- **`sigcomply evidence due` — know manual evidence is needed before CI goes
  red.** Until now the only signal that a quarterly access review or an annual
  policy acknowledgement was missing was a failed cadence run on the day it was
  already needed. The new command lists every manual-evidence entry whose folder
  for the current period is still empty, and `sigcomply init-ci` wires it into
  the daily workflow as a **non-failing** step (`continue-on-error: true` on
  GitHub, `|| true` on GitLab). It reports only genuinely empty folders, so it
  goes quiet the moment the upload lands rather than nagging about work already
  done, and it **always exits 0** when the scan completes — including when
  evidence is overdue. If the store cannot be reached it says so and still exits
  0 instead of inventing deadlines. Read-only: `LIST` calls only, no file bytes
  downloaded, no cloud API, no OIDC. Under GitHub Actions it also emits
  `::warning` annotations (capped at GitHub's ten-per-step limit, with an
  overflow line) and a `$GITHUB_STEP_SUMMARY` table. Flags: `-c`, `-f`, `-o
  text|json`, `--within-days` (default 30), `--all`.

- **Identity roster — check every system's accounts against your list of
  people.** A new opt-in `experimental.roster` block designates the one source
  that holds the organization's people (`okta`, `azure.entra`, `gcp.directory`
  or `active_directory`), with per-source `aliases` (account → roster email)
  and `non_human` account lists. Four new policies use it:
  `soc2.cc6.2.accounts_linked_to_roster` / `iso27001.5.16.accounts_linked_to_roster`
  (every active human account in GitHub, GitLab, AWS IAM, … belongs to someone
  in the roster) and `soc2.cc6.2.no_active_accounts_for_inactive_personnel` /
  `iso27001.5.18.no_active_accounts_for_inactive_personnel` (no active account
  belongs to someone the roster marks inactive). The roster source is never
  auto-bound and never checked against itself — a directory cannot vouch for
  its own accounts. Without the block the policies skip with a message naming
  the key to set. Violations identify accounts as `source_id/id`, the value a
  waiver's `resource_id` takes. Guide: `docs/guides/identity-roster.md`.
- **`roster_entry` evidence type** — one record per person in the
  authoritative workforce directory (`status`: `active` | `pending` |
  `inactive`), emitted by `okta` (including deprovisioned users), `azure.entra`
  (needs only `User.Read.All`, no Entra ID P1/P2), `gcp.directory`, and the new
  `active_directory` source. `additionalProperties: false`: plugins emit only
  the minimal personnel fields.
- **`active_directory` source** — reads on-prem Active Directory over LDAPS or
  StartTLS (plain LDAP is refused; TLS 1.2+, verified) with a simple bind and
  paged search, and emits `roster_entry`. Status comes from the
  ACCOUNTDISABLE flag and `accountExpires`; `service_account_ous` and
  `servicePrincipalName` mark service accounts.
- **`matches_in` cross-slot operator and `account.*` fields in `pass_when`.**
  `{op: matches_in, field, in_slot, remote_field, normalize: lower_trim, where}`
  expresses "this record's key appears in another slot" without the `rule:`
  escape hatch. Virtual `account.ref` / `.key` / `.linked_by` / `.non_human` /
  `.active` resolve aliases, non-human declarations and AWS root. Slots can
  declare `role: roster | roster_subject`; clause and condition keys are now
  decoded strictly, so a typo such as `normalise:` fails to load.
- **`gcp.directory` impersonation for CI** — optional `target_service_account`
  (ADC impersonates that service account) and `impersonate_subject`
  (domain-wide delegation; requires `target_service_account`).
- `directory_user.username` is emitted by `github` (login), `gitlab` (username)
  and `aws.iam` (`UserName`), so roster aliases can name accounts by login.
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

- **The scaffolded quarterly and annual crons now fire inside the period, not on
  its boundary** — `0 2 20 3,6,9,12 *` (Mar/Jun/Sep/Dec 20) and `0 2 20 12 *`
  (Dec 20), replacing `0 2 1 1,4,7,10 *` and `0 2 1 1 *`. The audit period is
  derived from the HEAD commit's timestamp, so a run at 02:00 on the first day of
  a period landed in whichever period HEAD fell in: usually the one that just
  closed (correct), but the *new* one if anyone pushed to `main` in the
  intervening hours — and a newly-opened period's evidence folder cannot
  legitimately hold anything, since the temporal-window check requires
  `uploadedAt >= period.Start`. Firing before the period closes makes the derived
  period unambiguous, keeps essentially the whole period available for uploads,
  and removes the race. Existing scaffolds are unaffected until re-run;
  `docs/architecture/09-ci-execution-model.md` explains the commit-time basis,
  which was load-bearing and previously undocumented.

- **A `pass_when` filter that cannot be evaluated now errors the policy instead
  of silently dropping the record.** `filterRecords` treated "the filter says
  this record is out of scope" and "the filter could not be evaluated" as the
  same outcome, and excluded both. Excluding the second biases toward passing:
  the record is one fewer thing checked, and `all`/`none` are true of the empty
  set — so a filter that failed to evaluate on every record returned a green
  tick having examined nothing. One unpopulated optional field was enough. A
  filter that legitimately tolerates an absent field must now say so with
  `is_set`, which returns false rather than erroring. Three shipped policies
  gained that guard (`soc2.cc6.7.kms_key_rotation_enabled`,
  `iso27001.8.24.kms_key_rotation`, `iso27001.5.16.inactive_user_accounts`);
  none change verdict on today's sources, which all populate the fields in
  question. A new build-failing test keeps a fourth from appearing.
- **`in` / `not_in` with a non-list value now errors** rather than matching
  nothing. `not_in` with a scalar (`value: "write"` instead of
  `value: ["write"]`) previously returned true for every record, passing the
  policy without comparing anything. No shipped policy was affected.
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
- **`okta` `directory_user.is_active` is now true for `RECOVERY`,
  `PASSWORD_EXPIRED` and `LOCKED_OUT`** as well as `ACTIVE` — those accounts
  are still live logins. **`gcp.directory` `is_active` is now false for
  archived users** as well as suspended ones.
- `resources_evaluated` no longer counts slots a policy reads only as a
  `matches_in` lookup table (the roster's people are not resources under test).
- CI examples and `init-ci` templates now default `SIGCOMPLY_VERSION` to a pinned
  release tag instead of `latest`, so a new release can't auto-propagate to every
  tester's next CI run. Set it to `latest` to opt back into always-newest.
- Error output no longer dumps the full command usage/flags block after a runtime
  error; the one-line message is shown on its own (`SilenceUsage`).

### Fixed

- A fresh `sigcomply init -f <framework> && sigcomply check` now exits `1`
  (findings to remediate), not `2`, and prints zero `[error]` lines.
- `sigcomply check` now exits `3`, not `2`, when planning rejects the config
  (for example an unknown roster source or an invalid binding) — the documented
  exit code for configuration errors.
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
