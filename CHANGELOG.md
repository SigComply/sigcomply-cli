# Changelog

All notable changes to the SigComply CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Every push to `main` that changes code cuts a release automatically. Per-release binaries and
generated notes are on [GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases);
this file lists the changes a user notices.

## [Unreleased]

### Changed

- Rewrote the customer docs. To submit results to SigComply Cloud, set `cloud.base_url` in
  `.sigcomply.yaml`; without it the CLI submits nothing.

### Fixed

- The install script checks the downloaded archive against the release's `checksums.txt` and stops
  on a mismatch. `SIGCOMPLY_VERSION` accepts a version without the leading `v`.
- `init-ci` scaffolds pin the CLI release that generated them (or `latest` for a development
  build) instead of `v0.73.2`.
- The GitLab template passes the CI ID token to the AWS SDK for role assumption, through
  `AWS_WEB_IDENTITY_TOKEN_FILE`.

## [0.65.0 to 0.88.3] - 2026-07-13 to 2026-10-22

Releases v0.65.0 through v0.88.3 were cut without per-version notes. This section lists their
combined changes.

### Added

- ISO 27001 ships the 16 clause 4-10 management-system requirements (`C.4.1-4.2` through `C.10.2`,
  policy IDs `iso27001.clause.<n>.<slug>`) as annual manual document uploads. They cannot be
  declared `not_applicable`. Existing ISO projects: the next annual run fails these 16 until the
  documents are uploaded; waive them with a reason and `expires_at` while you work through them.
- `sigcomply report --view soa` generates the ISO 27001 Statement of Applicability (text, JSON,
  CSV). It requires the project config and exits `3` without it.
- `controls.<id>.justification` config key: the inclusion justification printed in the SoA. Setting
  it together with an exclusion `reason` on one control is a config error.
- `experimental.risks` risk register: each risk names the Annex A controls that treat it, and the
  SoA gains a `RISKS` column. Plan-time `risks:` warnings flag unknown control IDs and stale
  registers.
- `sigcomply report --view coverage` shows, per control, whether automated or manual checks stand
  behind it and whether evidence exists for the period (`--format text|json|csv`). For ISO 27001
  it counts Annex A and management-system controls separately (`KIND` column).
- `sigcomply report --view scope` lists the declared estate, how each declared source fared, and
  every control the latest run skipped or errored, with a status column.
- `experimental.scope.required_sources`: a declared source that is unconfigured, unbound or returns
  no records makes the run report `SCOPE INCOMPLETE` and exit `1`. Opt-in.
- `sigcomply evidence due` lists manual-evidence entries whose current-period folder is empty
  (`-c`, `-f`, `-o text|json`, `--within-days`, `--all`). Read-only, always exits `0`; emits
  GitHub `::warning` annotations and a step-summary table. `init-ci` adds it to the daily workflow.
- Change management evidence: `pull_request` and `deployment` evidence types from `github` and
  `gitlab`, with four policies per framework (SOC 2 CC8.1, ISO 27001 A.8.32). GitHub tokens need
  Pull requests, Deployments, Checks and Commit statuses read; GitLab users need Reporter.
- Identity roster: `experimental.roster` designates one people source (`okta`, `azure.entra`,
  `gcp.directory`, `active_directory`) with per-source `aliases` and `non_human` lists. Four
  policies (`*.accounts_linked_to_roster`, `*.no_active_accounts_for_inactive_personnel`) check
  accounts and `iam_binding` grants against it; they skip when the block is absent. Runs print
  `unused-alias:` and `unused-non-human:` for roster keys that matched no account.
- `roster_entry` evidence type, emitted by `okta`, `azure.entra`, `gcp.directory` and
  `active_directory`. `directory_user.username` is emitted by `github`, `gitlab` and `aws.iam`.
- `active_directory` source: on-prem AD over LDAPS or StartTLS (plain LDAP refused), emits
  `roster_entry`; `service_account_ous` marks service accounts.
- `matches_in` cross-slot operator and virtual `account.*` fields in `pass_when`; slots can declare
  `role: roster | roster_subject`. Clause and condition keys are decoded strictly.
- `aws.identity_center` source: emits `directory_user`, `roster_entry` and `iam_binding`
  (permission-set assignments). Needs `identitystore:*` and `sso:*` read actions; `mfa_enabled`
  is always `false` because AWS exposes no per-user MFA, so bind MFA policies to your IdP.
- `gcp.cloud_identity` source: emits `password_policy.v2` from Cloud Identity, so the six password
  controls evaluate on a Google Workspace estate instead of skipping.
- `password_policy.v2` evidence type: `complexity_model` (`per_class | strength_enum | fixed |
  none`), `reuse_prevented` with optional `reuse_prevention_count`, optional platform fields,
  `not_configurable`, `defaulted`, `scope` and `precedence`. v1 stays registered for local plugins.
- `aws.password_policy` and `okta` emit `password_policy.v2`. Okta emits one record per active
  password policy and needs `okta.policies.read`.
- `soc2.cc6.1.password_reuse_depth_24` policy: requires a reuse history of 24 from sources that
  disclose a depth; others are out of scope.
- Vendor risk: manual entries can fan out over `experimental.vendors`, one folder per vendor at
  `{prefix}{evidence_id}.{vendor_id}/{period_id}/`. Policies `soc2.cc9.2.vendor_assurance`,
  `soc2.cc9.2.cuec_mapping` and `iso27001.5.19.supplier_assurance`; a vendor's
  `assurance_period_end` fails the check once more than 15 months old. A `low` tier requires
  `tier_rationale` and `approved_by`. Declaring a register adds one evidence obligation per vendor.
- Annual manual entries `soc2.cc9.2.vendor_lifecycle_process` and
  `iso27001.5.19.supplier_lifecycle_process`.
- `experimental.vendors` entries accept `providers:`; a configured source no entry claims produces
  a plan-time warning. Unknown `experimental.vendors` subkeys are reported.
- Multiple instances of one source via a bracket suffix (`"aws.iam[staging]"`), each producing its
  own evidence. AWS instances accept `role_arn`, `external_id` and `role_session_name`; `github`,
  `gitlab` and `okta` accept `token_env`.
- `sources.github.base_url` for GitHub Enterprise Server (usually `https://<host>/api/v3`).
- `gcp.directory` accepts `target_service_account` and `impersonate_subject` for CI.
- The effective evidence mode is recorded in `result.json` and on the wire. The cloud payload is
  `sigcomply.cloud.v5`: per-policy `evidence_mode`, `evidence_mode_overridden` and `vacuous`.
- Plan-time warnings: `coverage-gap:` for a required slot no configured source can fill,
  `unbound-source:` for a configured source no policy reads, a caveat warning when a source that
  reports an unobserved field is bound to a policy that reads it (with a suggested `bindings:`
  block), and warnings for unknown or wrongly typed keys under `sources:`. All advisory.
- `plugin` package: project-local Go sources, vault backends and manual readers import it instead
  of `internal/...`. `sigcomply build` warns about Go rule or evidence-type packages that never
  register.
- GCP evidence records carry their project, organization or customer ID as signed scope.
- `check` prints the sources it collects from before any API call, a one-line reason under each
  failing or errored policy, and a breakdown of passes by inspection versus document presence.
- `sigcomply init` scaffolds a local `manual.pdf` source (`./evidence`).

### Changed

- Manual-evidence folders are keyed by the entry's own cadence window (annual `2026`, quarterly
  `2026-Q1` and so on), not the run's period. Migration: move annual uploads from `…/{entry}/2026-Qn/`
  to `…/{entry}/2026/`; `sigcomply evidence due` prints each entry's folder.
- The prior-period duplication check compares annual entries with last year's folder, so a
  byte-identical yearly re-upload fails with `copy_paste_of_prior_period`.
- `soc2.cc9.2.vendor_contracts_reviewed` and `iso27001.5.20.supplier_security_agreements` fan out
  per vendor when `experimental.vendors` is set. Migration: copy existing evidence into each
  vendor's folder.
- `period.time_basis: wall_clock` is honored (it was ignored); `commit` remains the default.
- `evidence due` shows a `PERIOD` column, measures deadlines on the period clock, and
  `--within-days 0` means "closes today".
- `soc2.cc6.1.password_complexity` and `iso27001.8.5.password_complexity` pass on per-class rules,
  a strongest strength rating, or a platform-enforced rule. `soc2.cc6.1.password_reuse_prevention`
  asks whether reuse is prevented, so an AWS history depth of 1 passes it.
- The six password policies accept `password_policy.v2` and `password_policy`; a record that does
  not report a field is out of that clause's scope, and an empty clause is reported as vacuous.
- A pass that examined no resource (including `count` with `min_percentage: 0`) is flagged:
  `check`, `report --view latest` and the wire `message` explain it, and `vacuous` is set.
- The policy content hash covers `pass_when`; the first run after upgrading re-evaluates all policies.
- A configured source whose credentials cannot be resolved stops the run at startup with exit `3`
  (was exit `2` during collection). Covers `aws.*`, `azure.*`, `manual.pdf` and the `s3` and
  `azure_blob` vaults.
- Collection fails a binding immediately on 401, 403, 404 and schema errors instead of retrying.
- A `pass_when` filter that cannot be evaluated errors the policy instead of dropping the record;
  guard optional fields with `is_set`. `in` / `not_in` with a non-list value errors, and a clause
  naming an undeclared slot fails to load (custom policies only).
- Source keys and `catalog_entry` values must match letters, digits, `.`, `-`, `_` and an optional
  `[instance]` suffix.
- `okta` `is_active` is true for `RECOVERY`, `PASSWORD_EXPIRED` and `LOCKED_OUT`; `gcp.directory`
  `is_active` is false for archived users.
- `resources_evaluated` no longer counts slots used only as a `matches_in` lookup.
- Scaffolded monthly, quarterly and annual crons fire on day 20, inside the period. Re-run
  `init-ci` to pick this up.
- CI examples and `init-ci` templates pin `SIGCOMPLY_VERSION` to a release (`v0.73.2`) instead of
  `latest`; set `latest` to opt back in.
- `examples/github-actions/multi-environment.yml` uses source instances instead of a CI matrix.
- Runtime errors print the one-line message without the command usage block.

### Fixed

- Two instances of one source no longer merge into one violation. Waivers for an instanced
  source's resource must use the prefixed ID.
- `aws.iam` root records are keyed by `arn:aws:iam::<account>:root`, so roots in different
  accounts no longer collide. Exceptions scoped to `<root_account>` must use the ARN.
- `azure.entra` reads the tenant from the credential; a declared `tenant_id` that disagrees exits
  `3`. The credential needs `Organization.Read.All` (or a directory read scope covering it).
- Okta pagination no longer stops after the first page when the `next` link is on a second header.
- The SoA reports a control with only `na` policies as not evaluated instead of implemented, and a
  carried-forward control as implemented instead of not implemented.
- `init -f iso27001` no longer recommends `init-ci`; `init-ci --framework` help says SOC 2 only.
- A fresh `init && check` exits `1` with no `[error]` lines; `check` exits `3` when planning rejects
  the config; `init-ci` without `--ci` exits `3`.
- `--cloud` with no `cloud.base_url` warns that submission was skipped; malformed-YAML errors
  include a plain-language hint.
- Corrected several documentation errors (copyable `bindings:` examples with nonexistent slots or
  policy IDs, `tenant_id` listed as required, the extensibility guide, the `init-ci` SOC 2 gate
  reason, and A.8.13 / CC7.5 policy descriptions now say they check configuration, not testing).

### Removed

- The `overdue` field from `sigcomply evidence due -o json`.

## [0.64.38]

Baseline release for the beta-readiness changelog. For the complete history of
earlier tags, see the auto-generated notes on
[GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases).

[Unreleased]: https://github.com/SigComply/sigcomply-cli/compare/v0.88.3...HEAD
[0.65.0 to 0.88.3]: https://github.com/SigComply/sigcomply-cli/compare/v0.64.38...v0.88.3
[0.64.38]: https://github.com/SigComply/sigcomply-cli/releases/tag/v0.64.38
