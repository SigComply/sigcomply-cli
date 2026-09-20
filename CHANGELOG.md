# Changelog

All notable changes to the SigComply CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-release binaries and auto-generated notes are published on
[GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases); this file
tracks the human-curated highlights.

## [Unreleased]

### Fixed

- **`na` no longer reads as "implemented" in the Statement of Applicability.**
  `soaStatus` counted `na` alongside pass and waived, so following the
  documented remedy for a control you cannot satisfy
  (`exceptions: [{state: na}]`) turned "never examined" into an assertion of
  implementation on the one document an auditor reads as exactly that — worse
  than the `not implemented` it replaced. An `na` policy never reached its
  rule, so it now abstains from the roll-up entirely: a control with nothing
  but `na` policies reports **not evaluated**. This also closes a quieter leak,
  where a policy mapping to both a `not_applicable` control and an applicable
  one cascaded its `na` onto the applicable control's row.
  Use `state: waived` when you mean "this applies and we are accepting the
  gap" — that still counts as met, with your reason and expiry on the row.
- **A carried-forward control no longer reads as "not implemented" in the
  SoA.** `soaStatus` was the only roll-up in the CLI that did not treat
  carry-forward as the pass it inherits — the compliance score counts it in
  the numerator and `report --view coverage` ranks it with pass. A control
  whose checks were simply not due for re-evaluation this period was reported
  to the auditor as failing.
- **A vacuous pass is now distinguishable from a thorough one on the wire.**
  `resources_evaluated` counts a policy's records *before* its clauses filter
  them, and `all`/`none` are true of the empty set, so a policy that filtered
  500 records down to zero submitted *"All 500 resources passed."* — identical
  to one that inspected all 500. The dashboard could not tell them apart and
  could not be fixed from its side. The aggregator now emits *"Passed, but no
  resources matched the filter — verify this control is in scope."* for such a
  pass. `message` is an existing wire field, so there is **no schema bump and
  no migration**; the slot names behind the diagnostic stay in the CLI, and
  only the sentence crosses the aggregation boundary.
- **Config examples that failed when copied.** Eight `bindings:` examples
  across the docs and one Go doc comment keyed on a slot named
  `user_directory`, which no shipped policy declares — `planner: binding for
  unknown slot "user_directory"`, exit 3. The conventional slot is `evidence`;
  the other four are `roster` (`exactly-one`), `accounts`, `deployments` and
  `changes`. A further fifteen examples named policy IDs that do not exist
  (`soc2.cc6.1.mfa_enforced`, `soc2.cc6.1.access_key_rotation`,
  `soc2.cc7.2.annual_pentest`, …), which is also exit 3 — `project config:
  policies[…]: no such policy in framework`. Every example now names a real
  slot and a real policy. `04-source-plugins.md` also claimed one-or-more was
  the cardinality of "every slot the shipped frameworks declare"; `roster` is
  `exactly-one`.
- **`tenant_id` is documented as optional, which is what it is.**
  `docs/guides/configure-sources.md` and `docs/for-ai-agents.md` listed it as a
  *required* config key for Microsoft Graph sources. It is neither required nor
  auth-bearing: the Graph token is scoped by the credential's home tenant, and
  `tenant_id` only tags each record's provenance. (Deriving that provenance
  from the credential instead of trusting the declaration is separate, larger
  work.)

### Changed

- **Manual-evidence folders are now keyed by the entry's cadence, not by
  the run's audit period.** `{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/`
  where `{period_id}` is daily `2026-01-15`, weekly `2026-W03` (ISO),
  monthly `2026-01`, quarterly `2026-Q1`, annual `2026` — the table
  `docs/configuration.md` has documented since before the code produced
  it, and the keys the Evidence SPA has been telling customers to upload
  to all along.
  **This was a live `exit 1`, not a cosmetic mismatch.** All but four of
  the 137 shipped catalog entries are annual. Their evidence was being
  read from whichever quarter folder the run derived, and
  `isInTemporalWindow` is closed at both ends, so a January upload was
  invisible to the April, July and October runs — including the
  `compliance-annual.yml` workflow `sigcomply init-ci` itself scaffolds,
  where an explicit `--cadence annual` filter bypasses carry-forward.
  **Migration:** if you already have uploads under the old scheme, move
  `…/{entry}/2026-Qn/` to `…/{entry}/2026/` for every annual entry.
  `sigcomply evidence due` prints the folder each entry now reads. There
  is deliberately no compatibility read across periods: re-reading the
  old folder would trip the temporal window, and from the following
  period onward would trip `copy_paste_of_prior_period`, turning a
  missing-evidence failure into a fraud-shaped one.
  Under `fiscal_calendar.type: fiscal_year` the annual cadence keeps
  `FY2026`; under `custom`, and for cadences with no calendar window
  (`continuous`, `hourly`, `every:<duration>`), nothing changes. A
  per-policy `cadence:` override does not move the folder — the
  framework catalog's declared cadence does.
  The **run's** period is untouched: the vault run root, `manifest.json`,
  `summary.json`, the cloud payload's `period_id` and
  `PolicyState.LastPeriodID` are all as before, so there is no schema
  bump and no dashboard change. What does move is the `period_id` inside
  a `signed_document` record (and its `id` and `expected_uri`), which now
  names the window the document actually covers.
- **The prior-period duplication check now has a folder to compare
  against for annual entries** — last year's, where it used to be last
  quarter's, which was always empty. Re-uploading a byte-identical
  document year over year now fails with `copy_paste_of_prior_period`,
  which is what that check exists to catch. Evidence that legitimately
  does not change between periods is declared as an exception in
  `.sigcomply.yaml`.
- **`period.time_basis` is honored.** It has been accepted by the
  validator and read by nothing: every period was derived from the HEAD
  commit's timestamp whatever the config said. `wall_clock` now derives
  from the run's start clock, which for a project that sets it moves the
  run's `period_id` — and therefore the vault run root — whenever HEAD
  sits in an earlier period than the run. `commit` (the default) is
  unchanged.
- **`sigcomply evidence due` reports a period per entry.** The text and
  step-summary output gain a `PERIOD` column and the header names the
  run's period as context rather than claiming every entry shares it.
  Deadlines are now measured on the same clock the period was derived
  from, so a repo with a stale HEAD is no longer told it is months
  overdue for a period the next run will read quite happily. With one
  consistent clock there is no reachable "overdue" state, so the
  `overdue` field is gone from the JSON output and `--within-days 0` now
  means "only what closes today" rather than "only what is already late".

### Added

- **`aws.identity_center` now enumerates permission-set assignments**, which
  makes it the second emitter of `iam_binding` and closes the `is_admin`
  gap it shipped with. The traversal is `sso:ListPermissionSets` →
  `DescribePermissionSet` + `ListManagedPoliciesInPermissionSet` →
  `ListAccountsForProvisionedPermissionSet` → `ListAccountAssignments`,
  plus `identitystore:DescribeGroup` / `ListGroupMemberships`.
  **Zero policy or framework changes were needed** — substitutability
  again: `iso27001.5.3.no_broad_admin_bindings` and
  `iso27001.8.3.no_broad_admin_iam_bindings` already accepted
  `iam_binding` and simply had no emitter on an AWS-only estate, and the
  roster policies' `accounts` slot already accepted it too.
  **The design decision worth keeping:** an `iam_binding` mirrors the
  assignment *as it was made* — a group assignment stays a `group`
  principal and is **not** expanded into per-member records, because the
  least-privilege policies are phrased
  `none(principal_type == "user" AND is_broad_admin_role AND NOT has_condition)`
  and their remediation says to grant admin through groups; expanding
  would report the recommended pattern as a violation of the policy that
  recommends it, and would mis-key the roster join, whose
  `account.non_human` derives from `principal_type`. `is_admin` asks a
  different question — does this *person* hold elevated privileges — so it
  **does** resolve group membership. `internal/sources/aws/iam` already
  split the two the same way. `is_broad_admin_role` is `AdministratorAccess`
  attached **or** a permission-set name containing "admin", and
  `has_condition` is a flat `false` (an assignment carries no IAM
  condition) — both err toward failing a control rather than passing one.
  Remaining blind spot: a permission set reaching admin only through an
  inline or customer-managed policy under a non-obvious name reads as
  not-broad. The traversal costs O(permission sets x accounts) API calls;
  a slot asking only for `directory_user` skips the account fan-out for
  non-admin sets, and a roster-only slot skips the traversal entirely and
  needs none of the `sso:*` permissions. **Breaking for existing
  configs:** a binding that collects `directory_user` or `iam_binding` now
  requires the new read actions above, and a run whose credentials lack
  them fails loudly rather than quietly omitting `is_admin`.
  The L2 cassette gained the new interactions and is now regenerable from
  a committed `//go:build cassette` driver — it is still constructed from
  the published Smithy models, not recorded against a live tenant.

- **`aws.identity_center` — an AWS IAM Identity Center (SSO) source.**
  Emits `directory_user` (v1) and `roster_entry` from one
  `identitystore:ListUsers` listing. Modern AWS human access runs through
  Identity Center rather than IAM users, so on such an estate the roster
  policies were checking the wrong population; Identity Center identities
  carry emails, so they join the roster directly and the `aws.iam:`
  `aliases` block becomes unnecessary. **Zero policy changes were needed** —
  it emits existing cloud-neutral types, which is the substitutability
  property working as designed. `identity_store_id` is optional and
  discovered from `sso-admin:ListInstances`. It emits **v1, not v2**:
  v2's required `is_root` / `has_console_access` /
  `has_programmatic_access` describe an IAM account, and emitting them
  would make the three v2-only IAM policies pass trivially over SSO users
  — inflating the score. One honest gap: Identity Center publishes no
  per-user MFA enrollment, so `mfa_enabled` is best-effort `false` (which
  can only fail a control, never pass one). Bind the MFA policies to the
  IdP that actually holds that state. (`is_admin` was the second gap in
  this entry as first written; the permission-set traversal below now
  answers it.) **The L2 cassette is derived from
  the published Smithy service models, not recorded against a live tenant
  — it needs a live re-record before it can be trusted as a contract test.**
- **Declared-but-never-matched roster keys are now reported.** An
  `experimental.roster.aliases` or `non_human` entry naming an account no
  source returned was silent — a perfectly valid entry for an account that
  does not exist. Runs now print `unused-alias:` / `unused-non-human:`
  naming each key. Usage is accumulated run-scoped across every roster
  policy, because the alias map is shared by reference while each policy
  gets its own evaluation context, so a per-policy verdict would report a
  key as unused in the policy whose slot never bound that source. Printed
  to stdout rather than the logger, whose redaction would rewrite an
  email-shaped alias key. Carried-forward and skipped policies declare
  nothing, so a daily run cannot false-alarm on annual roster policies.
- **Collector errors are classified as retryable or terminal.** A
  rejected or under-permissioned credential used to be retried as
  patiently as a 429 — per binding, sequentially — so one mis-scoped
  credential could spend the whole ~8 min PR budget against every binding
  on that source before the run said anything. 429/5xx/timeouts still
  spend the budget; 401/403/404 and schema failures now fail the binding
  at once. Most plugins needed no change: their SDK errors were already
  wrapped with `%w` and are classified via `errors.As`. **An unclassified
  error is still treated as retryable**, so this is non-breaking and
  adoptable incrementally. New shared contract in
  `internal/sources/errors.go`.

- **The identity-roster check now covers cloud IAM grants, not just accounts.**
  The roster policies' subject slot accepts `iam_binding` alongside the
  `directory_user` family, so a GCP project role held by someone who was never
  an account in any bound directory — a personal Google account, a partner-domain
  user — is joined to the roster and reported like any other unlinked identity.
  `account.key` falls back to `payload.principal_id`, so
  `experimental.roster.aliases` and `non_human` work for `gcp.iam` principals;
  service-account, group and domain principals are excluded automatically, while
  an unclassifiable principal (`allUsers`) stays in the population on purpose.
  No new policy and no new control: adding a source that emits `iam_binding`
  widens what the existing checks see.

- **GitHub Enterprise Server is reachable.** `sources.github` accepts an
  optional `base_url` (default `https://api.github.com`), mirroring the
  key GitLab already had for self-managed instances. Give the API root,
  usually `https://<host>/api/v3`.
- **Vendor onboarding and termination have an entry.** New annual manual
  entries `soc2.cc9.2.vendor_lifecycle_process` and
  `iso27001.5.19.supplier_lifecycle_process`, covering the documented
  procedure plus the period's onboarding/termination records. Deliberately
  flat rather than fanned out: a terminated vendor is one you delete from
  the register, so a per-member folder set can never hold evidence for the
  relationship that ended.
- **Vendor contracts and supplier agreements fan out per vendor.**
  `soc2.cc9.2.vendor_contracts_reviewed` and
  `iso27001.5.20.supplier_security_agreements` now collect one folder per
  register member, like assurance reports — a contract is a
  per-relationship artifact and auditors sample them per vendor.
  **Breaking for projects that already declared `experimental.vendors`:**
  evidence at `{prefix}/vendor_contracts_reviewed/{period_id}/` is no
  longer scanned; copy it into each vendor's folder.
- **The third-party register is checked against the sources you configured.**
  A register entry may declare `providers:` naming the sources it supplies;
  a configured source no entry claims now produces a plan-time warning.
  Advisory, never fatal, and it discovers nothing — it cross-checks the
  register against the estate you already declared. Unrecognized
  `experimental.vendors` subkeys are now reported too (they were parsed and
  silently dropped).
- **Configured-but-unused sources are named.** A source no policy slot binds
  (an `active_directory` source with no `experimental.roster`, say) was
  listed in the collection banner as though it were being read. The banner
  still prints before planning, by design; a new `unbound-source:` warning
  after the plan says which of those were never consulted.

- **Vendor and third-party risk collects per vendor, not per folder.** A manual
  catalog entry can now fan out over a set the project declares in
  `experimental.vendors`: one evidence folder per vendor
  (`{prefix}{evidence_id}.{vendor_id}/{period_id}/`), each checked
  independently, all reported as a single policy. Three new manual policies —
  `soc2.cc9.2.vendor_assurance`, `soc2.cc9.2.cuec_mapping` (fans out over
  subservice organizations only) and `iso27001.5.19.supplier_assurance`.
  Each vendor may declare `assurance_period_end`, the last day its own
  assurance report covers, which fails the check once it is more than 15
  months before the audit period — the only way to catch a stale report,
  since the temporal window proves upload time alone. The date is **declared,
  never parsed**: the CLI still does not read document contents. Risk tier
  decides *which* artifact a vendor owes, never *whether* one is owed; a `low`
  tier is an approved exemption requiring `tier_rationale` and `approved_by`,
  not a silent opt-out. Vendor names, rationales and approver addresses stay
  vault-side — the evaluator reduces the register to two counts before
  submission, so the cloud never learns which third parties a customer uses.
  **Behavior change: a project that declares a register gains one evidence
  obligation per vendor, and those policies fail until each vendor's document
  is uploaded.** Projects that declare no register are unaffected — the
  entries behave as ordinary single-folder manual entries. See
  [Vendor and third-party risk](docs/guides/vendor-risk.md).

- **ISO 27001 now covers the management system, not just Annex A — and
  generates the Statement of Applicability.** **Behavior change: existing ISO
  27001 projects gain 16 manual policies that fail until the documents are
  uploaded.** See the migration note at the end of this entry.

  The ISO framework shipped the 93 Annex A controls and nothing for clauses
  4–10. Certification is not granted against Annex A; it is granted against the
  information security management system, and a Stage 1 audit is in practice a
  documentation review of exactly those clauses — is the scope written down, is
  there a risk assessment process, were internal audits conducted, did top
  management review the ISMS. So a customer could pass every SigComply check,
  read a clean coverage report, and fail Stage 1, with nothing in the product
  having hinted at the gap. Worse, the gap was invisible by construction: the
  universe coverage was measured over was itself missing a third of what the
  auditor asks for, so no number computed inside it could reveal the omission.
  That was an ISO readiness claim we could not back.

  Sixteen management-system requirements now ship as manual `document_upload`
  entries on an annual cadence: `C.4.1-4.2` (context and interested parties),
  `C.4.3` (ISMS scope), `C.5.2` (information security policy), `C.5.3` (ISMS
  roles), `C.6.1.2` (risk assessment process), `C.6.1.3` (risk treatment
  process), `C.6.2` (objectives), `C.7.2` (competence), `C.7.5` (documented
  information), `C.8.1` (operational planning), `C.8.2` (risk assessment
  results), `C.8.3` (risk treatment results), `C.9.1` (monitoring), `C.9.2`
  (internal audit), `C.9.3` (management review), `C.10.2` (corrective action).
  Policy IDs are `iso27001.clause.<n>.<slug>`. The `C.` prefix exists so a
  clause can never be read as an Annex A reference — clause 5.2 and A.5.2 are
  different requirements an auditor tests separately.

  **The 93 and the 16 are never added together.** They are different kinds of
  control and a blended total flatters the headline at exactly the moment the
  honest gap is closed: "93 of 93 covered" would become "109 of 109 covered" on
  the day sixteen requirements nobody has uploaded evidence for were added.
  `core.Control` therefore carries a `Kind` (`catalog`, the default, or
  `management_system`) with an `IsManagementSystem()` predicate; `--view
  coverage` gained a `KIND` column and its own `ManagementSystem` /
  `ManagementSystemOnFile` counters; and the doc-figures test that pins
  published counts to the compiled framework now splits them too. Project-local
  framework extensions carry the same field as `kind:` on a control, decoded
  strictly so an unrecognized value is rejected rather than read as the default.

  The kind lives on the control rather than in an ID-prefix check for two
  reasons. `internal/report` is deliberately framework-registry-free — it reads
  vault bytes plus a catalog handed to it, and must not import
  `internal/frameworks` — so a `"C."` test would smuggle one framework's ID
  convention into a package that is not allowed to know which framework it is
  rendering. And a project-local extension's controls carry neither an `A.` nor
  a `C.` prefix, yet belong in the Statement of Applicability like any other
  selectable control.

  **A management-system requirement cannot be declared `not_applicable`.**
  `validateApplicability` rejects it at config load (exit 3). Nothing would have
  *failed* without this check, which is the problem: control-level applicability
  cascades, so an accepted exclusion would mark every policy under the clause
  `na`, drop them out of the compliance-score denominator, and *raise* the score
  for declining to have an ISMS. Excluding an Annex A control is untouched — it
  is exactly what applicability is for.

- **`sigcomply report --view soa` — the Statement of Applicability, generated.**
  ISO/IEC 27001:2022 6.1.3 d) requires one and it is the first document a Stage
  1 auditor asks for. It must state, per control, which are necessary, why each
  is included, whether it is implemented, and the justification for any
  exclusion. SigComply already held all four — the catalog in the framework, the
  applicability decision and its reasoning in `.sigcomply.yaml`, the
  implementation status in the vault — and had no surface that joined them, so
  the one document the auditor reads first had to be maintained by hand
  alongside the tool that knew the answer. A hand-maintained copy of a derived
  artifact drifts the moment a control is excluded or a check starts failing,
  silently, because nothing compares the two.

  Text, JSON and CSV; CSV is the spreadsheet auditors actually work in. Status
  is derived from the period's results and never asserted — `implemented` only
  when every check that ran passed, then `partially implemented`, `not
  implemented`, and `not evaluated` when nothing ran. A control whose annual
  policy has not run this quarter says so rather than borrowing a pass from the
  catalog. Each row also carries its assurance (`automated` / `manual` /
  `none`), because an implemented control evidenced only by a PDF on file is a
  weaker claim than one where infrastructure was inspected, and a document
  handed to a certification body should not flatten the two.

  The view lists the selectable control catalog and never the management-system
  clauses. Note that this is wider than Annex A: 6.1.3 b) NOTE 1 lets an
  organization design controls from any source, and Annex A is the cross-check
  list rather than the menu — so a project-local extension's own controls belong
  in the SoA too. The filter is `!IsManagementSystem()`, not an `A.` prefix
  test.

  **`--view soa` is the one report view that requires the project config** and
  exits 3 without it. Every other view is a pure reader of vault bytes, so an
  auditor holding only a vault path can produce them. The applicability
  decisions are authored, not observed — there is nowhere in the vault to read
  them from — and degrading gracefully would render every control as applicable,
  turning a deliberate, approved exclusion into a silent inclusion on the single
  document a certification auditor reads first. Refusing is the honest answer; a
  footnote at the bottom of a CSV nobody scrolls to is not.

- **New `.sigcomply.yaml` key: `controls.<id>.justification`.** The *inclusion*
  justification — the other half of what 6.1.3 d) asks for, alongside the
  existing exclusion `reason`. `--view soa` prints it verbatim. Where it is
  absent the view derives one from the checks standing behind the control
  ("Applicable — no exclusion declared. Verified by 3 automated checks.") and
  marks it `(derived)`, so an auditor can tell deliberation from boilerplate and
  the headline note can say how many inclusions still carry a default. Setting
  both `justification` and an exclusion `reason` on one control is a config
  error: a row the SoA reports as excluded must not also carry an inclusion
  justification.

  Three of the sixteen — `C.4.1-4.2`, `C.5.3` and `C.7.5` — are **not strictly
  mandatory documented information** under the 2022 text. Clauses 4.1/4.2
  require the determination to be made rather than documented, 5.3 requires
  roles to be assigned and communicated, and 7.5 governs how documented
  information is controlled. They are included because every certification audit
  asks for them, and the source and the docs both say so: a set advertised as
  "ISO's mandatory documented information" that quietly exceeds it would be the
  same species of overclaim this change exists to fix.

  All sixteen are `document_upload` rather than Evidence SPA click-through
  forms. These are documents an auditor reads — a scope statement, a risk
  register, internal audit findings, management review minutes — and rendering a
  management review as a set of checkboxes someone ticks would reproduce, one
  layer down, the exact overclaim being retired. The SPA already filters
  `document_upload` entries out of its dashboard, so all sixteen are correctly
  absent from it and no SPA change was needed. Clause 6.1.3's own mandatory
  output, the SoA, is deliberately not one of the sixteen — SigComply generates
  it; `C.6.1.3` covers the risk treatment process and plan, which the SoA does
  not replace.

  **Migration — what an existing ISO 27001 project will see.** On the next
  annual run, 16 new manual policies fail because their evidence folders are
  empty: `sigcomply check --cadence annual` exits `1`, the compliance score
  drops (16 policies enter the denominator, none pass), and the Cloud dashboard
  shows the same drop. That is a correction to a score previously computed over
  an incomplete universe, not a regression in posture. No config key is
  required, no existing control's behavior moves, and the daily and quarterly
  workflows are unaffected since all sixteen are annual. `sigcomply evidence
  due` lists every clause folder still empty for the current period with the
  exact upload URI for each, and always exits 0. To keep the build green while
  working through the backlog, waive the policies with a reason and an
  `expires_at` — the control cannot be excluded. Guide:
  `docs/guides/isms-clauses.md`. Design: `docs/architecture/13-isms-clauses-and-soa.md`.

- **Change management is now evidenced from the changes themselves, not just
  the guardrail around them.** Two new evidence types — `pull_request` and
  `deployment` — collected from GitHub and GitLab over the audit period, with
  four new policies per framework (SOC 2 CC8.1, ISO 27001 A.8.32): every merged
  change had an independent approval, passed its automated checks, and was
  approved *before* it was merged; and every production deployment traces back
  to an approved change.

  The eight CC8.1 policies that shipped before this read `git_repository` —
  branch protection on, reviews required, force-push off. That is a photograph
  of the configuration at the instant the run executes, and it answers "is
  review required?". It cannot answer "did the changes that actually shipped
  get reviewed?", because a protection setting can be bypassed by an admin,
  disabled and re-enabled between runs, or simply not apply to everyone, and
  none of that leaves a trace in the setting. An auditor testing CC8.1 asks for
  the population of changes in the period and samples it. Until now we could
  not produce that population at all. Both halves are kept — the guardrail
  check and the outcome check are different assertions.

  This is the first policy family that reads what *happened during* the period
  rather than what is true right now. The plumbing already existed: the
  orchestrator has been injecting `period_start`/`period_end` into every slot
  request since the manual-evidence work, and only the manual plugin was
  reading them.

  Three notes on what these policies deliberately do **not** claim. They do not
  check that the merger differs from the author — merging your own change after
  an independent approval is normal practice, and Vanta and Drata both check
  the approver, not the merger. They do not compare the deployer against the
  merger: that is a field-to-field comparison across two slots, which the
  `pass_when` DSL cannot express, so the deployment policy asserts traceability
  to an approved change instead. And they do not claim ISO A.8.31 (separation
  of development, test and production environments) — a deployment record
  proves who released what, not that the environments are separated, and
  claiming it would be exactly the kind of overclaim the coverage work exists
  to prevent. A.8.31 stays manual evidence.

  For a change that legitimately merged without an approval — a production
  hotfix, an automated dependency bump — waive it with the existing scoped
  exception mechanism, keyed on the record ID the policy reports
  (`acme/api#1234`). The waiver then lives in your repository, version
  controlled and reviewable, which is stronger evidence than a justification
  typed into a vendor's dashboard.

  No wire or dashboard change: these are ordinary policy results carrying the
  existing per-policy counts, so `resources_evaluated` is the number of merged
  changes in the period and `resources_failed` the number that fell short.
  **No Rails deploy is needed for this one.**

  Requires wider read scopes than before. GitHub: *Pull requests: read*,
  *Deployments: read*, *Checks: read*, *Commit statuses: read* alongside the
  existing repository scopes. GitLab: `read_api` already covers it, but the
  token's user needs at least Reporter on each project. Approver lists are
  readable on GitLab Free; approval *rules* are Premium-only and degrade to
  zero rather than failing the run.

- **`sigcomply report --view coverage` — what is actually behind the green.**
  A compliance score is a pass rate over the policies that ran, and a policy
  satisfied by a document sitting in your evidence folder counts exactly as
  much as one that inspected live infrastructure. Both pass. Nothing in the
  product distinguished them, so a run whose controls rest on uploaded PDFs
  read identically to one that verified everything — for SOC 2 that is 27 of
  43 criteria, the whole CC1–CC5 governance spine plus vendor risk and
  privacy. The new view reports, per control, which kind of check stands
  behind it, how many of each, and whether that evidence exists for the
  period. It is framework-scoped rather than run-scoped on purpose: cadence
  is independent of the audit period, so a control checked annually writes no
  result at all in three quarters out of four, and a view built only from the
  period folder would show a clean bill of health over whatever happened to
  run. A control with no result says so and names its cadence, so "annual,
  expected" is distinguishable from "daily, broken". Flags: `--view coverage`,
  with `--format text|json|csv`. Reference: `docs/reference/commands.md`.

- **`sigcomply check` now says what earned the passes.** `pass=84` is the
  number a reader over-trusts. The summary now breaks passing policies into
  those verified by inspection and those satisfied by a document being
  present, and says plainly that a document-presence pass means the file was
  there, not that its contents were checked.

- **The effective evidence mode is recorded everywhere a result goes.** Every
  `PolicyResult` carries the mode it was actually evaluated under, plus
  whether the project overrode the framework default — persisted in
  `result.json` and submitted on the wire as `evidence_mode` /
  `evidence_mode_overridden`. This closes a documented-but-unimplemented gap:
  a project could downgrade an automated check to a document upload and no
  artifact anywhere recorded that it happened. Bumps the cloud schema to
  `sigcomply.cloud.v4` (both fields are non-identifying — a two-value enum
  and a boolean). **Deploy the Rails side first**: an unknown field is
  silently dropped by strong params and the request still returns 201.

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
  decoded strictly, so a typo such as `normalize:` fails to load.
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

- **The policy content hash now covers `pass_when`.** It previously
  covered only a policy's wiring (id, control, rule reference, severity,
  cadence, slots, parameters, schema digests), so editing a clause, an
  operator or a threshold left the hash unchanged and the policy carried
  the old signed envelope forward until its next cadence boundary. Since
  every shipped policy is `pass_when`-driven, the guard against
  "silently re-certifying old evidence with new rules" was not actually
  covering the rules. **Every stored policy hash rotates once**, so the
  first run after upgrading re-evaluates every policy; that is expected
  and self-correcting. The canonical projection is hand-built rather than
  a struct marshal, so renaming a Go field cannot rotate hashes.

- **A release is now gated on the test suite.** `auto-release.yml` calls
  `test.yml` and waits for it, instead of racing it on the same push. The
  E2E repos install `releases/latest` and resolve it at run time, so an
  ungated tag reached them the moment it was pushed.
- **The scaffolded monthly cron moved off the period boundary**, `0 2 1 * *`
  → `0 2 20 * *`, joining the quarterly and annual crons inside the period.
  On the 1st it collided with the calendar-quarter boundary four times a
  year, which is the race the other two were moved to avoid.
- **`sigcomply init-ci` scaffolds a current release pin.** The embedded
  templates still pinned `v0.64.38` while the copy-paste examples had moved
  on; both are now `v0.73.2`.
- **`examples/github-actions/multi-environment.yml` no longer uses a CI
  matrix** over accounts. Multi-account estates are bracketed source
  instances in `.sigcomply.yaml`, and one run covers them — a matrix
  produced N independent runs, each asserting the whole framework from one
  account's data.

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

- **An unhashable policy no longer fails open.** `PolicyContentHash`
  returns `""` when canonicalization fails, and the planner's
  content-hash gate was written as `contentHash != "" && ...`, which
  *skipped* the mismatch check rather than forcing evaluation — the
  opposite of the "treat the policy as due defensively" claim in its own
  comment. The empty case now forces evaluation. Latent before this
  release (the projection held only strings, bools and slices, so the
  marshal could not fail); pulling the user-supplied `pass_when` `value`
  into the hash makes it reachable.

- **`count` with `min_percentage: 0` is no longer exempt from the vacuity
  guard.** It passes over the empty set exactly as `all`/`none` do, but
  reported no `vacuous_clauses` diagnostic — a green tick over an estate
  nobody examined, with nothing to say so.
- **`sources.Env` no longer carries an unused `Vault` field.** Nothing read
  it and nothing set it; its doc comment claimed `manual.pdf` needed it for
  attachments, which was never true — `manual.pdf` configures its own
  backend.
- **Corrected a documented workaround that did not exist.**
  `docs/architecture/12-multicloud-sources.md` told GCP-/Azure-only
  customers they could cover the six password policies "via the manual
  evidence flow". No such catalog entry exists and one cannot be added
  without obliging every AWS customer to upload a PDF they do not need. The
  doc now shows the per-policy `exceptions: {state: na}` path that actually
  works, and is explicit that it does not repair the score denominator.

- **A configured source with no credentials now fails the run at startup
  (exit `3`) instead of failing during collection.** `sources:` is the
  operator's declaration of what a project audits, so a source listed there
  that nothing in the environment can authenticate as is a configuration
  error, not a collection outcome. **Behavior change:** a run that previously
  limped to a per-policy execution error (exit `2`) now stops before
  collecting anything, naming the source and the environment variables to
  set. Token sources (`github`, `gitlab`, `okta`, `active_directory`) and all
  `gcp.*` sources already behaved this way; the four paths that did not are
  now fixed:
  - `aws.*` — `awscfg.Load` retrieved credentials eagerly only when
    `role_arn` was set. `LoadDefaultConfig` assembles a *lazy* provider chain
    and succeeds with no credentials at all, so the ambient path built
    cleanly and failed at the first API call — after `withRetry` had retried
    a permanent failure through its whole backoff budget, per binding,
    sequentially.
  - `azure.*` — factories constructed a `DefaultAzureCredential` and never
    requested a token. That constructor cannot fail: a sub-credential whose
    own constructor fails is still appended to the chain wrapped in an error
    reporter. `azcommon.NewCredential(ctx, scope)` now mints one token to
    prove the credential works, memoized per scope so 13 ARM sources cost one
    request rather than 13.
  - `manual.pdf` on the `s3` and `azure_blob` backends — each builds its own
    client outside the shared credential helpers and had the same two holes.
    manual.pdf is a project-level singleton, so this turned one configuration
    error into a collection error on every manual policy in the run.
  - The `s3` and `azure_blob` **vault** backends, for the same reason. The
    vault is where a run puts its signed evidence, so an unresolvable
    credential there previously surfaced only after the run had collected and
    evaluated everything.

  Resolution is memoized per AWS `Options` / per Azure scope, and a failure is
  never cached, so a credential that appears mid-run is picked up. Every eager
  resolve is bounded by a 60s timeout so a blackholed credential endpoint
  cannot stall startup — well above any legitimate resolve, so the operator
  still sees the real error rather than a timeout hiding it. AWS error
  wrapping also drops a now-inaccurate `load AWS config:` prefix — the config
  loaded fine; the credentials did not resolve.

- **`sigcomply report` no longer hides errored policies.** `--view scope`
  listed only skipped controls, so an errored policy — an unevaluated control
  that, unlike a skip, stays in the compliance-score denominator and counts
  against it — was invisible in the very view meant to name unevaluated
  controls. Errors now appear alongside skips with a status column. The scope
  header also no longer claims both kinds are excluded from the score; that
  was true of skips and false of errors.

- **`--view latest` now explains a failure or error inline.** It printed a
  bare `error` with the diagnostic stranded in the vault's `result.json`. It
  now carries the same one-line reason `check` prints. A related bug meant a
  vacuous pass (a clause that examined no resources) rendered as a blank cell
  in a report while `check` explained it correctly — the diagnostic did not
  survive the JSON round-trip out of the vault.

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
