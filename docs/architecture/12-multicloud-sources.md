# 12 — Multicloud Sources

This document is the design reference for SigComply's source plugins across cloud and identity providers. It defines the **authentication model**, **package layout**, **source-ID naming**, and **dependency policy** that every provider plugin follows, so that adding a new provider (as GitLab, the expanded GCP suite, and Azure each were) is a mechanical exercise rather than a fresh design each time.

It complements [04-source-plugins.md](04-source-plugins.md) (the factory contract and the policy ↔ evidence-type ↔ source registry) and [04a-evidence-type-registry.md](04a-evidence-type-registry.md) (the cloud-neutral evidence-type schemas). The *phased rollout, work-unit breakdown, and progress tracking* live outside the CLI repo in the **Core Source-API Integrations Plan** (`core_source_integrations_plan.md`, in the `sigcomply-repositories/` root), which is the source of truth for what ships when.

---

## Why multicloud is mostly mechanical

A policy accepts an **evidence type**, not a vendor. The evidence-type schemas are already **cloud-neutral** — `object_storage_bucket`, `managed_database_instance`, `directory_user`, `firewall_rule`, etc. — and cover every type the policy set consumes (31 distinct types in the shipped registry). So a new provider almost always **reuses an existing schema** and emits records into it; new schemas are the exception, not the rule.

This yields the substitutability property: one "object storage encrypted at rest" policy spans AWS S3, GCS, and Azure Blob because all three emit the single `object_storage_bucket` type. Adding a new source for an existing type needs **zero policy changes**.

---

## Provider coverage (current and planned)

| Provider | Hosting | Auth | Status |
|----------|---------|------|--------|
| **AWS** | management plane (per region/account) | SDK default chain | 24 plugins (mature) |
| **GCP** | management plane (per project) | Application Default Credentials | 18 plugins (mature) |
| **Azure** | management plane + Entra/Graph | DefaultAzureCredential / OIDC (Entra via raw Graph REST) | 14 plugins (mature) |
| **GitHub** | SaaS | token | 1 plugin → `git_repository`, `directory_user`, `source_control_org_policy`, `vulnerability_finding`, `pull_request`, `deployment` |
| **GitLab** | SaaS / self-managed | token | 1 plugin → `git_repository`, `directory_user`, `pull_request`, `deployment` |
| **Okta** | SaaS | token | 1 plugin → `directory_user`, `okta_app`, `roster_entry`, `password_policy.v2` |
| **Active Directory** | on-prem (LDAPS / StartTLS) | bind DN + password | 1 plugin (`active_directory`) → `roster_entry` |
| **Manual** | customer bucket | n/a | 1 plugin (`manual.pdf`, project singleton) |

Totals: **61 plugins** (AWS 24 · GCP 18 · Azure 14 · GitHub 1 · GitLab 1 · Okta 1 · Active Directory 1 · Manual 1) emitting **31 distinct cloud-neutral evidence types**. The full provider × evidence-type matrix lives in [04-source-plugins.md](04-source-plugins.md); see the plan's gap matrix for per-evidence-type history.

---

## Source-ID naming

Source IDs follow **`<provider>`** for single-service providers and **`<provider>.<service>`** for multi-service providers:

- Single-service (one plugin per provider): `github`, `okta`, `gitlab`, `active_directory`.
- Multi-service (one plugin per service): `aws.s3`, `aws.iam`, `gcp.storage`, `gcp.sql`, `azure.storage`, `azure.entra`.

The `<service>` segment names the underlying cloud service, not the evidence type — one plugin may emit several types (e.g. `azure.keyvault` → `kms_key` + `secret`; `gcp.scc` → `threat_detection_service` + `security_service` + `vulnerability_finding`). Keep a plugin to one underlying service.

---

## Package layout

Plugins live under `internal/sources/`:

- **Multi-service providers nest per service:** `internal/sources/<provider>/<service>/` (e.g. `aws/s3/`, `gcp/storage/`, `azure/storage/`). Each service is its own Go package and its own source ID.
- **Single-plugin providers are flat:** `internal/sources/<provider>/` (e.g. `github/`, `okta/`, `gitlab/`, `activedirectory/` — the package drops the underscore; the source ID keeps it).

Each package ships the canonical file set:

| File | Contents |
|------|----------|
| `factory.go` | `const SourceID`, `func init()` calling `sources.RegisterFactory(SourceID, build)`, and `build(ctx, env)` that parses config and calls `New(...)`. |
| `<service>.go` | `Plugin` struct, `Options`, `New` / `NewFromX`, the `ID()` / `Emits()` / `Init()` / `Collect()` methods, the payload struct, a minimal mockable `API` interface, and the real-SDK adapter. |
| `<service>_test.go` | A `fakeAPI` plus assertions (record count, ID sort order, payload validity, key field mappings). |

Plugin conventions (per the plan's §4.5 WU template): inject `Now()`, **sort records by `ID`**, set `IdentityKey` for identity types, wrap errors with context, handle pagination, and populate **all `required` schema fields** for each emitted type.

### Registration

Each plugin self-registers in its `init()` via `sources.RegisterFactory`. A package only initializes if it is imported, so every plugin is added as a **blank import** to `internal/sources/builtin/builtin.go`:

```go
_ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/firewall"
```

No central registry edit is needed: `internal/sources/builtin/coverage_test.go` auto-discovers factories and fails the build if any accepted evidence type lacks an emitter. (A plugin that cannot build without credentials uses the hardcoded-`Emits()` fallback pattern in `coverage_test.go` — `gcp.iam` and `azure.entra` are the two that need it. The AWS plugins construct there under static dummy credentials, which the SDK's env provider resolves in-process with no network call.)

---

## Authentication model per provider

Auth is **read-only** and, in CI, prefers keyless federation (OIDC / workload identity) over long-lived secrets.

- **GCP** — Application Default Credentials (ADC): the existing pattern (`storage.NewClient(ctx)`, service clients via `google.golang.org/api/...`). In CI, Workload Identity Federation. Config key: `project_id`.
- **Azure** — `azidentity.NewDefaultAzureCredential(nil)`: OIDC / workload-identity federation in CI (no secrets), falling back to `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`. `azcommon.NewCredential(ctx, scope)` mints one token to prove the credential works before any plugin is returned, so a missing identity is exit 3 at startup rather than a failure at the first API call; the verified credential is memoized per scope (ARM / Graph), so 13 ARM sources cost one token request, not 13. The cache key is the scope alone because `DefaultAzureCredential` resolves one ambient identity per process — if per-tenant credentials are ever added, that key must grow a tenant component. Management plane via `armXXX` clients scoped to a `subscription_id`; **Entra / Microsoft Graph** via the Graph v1.0 REST API (raw `net/http`, no vendor SDK) with the *same* credential. Config keys: `subscription_id`, `tenant_id` (Graph). Required Graph scopes and the Entra ID P1/P2 caveat for per-user MFA reporting are documented per the relevant WU.
- **GitLab** — token from config `token` or `GITLAB_TOKEN`; client `gitlab.com/gitlab-org/api/client-go`; scope `read_api`. Config key: `group` (or `instance`); `base_url` (default `https://gitlab.com`) for self-managed.
- **GitHub** / **Okta** — unchanged: token from config or env (`GITHUB_TOKEN`/`GH_TOKEN`, `OKTA_API_TOKEN`), direct HTTP (no vendor SDK). GitHub config keys: `org`; `base_url` (default `https://api.github.com`) for GitHub Enterprise Server, mirroring GitLab's self-managed key above.

Per-provider config keys and required scopes are catalogued in `docs/configuration.md` as each plugin lands.

---

## Dependency policy

**Dependencies are added at first use, not pre-added.** Go's `go mod tidy` strips modules with no importing code, so a dep added "ahead of need" would not survive a tidy. Each provider's SDK therefore enters `go.mod` in the first work unit that imports it:

- `gitlab.com/gitlab-org/api/client-go` — present (GitLab plugin). (Note: the client moved from the deprecated `github.com/xanzy/go-gitlab`.)
- **Microsoft Graph** — no SDK dependency; the Entra plugin calls the Graph v1.0 REST API directly over `net/http` (`grep msgraph go.mod` is empty).
- `github.com/Azure/azure-sdk-for-go/sdk/azidentity` — **already present** (v1.x), pulled in by the manual-evidence Azure Blob backend; reused by Azure management-plane plugins. The `armXXX` resource-manager modules are added per Azure service WU.
- GCP (`cloud.google.com/go/...`, `google.golang.org/api/...`) and AWS SDK modules are already present and extended per service.

---

## Cross-vendor identity contract (`directory_user`) — settled (WU-0.2)

Every account-bearing identity source — AWS IAM, GitHub, Okta, GitLab, GCP, Azure Entra — emits into the cloud-neutral `directory_user` type. (Active Directory has no MFA signal and emits only `roster_entry`, the list-of-people type that roster policies match those accounts against. AWS IAM Identity Center — `aws.identity_center` — emits both, and `iam_binding` besides, but see the Identity Center caveat under Decision 1.) `directory_user` is not the only shape a roster can vouch for: the roster policies' subject slot also accepts `iam_binding`, so a cloud role grant is joined to the roster on its principal even when the holder is an account in no directory at all. Two questions had to be settled so that adding a non-AWS identity source is mechanical and so the cross-vendor admin-MFA policies actually fire. Both are now decided.

**Decision 1 — non-AWS identity sources emit `directory_user` (v1), not v2.**
`directory_user.v2` adds three **required** AWS-centric fields — `is_root`, `has_console_access`, `has_programmatic_access` (`internal/evidence_types/schemas/directory_user.v2.json`). Those have no honest analog on GitHub, Okta, GitLab, Cloud Identity, or Entra, so non-AWS sources **must not** fabricate them. v1 requires only `id` + `mfa_enabled` and exposes the cross-vendor fields (`is_admin`, `is_active`, `email`, `mfa_enabled`, `last_login_at`, `display_name`) as optional. AWS keeps emitting v2; everyone else emits v1. GitHub already does this (`internal/sources/github/github.go` emits `"directory_user"` / v1).

**Decision 1, addendum — "AWS" here means AWS *IAM*, not "any AWS source".**
`aws.identity_center` (IAM Identity Center, formerly AWS SSO) is an AWS plugin that emits **v1**, because the v2 required fields describe an IAM account, not an SSO identity: an Identity Center user has no root flag and no access keys. Were it to emit v2, the three v2-only policies — `soc2.cc6.1.root_mfa_enabled`, `soc2.cc6.1.no_root_access_keys`, `soc2.cc6.1.no_direct_iam_policies` (and `iso27001.5.15.*` in `policies_5_organizational.go`) — would start evaluating SSO identities and pass on them trivially, inflating the compliance score. So the rule is not "provider == AWS ⇒ v2"; it is "**the source's identities are IAM users ⇒ v2**". Every other identity source, inside AWS or out, emits v1. Emitting v1 costs nothing on the roster side: the roster subject slot accepts the whole `directory_user` family plus `iam_binding` (`rosterSubjectTypes`), and the MFA policies accept both `directory_user` versions — so no policy changed when `aws.identity_center` landed, and none changed again when it grew an `iam_binding` emitter.

**Identity Center caveat — it cannot prove MFA, and that is visible in its output.**
No public Identity Center API exposes per-user MFA enrollment: MFA is configured at the instance level, or — when the identity source is an external IdP synced over SCIM — enforced by that IdP. `mfa_enabled` is schema-`required`, so the plugin emits it **best-effort `false`** (the same convention `internal/sources/gitlab` uses for a 2FA flag its token cannot read). False can only ever *fail* a policy, never pass one, so the error is in the safe direction — but it is still a finding the operator cannot fix from Identity Center. An estate that wants a real MFA verdict binds the identity source itself (`okta`, `azure.entra`, `gcp.directory`) and pins the MFA policies' `evidence` slot to it with a `bindings:` override — see [configure-sources.md](../guides/configure-sources.md#aws-iam-identity-center-awsidentity_center). This is the one place the plugin knowingly emits a value it cannot verify; everything else it cannot answer it omits.

**Decision 2 — `is_admin` and `is_active` are mandatory in practice, even though the schema marks them optional.**
The admin-MFA policies are phrased as `none(is_admin == true AND mfa_enabled == false)`:

- `soc2.cc6.1.mfa_enforced_admins` — `internal/frameworks/soc2/policies_cc6.go:47`
- `iso27001.8.2.privileged_mfa_enforced` — `internal/frameworks/iso27001/policies_8_technological.go:34`

The evaluator treats a **referenced-but-absent field as a contract gap, not a pass**: `getField` miss → `status=error` (exit 3), see `evalCondition` in `internal/evaluator/pass_when.go` and `TestPassWhen_AbsentField_Errors`. So a source that omits `is_admin` does **not** silently no-op these policies — it makes them **error**, which is the intended way to surface a coverage gap (the policy comments say so explicitly). Therefore every `directory_user` emitter **must populate** `is_admin` (vendor heuristic: org owner / SuperAdmin / Owner-or-Maintainer / privileged directory-role) and **must populate** `is_active` (from the vendor's account-status field; `true` when only active identities are listable). If a source genuinely cannot compute `is_admin` yet, that is a tracked coverage gap for its WU (e.g. Okta, WU-1.2) — not a license to omit the field. **Closed (2026-09-20): `aws.identity_center` now populates `is_admin`.** Admin-ness there is a permission-set question, not a user attribute — `ListPermissionSets` → `DescribePermissionSet` + `ListManagedPoliciesInPermissionSet` → `ListAccountsForProvisionedPermissionSet` → `ListAccountAssignments` — and the plugin now walks it, resolving group membership (`identitystore:ListGroupMemberships`) so a person who is admin *only* through a group is not read as `is_admin: false`. That traversal also makes the plugin the second emitter of `iam_binding`, which needed no policy edit at all. **Two rules came out of it, and they hold for any future emitter.** (a) *The grant record mirrors the assignment as made; the person record answers about the person.* `iam_binding.principal_type` stays `group` for a group assignment, because the least-privilege policies are phrased `none(principal_type == "user" AND is_broad_admin_role AND NOT has_condition)` and their remediation says to grant admin through groups — expanding a group grant into member records would report the recommended pattern as a violation of the policy recommending it, and would mis-key the roster join, whose `account.non_human` is derived from `principal_type`. `is_admin` is not asking that question, so it does resolve membership; `internal/sources/aws/iam` already split the two this way. (b) *"Emitting zeros would be misleading evidence" is about fabricating a value you cannot compute, not about computing one conservatively.* This reconciles the rule with Decision 1's `password_policy` deferral, which it otherwise rubs against: `is_broad_admin_role` over-reports (an "admin"-named set with no admin policy is flagged) and `has_condition` is a flat `false` — both err toward *failing* a control, the recoverable direction. For `password_policy` no *uniformly* conservative value exists — but the field named here was the wrong one, and the correction matters. A zeroed `min_length` **fails** `min_length >= 14`, which is the recoverable direction; the zero that passes is `max_age_days`, because `0` is the vendors' own encoding of "no expiry" and the expiry clause deliberately accepts it. (Consequence, still true and still open: an AWS account with **no** password policy at all passes `soc2.cc6.1.password_expiry_90d`.) The real reason zeros were not viable under v1 is simpler: v1 required all eight fields, so a source that could read two of them had to invent six, and "invent six" is not conservative in any direction. `password_policy.v2` removes that forcing — see the section below. **The blind spot that remains:** a permission set reaching admin through an inline or customer-managed policy under a non-obvious name reads as not-broad; closing it means parsing IAM policy documents.

> **Schema-text caveat.** `directory_user.v1.json`'s description for `is_active` reads "Absent means assume active." That default is **aspirational** — it would only apply to a rule that opts into it with an explicit `is_set` guard. The generic evaluator does **not** apply it; a bare reference to an absent field errors, in a condition and in a filter alike. The operative contract is **populate, don't rely on the default.**

Optional vendor-specific fields (`email`, `is_external`, `is_service_account`, `mfa_factor_count`, `last_login_at`) may be omitted when the vendor doesn't surface them; any policy that reads them must guard with `is_set` — in the condition *or* in the filter. A bare clause `filter` is not a guard: an unevaluable filter errors the policy rather than silently dropping the record (see `filterRecords`), which is what used to turn an omitted optional field into a vacuous pass.

## `password_policy` schema fit for GCP / Azure — `v2` shipped; the collectors are still open

> **Status.** `password_policy.v2` ships, and so does the **Entra
> collector**: `azure.entra` emits `password_policy.v2` from `GET /domains`
> (permission `Domain.Read.All`, no P1/P2 license), one record per verified
> domain. The **GCP collector is still unwritten** — it is blocked on the
> three unverifiable wire-format details recorded under D1, not on the
> schema. The verified vendor detail below is the input for whoever writes
> it.
>
> **What the Entra collector emits, and what it refuses to.** `max_age_days`
> ← `domain.passwordValidityPeriodInDays`, with Microsoft's documented
> never-expires sentinel (`2147483647`) translated to the schema's `0`
> ("an observed no-expiry"), and omitted entirely for a federated domain,
> whose passwords an external IdP validates. Everything else is absent,
> with `not_configurable: [min_length, reuse, complexity]` recording that
> the absence is structural. In particular it does **not** emit
> `complexity_model: "fixed"`, although this schema's own description names
> Entra's character-class rule as the example of that arm. Two reasons, and
> the second is the general one: (a) `fixed` is legitimate only for a rule
> the tenant cannot change, and Entra's is changeable —
> `user.passwordPolicies` accepts the documented value
> `DisableStrongPassword`, and in a federated or hash-synced domain the rule
> in force is the external directory's, which Graph does not expose;
> (b) even where it holds, the rule would be read from Microsoft's
> documentation rather than from the tenant, and `fixed` would then pass
> both `password_complexity` policies for every Entra tenant unconditionally
> on the strength of a string constant in our own source. Absent + vacuous
> is the honest verdict. Net effect: an Entra-only estate answers
> `soc2.cc6.1.password_expiry_90d` automatically; the other five stay
> unanswered and want a reasoned `na`.
>
> **What v2 changes.** Complexity became a discriminated union —
> `complexity_model` names the KIND of answer a source has (`per_class` |
> `strength_enum` | `fixed` | `none`) and only that kind's fields are
> required — reuse became a boolean (`reuse_prevented`) with the depth as an
> optional refinement, every platform-dependent field became optional so
> absence is expressible, and each record carries `scope` + `precedence` so
> N records are not read as interchangeable. `not_configurable` names the
> attributes a platform exposes no tenant setting for, which is how "Entra
> does not let you set a minimum length" stops looking like "we did not read
> one". The value itself still stays absent: a documented default is a value
> the tenant may have overridden, so reading one out of a manual says
> nothing about this tenant and is never signed into evidence.
>
> **The clauses were reframed, not the sources reinterpreted.** Three of the
> six policies asked questions a `strength_enum` source structurally cannot
> answer. `password_complexity` (×2) now reads *"a password-strength control
> is enforced"* — satisfied by a per-class source's four booleans, by a
> strength-rating source reporting its strongest rating, or by a
> platform-enforced rule the tenant cannot weaken.
> `password_reuse_prevention` now reads *"reuse is prevented"*, because the
> depth is genuinely undisclosed by some vendors and the clause must not
> claim to know it. `min_length` / `expiry` were not reframed; they only
> learned that the field may be absent, and a record that cannot answer is
> filtered out of the clause's scope (reported as a vacuous clause) rather
> than failed on a setting nobody read. Accepted trade, recorded here so it
> is not rediscovered as a bug: an AWS account with history depth 1 now
> passes "reuse is prevented" where "the last 24" would have failed it. A
> second clause on the depth is a separate, deferred decision.
>
> **Both shipped emitters moved to v2** (`internal/sources/aws/passwordpolicy`,
> `internal/sources/okta`) and neither emits both versions: every record a
> binding returns lands in the same slot, so dual-emitting would double the
> resource counts and write two signed envelopes for one fact. The six
> policies accept `password_policy` **and** `password_policy.v2` so a
> project-local plugin still on v1 keeps binding.
>
> **Two things in the original analysis below are no longer true.**
> **(1) `password_policy` is not AWS-only.** Okta emits it as of the Okta
> password-policy collector — its API answers all eight required fields
> essentially 1:1, so no schema work was needed. Any Okta-backed estate now has
> automated coverage of the six password policies, and the `state: na` recipe at
> the end of this section is for estates with neither AWS nor Okta.
> **(2) The GCP half of the rationale has expired.** Google's Cloud Identity
> **Policy API reached GA on 2025-02-20** (open beta 2024-10-24) and exposes
> setting type `settings/security.password` with six fields: `minimumLength`,
> `maximumLength`, `allowedStrength`, `allowReuse`, `expirationDuration` and
> `enforceRequirementsAtLogin`. So "a Go collector cannot honestly populate
> *any* field" is stale. It does **not** follow that GCP can fill *this*
> schema: `allowedStrength` is a two-value enum (`STRONG`/`WEAK`), and Google
> states in its own admin documentation that *"a strong password doesn't need
> to have a specific number of characters of a specific type"* — `STRONG` is
> entropy plus breach and common-password screening, explicitly **not** a
> character-class rule. Mapping `STRONG` → "all four true" would therefore be
> exactly the fabrication this section rejects, and Google says so itself.
> GCP still emits nothing: the `v2` with a complexity abstraction it was
> waiting on now exists (see Status above), so what is missing is the
> collector, not the schema. The Azure/Entra analysis below stands unchanged.
>
> Three things a future collector must handle, all verified against Google's
> own reference and none of them obvious: the API returns only policies where a
> value was **explicitly set**, and an omitted field carries a documented
> default (`allowedStrength` STRONG, `minimumLength` 8, `maximumLength` 100,
> `allowReuse` false, `expirationDuration` 0) — Go zero values are the wrong
> answer. There is **no effective-policy endpoint**: several policies apply per
> org-unit and group, and reduction is the caller's job, field by field, with
> the highest `policyQuery.sortOrder` winning. And the quota is **1 QPS per
> customer, not increasable**, so the collector must not parallelize.
> Access is **super-admin only**, via domain-wide delegation with the scope
> `cloud-identity.policies.readonly` allowlisted verbatim — a broader scope is
> rejected.

The `password_policy.v1` schema is **AWS-IAM-shaped**: eight required fields — `min_length`, `max_age_days`, `reuse_prevention_count`, and four discrete complexity booleans (`requires_uppercase`/`_lowercase`/`_numbers`/`_symbols`). That is what forced v2. Because every consumed field was schema-`required`, a partial record was not viable — the evaluator errors (exit 3) on any referenced field a record omits (`evalCondition` in `internal/evaluator/pass_when.go`), and emitting zeros/false for unknowable fields is **misleading evidence**, not missing evidence — so a source that can answer two questions out of five had no way to emit anything at all. v1 stays registered and frozen (a project-local plugin may still emit it); the in-tree emitters and the six consuming policies moved to v2, which keeps v1's field names and meanings and relaxes rather than rewrites them.

**Original decision (superseded in part): neither GCP nor Azure emits `password_policy`.** The reasoning below is why v1 could not be filled; v2 removes the schema blocker, and the two collectors remain unwritten for the reasons recorded under D1 (a Google collector owes an L2 cassette, and its three wire-format details are unverifiable without a real tenant). The vendor facts still stand:

- **GCP (Cloud Identity / Workspace).** Cloud IAM has no password policy at all (it governs authorization, not human credentials — confirmed). A Workspace password policy *exists* (min/max length, expiry, "enforce strong password") but is **Admin-Console-only**: the Admin SDK Directory API exposes **no** policy object — `Customer`/`Domain` carry no `passwordPolicy`, no length, no expiry, no reuse. "Strong password" is a single opaque Google rating, not four complexity booleans, and there is **no** reuse/history concept. A Go collector cannot honestly populate *any* field automatically.
- **Azure (Entra ID).** For cloud-only accounts, length (8) and complexity (fixed "3 of 4 character classes") are **Microsoft constants**, not tenant-readable settings — hard-coding them would fabricate the four-boolean shape (and "3 of 4" is structurally not four independent booleans). History is depth-1 on change / unenforced on reset, with no numeric count. The **only** genuinely API-readable knob is expiration: `domain.passwordValidityPeriodInDays` (+ `passwordNotificationWindowInDays`) via Graph, plus per-user `user.passwordPolicies`. One real field out of eight required ⇒ cannot faithfully populate the schema. **Superseded by v2 and by the shipped collector:** one real field out of eight was fatal only while all eight were *required*. v2 made them optional, so the one readable knob is now emittable on its own and `azure.entra` emits it — see Status above. The vendor facts in this bullet are unchanged and are exactly why the record carries nothing else.

**Consequence for the plan.** WU-4.6 (`gcp.passwordpolicy`) stays unbuilt; WU-5.15 (`azure.entra` pwpolicy) shipped — see Status above. `coverage_test` is unaffected by the widened `accepts:` because it requires an emitter for *some* accepted type, not all of them — `password_policy.v2` has two. Customers with **neither AWS nor Okta** simply do not satisfy the six password policies via automated evidence. (Okta does now emit the type — see the note at the top of this section — so "AWS-only emitter", as this paragraph originally read, no longer holds.)

**How a customer with no `password_policy` emitter actually covers this today — corrected.** An earlier version of this paragraph said those customers "can cover those controls via the manual evidence flow — a screenshot/export of the Workspace/Entra password settings". **That was an overclaim, and it is not expressible.** A manual catalog entry is 1:1 with a manual *policy* and is structurally unconditional, so no password entry exists to point a `catalog_entry:` override at, and `manual.pdf` hard-fails on a `catalog_entry` the framework does not declare. Adding one would also oblige every AWS customer — who already has automated coverage — to upload a PDF they do not need, and a manual entry with an empty folder **fails**, it does not skip.

What works today is a per-policy exception, which is what the worked configs actually show (`docs/architecture/examples/gcp-project.sigcomply.yaml`, `azure-subscription.sigcomply.yaml`):

```yaml
policies:
  soc2.cc6.1.password_min_length_14:
    exceptions:
      - state: na
        reason: >-
          Google Workspace does not expose password-policy settings via any
          API. Settings are screenshotted quarterly and held with the
          access-review evidence.
    # (Same for the other password_* CC6.1 / ISO 8.5 policies.)
```

Be clear about what that buys and what it does not. `na` is subtracted from the score denominator exactly as `skip` is (`internal/aggregator/aggregator.go`), so it does **not** repair the arithmetic — an unanswerable control still leaves the denominator either way. What it buys is that the exclusion is explicit, reasoned, attributable and auditor-visible in the config, instead of a silent skip nobody declared. The real fix for the arithmetic is the `authentication_policy` type below.

**The `authentication_policy` option was considered and not taken.** An earlier note proposed a separate evidence type modelling what Entra/Workspace expose, rather than forcing the AWS shape. v2 takes the other branch of the same rule (Invariant #4: design top-down from the concept, every field satisfiable by all sources without sentinels) — the concept "the rule an authentication system applies to passwords" is one concept, and a second type would have split it, forcing every consuming policy to accept both and every clause to be written twice. What the proposal was right about is preserved: nothing was forced into the AWS shape, and `password_policy.v1` was not mutated. A separate type remains the right answer for the genuinely different concept next door — sign-on / auth-strength policy, which is not a password rule at all.

---

## See also

- [04-source-plugins.md](04-source-plugins.md) — the factory contract and policy ↔ evidence-type ↔ source registry.
- [04a-evidence-type-registry.md](04a-evidence-type-registry.md) — the cloud-neutral evidence-type schemas every plugin emits into.
- `internal/sources/builtin/builtin.go` — the blank-import registration list.
- `docs/configuration.md` — per-provider config keys and auth env vars.
- `core_source_integrations_plan.md` (repositories root) — phased rollout, work units, and progress tracking.
