# 12 — Multicloud Sources

This document is the design reference for SigComply's source plugins across cloud and identity providers. It defines the **authentication model**, **package layout**, **source-ID naming**, and **dependency policy** that every new provider plugin follows, so that adding GitLab, expanding GCP, or building Azure is a mechanical exercise rather than a fresh design each time.

It complements [04-source-plugins.md](04-source-plugins.md) (the factory contract and the policy ↔ evidence-type ↔ source registry) and [04a-evidence-type-registry.md](04a-evidence-type-registry.md) (the cloud-neutral evidence-type schemas). The *phased rollout, work-unit breakdown, and progress tracking* live outside the CLI repo in the **Core Source-API Integrations Plan** (`core_source_integrations_plan.md`, in the `sigcomply-repositories/` root), which is the source of truth for what ships when.

---

## Why multicloud is mostly mechanical

A policy accepts an **evidence type**, not a vendor. The evidence-type schemas are already **cloud-neutral** — `object_storage_bucket`, `managed_database_instance`, `directory_user`, `firewall_rule`, etc. — and exist for all 24 types the policy set consumes. So a new provider almost always **reuses an existing schema** and emits records into it; new schemas are the exception, not the rule.

This yields the substitutability property: one "object storage encrypted at rest" policy spans AWS S3, GCS, and Azure Blob because all three emit the single `object_storage_bucket` type. Adding a new source for an existing type needs **zero policy changes**.

---

## Provider coverage (current and planned)

| Provider | Hosting | Auth | Status |
|----------|---------|------|--------|
| **AWS** | management plane (per region/account) | SDK default chain | 23 plugins (mature) |
| **GCP** | management plane (per project) | Application Default Credentials | 4 plugins → expanding (Phases 3–4) |
| **GitHub** | SaaS | token | 1 plugin → `git_repository`, `directory_user`, `source_control_org_policy`, `vulnerability_finding` |
| **Okta** | SaaS | token | 1 plugin (`directory_user`) |
| **GitLab** | SaaS / self-managed | token | planned (Phase 2) |
| **Azure** | management plane + Entra/Graph | DefaultAzureCredential / OIDC | planned (Phase 5) |
| **Manual** | customer bucket | n/a | 1 plugin (`manual.pdf`, project singleton) |

See the plan's gap matrix for the per-evidence-type breakdown.

---

## Source-ID naming

Source IDs follow **`<provider>`** for single-service providers and **`<provider>.<service>`** for multi-service providers:

- Single-service (one plugin per provider): `github`, `okta`, `gitlab`.
- Multi-service (one plugin per service): `aws.s3`, `aws.iam`, `gcp.storage`, `gcp.sql`, `azure.storage`, `azure.entra`.

The `<service>` segment names the underlying cloud service, not the evidence type — one plugin may emit several types (e.g. `azure.keyvault` → `kms_key` + `secret`; `gcp.scc` → `threat_detection_service` + `security_service` + `vulnerability_finding`). Keep a plugin to one underlying service.

---

## Package layout

Plugins live under `internal/sources/`:

- **Multi-service providers nest per service:** `internal/sources/<provider>/<service>/` (e.g. `aws/s3/`, `gcp/storage/`, `azure/storage/`). Each service is its own Go package and its own source ID.
- **Single-plugin providers are flat:** `internal/sources/<provider>/` (e.g. `github/`, `okta/`, `gitlab/`).

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

No central registry edit is needed: `internal/sources/builtin/coverage_test.go` auto-discovers factories and fails the build if any accepted evidence type lacks an emitter. (A plugin that cannot build without credentials uses the hardcoded-`Emits()` fallback pattern in `coverage_test.go`.)

---

## Authentication model per provider

Auth is **read-only** and, in CI, prefers keyless federation (OIDC / workload identity) over long-lived secrets.

- **GCP** — Application Default Credentials (ADC): the existing pattern (`storage.NewClient(ctx)`, service clients via `google.golang.org/api/...`). In CI, Workload Identity Federation. Config key: `project_id`.
- **Azure** — `azidentity.NewDefaultAzureCredential(nil)`: OIDC / workload-identity federation in CI (no secrets), falling back to `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`. Management plane via `armXXX` clients scoped to a `subscription_id`; **Entra / Microsoft Graph** via `msgraph-sdk-go` with the *same* credential. Config keys: `subscription_id`, `tenant_id` (Graph). Required Graph scopes and the Entra ID P1/P2 caveat for per-user MFA reporting are documented per the relevant WU.
- **GitLab** — token from config `token` or `GITLAB_TOKEN`; client `gitlab.com/gitlab-org/api/client-go`; scope `read_api`. Config key: `group` (or `instance`); `base_url` (default `https://gitlab.com`) for self-managed.
- **GitHub** / **Okta** — unchanged: token from config or env (`GITHUB_TOKEN`/`GH_TOKEN`, `OKTA_API_TOKEN`), direct HTTP (no vendor SDK).

Per-provider config keys and required scopes are catalogued in `docs/configuration.md` as each plugin lands.

---

## Dependency policy

**Dependencies are added at first use, not pre-added.** Go's `go mod tidy` strips modules with no importing code, so a dep added "ahead of need" would not survive a tidy. Each provider's SDK therefore enters `go.mod` in the first work unit that imports it:

- `gitlab.com/gitlab-org/api/client-go` — added by the first GitLab WU (Phase 2). (Note: the client moved from the deprecated `github.com/xanzy/go-gitlab`.)
- `github.com/microsoftgraph/msgraph-sdk-go` — added by the first Azure Entra WU (Phase 5).
- `github.com/Azure/azure-sdk-for-go/sdk/azidentity` — **already present** (v1.x), pulled in by the manual-evidence Azure Blob backend; reused by Azure management-plane plugins. The `armXXX` resource-manager modules are added per Azure service WU.
- GCP (`cloud.google.com/go/...`, `google.golang.org/api/...`) and AWS SDK modules are already present and extended per service.

---

## Cross-vendor identity contract (`directory_user`) — settled (WU-0.2)

Every identity source — AWS IAM, GitHub, Okta, GitLab, GCP, Azure Entra — emits into the cloud-neutral `directory_user` type. Two questions had to be settled so that adding a non-AWS identity source is mechanical and so the cross-vendor admin-MFA policies actually fire. Both are now decided.

**Decision 1 — non-AWS identity sources emit `directory_user` (v1), not v2.**
`directory_user.v2` adds three **required** AWS-centric fields — `is_root`, `has_console_access`, `has_programmatic_access` (`internal/evidence_types/schemas/directory_user.v2.json`). Those have no honest analog on GitHub, Okta, GitLab, Cloud Identity, or Entra, so non-AWS sources **must not** fabricate them. v1 requires only `id` + `mfa_enabled` and exposes the cross-vendor fields (`is_admin`, `is_active`, `email`, `mfa_enabled`, `last_login_at`, `display_name`) as optional. AWS keeps emitting v2; everyone else emits v1. GitHub already does this (`internal/sources/github/github.go` emits `"directory_user"` / v1).

**Decision 2 — `is_admin` and `is_active` are mandatory in practice, even though the schema marks them optional.**
The admin-MFA policies are phrased as `none(is_admin == true AND mfa_enabled == false)`:

- `soc2.cc6.1.mfa_enforced_admins` — `internal/frameworks/soc2/policies_cc6.go:47`
- `iso27001.8.2.privileged_mfa_enforced` — `internal/frameworks/iso27001/policies_8_technological.go:34`

The evaluator treats a **referenced-but-absent field as a contract gap, not a pass**: `getField` miss → `status=error` (exit 3), see `internal/evaluator/pass_when.go:245` and `TestPassWhen_AbsentField_Errors`. So a source that omits `is_admin` does **not** silently no-op these policies — it makes them **error**, which is the intended way to surface a coverage gap (the policy comments say so explicitly). Therefore every `directory_user` emitter **must populate** `is_admin` (vendor heuristic: org owner / SuperAdmin / Owner-or-Maintainer / privileged directory-role) and **must populate** `is_active` (from the vendor's account-status field; `true` when only active identities are listable). If a source genuinely cannot compute `is_admin` yet, that is a tracked coverage gap for its WU (e.g. Okta, WU-1.2) — not a license to omit the field.

> **Schema-text caveat.** `directory_user.v1.json`'s description for `is_active` reads "Absent means assume active." That default is **aspirational** — it would only apply to a future active-only rule that opts into `is_set`/filter semantics. The generic evaluator does **not** apply it; a bare reference to an absent field errors. The operative contract is **populate, don't rely on the default.**

Optional vendor-specific fields (`email`, `is_external`, `is_service_account`, `mfa_factor_count`, `last_login_at`) may be omitted when the vendor doesn't surface them; any policy that reads them must guard with `is_set`/filter.

## `password_policy` schema fit for GCP / Azure — settled (WU-0.3): DEFER both

The `password_policy.v1` schema is **AWS-IAM-shaped**: eight required fields — `min_length`, `max_age_days`, `reuse_prevention_count`, and four discrete complexity booleans (`requires_uppercase`/`_lowercase`/`_numbers`/`_symbols`). The AWS plugin (`internal/sources/aws/passwordpolicy/`) fills these from `IAM GetAccountPasswordPolicy`. Six policies consume it — `soc2.cc6.1.password_{min_length_14,expiry_90d,reuse_prevention,complexity}` and `iso27001.8.5.password_{minimum_length,complexity}` — referencing `min_length`, `max_age_days`, `reuse_prevention_count`, and all four complexity booleans. Because every consumed field is schema-`required`, a partial/half-populated record is not viable: the evaluator errors (exit 3) on any referenced field a record omits (`internal/evaluator/pass_when.go:245`), and emitting zeros/false for unknowable fields would be **misleading evidence**, not missing evidence.

**Decision: neither GCP nor Azure emits `password_policy`. Defer.** Neither provider exposes the AWS-shaped policy via a readable API:

- **GCP (Cloud Identity / Workspace).** Cloud IAM has no password policy at all (it governs authorization, not human credentials — confirmed). A Workspace password policy *exists* (min/max length, expiry, "enforce strong password") but is **Admin-Console-only**: the Admin SDK Directory API exposes **no** policy object — `Customer`/`Domain` carry no `passwordPolicy`, no length, no expiry, no reuse. "Strong password" is a single opaque Google rating, not four complexity booleans, and there is **no** reuse/history concept. A Go collector cannot honestly populate *any* field automatically.
- **Azure (Entra ID).** For cloud-only accounts, length (8) and complexity (fixed "3 of 4 character classes") are **Microsoft constants**, not tenant-readable settings — hard-coding them would fabricate the four-boolean shape (and "3 of 4" is structurally not four independent booleans). History is depth-1 on change / unenforced on reset, with no numeric count. The **only** genuinely API-readable knob is expiration: `domain.passwordValidityPeriodInDays` (+ `passwordNotificationWindowInDays`) via Graph, plus per-user `user.passwordPolicies`. One real field out of eight required ⇒ cannot faithfully populate the schema.

**Consequence for the plan.** WU-4.6 (`gcp.passwordpolicy`) and WU-5.15 (`azure.entra` pwpolicy) are **dropped** (stay `[!]`/skipped in the dashboard). No new source ID is created for them; `coverage_test` is unaffected because no policy's `accepts:` is broadened — `password_policy` remains an AWS-only emitter and GCP-/Azure-only customers simply do not satisfy the six password policies via automated evidence (they can cover those controls via the **manual** evidence flow — a screenshot/export of the Workspace/Entra password settings — exactly the gap manual evidence exists to fill).

**Future option (not now): a separate `authentication_policy` type.** If automated coverage of these controls becomes a priority, the clean path is a *new, append-only* evidence type modeling what Entra/Workspace actually expose (password expiration ± a platform-enforced-complexity attestation, MFA/auth-strength) — **not** forcing the AWS shape and **not** mutating `password_policy.v1` (Invariant #4: schemas are designed top-down from the concept, every field satisfiable by all sources without sentinels). That would be its own future WU with its own policies; it is explicitly out of scope for this plan.

---

## See also

- [04-source-plugins.md](04-source-plugins.md) — the factory contract and policy ↔ evidence-type ↔ source registry.
- [04a-evidence-type-registry.md](04a-evidence-type-registry.md) — the cloud-neutral evidence-type schemas every plugin emits into.
- `internal/sources/builtin/builtin.go` — the blank-import registration list.
- `docs/configuration.md` — per-provider config keys and auth env vars.
- `core_source_integrations_plan.md` (repositories root) — phased rollout, work units, and progress tracking.
