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

## Open design decisions (tracked here)

Two cross-vendor decisions are settled in their own work units and recorded in this document:

- **Cross-vendor identity contract** (`is_admin` / `is_active`, and which `directory_user` version non-AWS sources emit) — to be documented by WU-0.2. Interim rule: every `directory_user` emitter **must** populate `is_admin` and `is_active`; the `mfa_enforced_admins` and inactive-account policies depend on them.
- **`password_policy` schema fit for GCP / Azure** — to be decided by WU-0.3 (map / new `authentication_policy` type / defer). Default is **defer** rather than emit a misleading record, because Entra ID and Cloud Identity do not expose a classic IAM-style password policy.

---

## See also

- [04-source-plugins.md](04-source-plugins.md) — the factory contract and policy ↔ evidence-type ↔ source registry.
- [04a-evidence-type-registry.md](04a-evidence-type-registry.md) — the cloud-neutral evidence-type schemas every plugin emits into.
- `internal/sources/builtin/builtin.go` — the blank-import registration list.
- `docs/configuration.md` — per-provider config keys and auth env vars.
- `core_source_integrations_plan.md` (repositories root) — phased rollout, work units, and progress tracking.
