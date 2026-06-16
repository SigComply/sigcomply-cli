# 04 — Source Plugins

A source plugin knows how to fetch data from one external system —
AWS IAM, Okta, BambooHR, GitHub, a customer's internal LDAP, a PDF
deposited in a bucket — and emit evidence records of declared types.
Plugins are the only layer that talks to external systems.

This document specifies the plugin contract, evidence type declarations,
the built-in plugin set, the canonical `manual.pdf` plugin, and how to
author a custom plugin.

---

## The plugin contract

A plugin is a Go type implementing `core.SourcePlugin`
(`internal/core/source.go`):

```go
type SourcePlugin interface {
    // ID returns the plugin's stable identifier, e.g. "aws.iam".
    ID() string

    // Emits returns the evidence type IDs this plugin can produce.
    Emits() []string

    // Init initializes the plugin with already-typed configuration.
    // Called once per plugin instance per run. After Init, Collect may
    // be called many times.
    Init(...) error

    // Collect fetches records for the given slot. Collect may be
    // invoked multiple times within a run (once per policy binding,
    // per the no-shared-collection axiom).
    Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error)
}

type SlotRequest struct {
    // PolicyID is the policy this Collect call serves; diagnostic only.
    // Never branch on it — doing so breaks substitutability.
    PolicyID string

    // AcceptedTypes is the INTERSECTION of the slot's declared accepts
    // and this plugin's Emits() — i.e. slot.Accepts ∩ plugin.Emits(),
    // not the raw slot.Accepts. The plugin should return records whose
    // Type is in this set; the collector validates each payload against
    // the registered schema for that type before signing.
    AcceptedTypes []string

    // SlotName is the slot's name on the policy.
    SlotName string

    // Params are slot-specific parameters from the binding (rare).
    Params map[string]any
}
```

The plugin sees the *narrowed* type set, never the consuming policy's
full `accepts:` — one more place the policy and the plugin do not name
each other.

**Lifecycle within a run:**

1. The planner assembles per-(plugin, config) instances and registers
   them in the run plan.
2. The collector calls `Init` once per instance.
3. The collector calls `Collect` once per (policy, slot) binding.
4. The plugin instance is discarded at run end.

**Per-policy fetch, not per-run.** Per the KISS-no-DRY axiom, if ten
policies bind the same `aws.iam` instance, `Collect` is invoked ten
times. The plugin should not cache between invocations: each call
must reflect the live state. (If the underlying system supports it,
the plugin *may* maintain in-memory caches across calls within a
single run for efficiency — but it must remain correct without them.)

---

## The factory contract

Every source plugin package self-registers a **factory** with the
process-global `SourceRegistry` via an `init()` function. There is no
hardcoded switch on source ID anywhere in the orchestrator; the check
command iterates `cfg.Sources` and dispatches generically through the
registry.

```go
// internal/sources/aws/iam/factory.go
package iam

import (
    "context"

    "github.com/sigcomply/sigcomply-cli/internal/core"
    "github.com/sigcomply/sigcomply-cli/internal/sources"
)

const SourceID = "aws.iam"

// factory builds a configured aws.iam plugin instance from the
// already-typed Env (which carries the parsed config for this source).
func factory(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
    return New(ctx, env)
}

func init() {
    sources.RegisterFactory(SourceID, factory)
}
```

The factory signature is fixed (`internal/sources/factory.go`):

```go
type Factory func(ctx context.Context, env Env) (core.SourcePlugin, error)

// In the sources package:
func RegisterFactory(id string, f Factory)
```

`env` is an `Env` **struct**, not a `map[string]any` — the source
config is parsed into typed fields before the factory runs. If config
is missing required fields or has invalid values, the factory returns
an error and the orchestrator exits with code 3.

**Why factories rather than constructors.** A factory produces a
configured plugin instance from the typed `Env`. This is the only way
to keep the orchestrator generic: it never imports `iam.New`, never
knows that `aws.iam` needs a region — it dispatches through the
registered factory by source ID.

**Bootstrap-time registration.** Each in-tree source package
self-registers its factory in `init()` via `sources.RegisterFactory`.
The registry is bootstrapped by blank-importing
`internal/sources/builtin`, which in turn blank-imports every in-tree
source package so their `init()` functions run:

```go
import _ "github.com/sigcomply/sigcomply-cli/internal/sources/builtin"
```

Adding a new in-tree source is: write the package, add one blank-import
line in `builtin`. There is no central case statement to keep in sync.
Adding a project-local plugin is the same pattern, applied through
`sigcomply build`.

**No runtime plugin loading.** Go's `plugin` package is fragile across
versions and Linux-only; we don't use it. Every source — in-tree or
third-party — is compiled in. `sigcomply build` is the build wrapper
that includes project-local plugins; see
[`07-extensibility.md`](07-extensibility.md).

---

## How a plugin declares itself

**In-tree plugins declare everything in code — there is no in-tree
`plugin.yaml`.** A plugin's identity is its `ID()`, the evidence types
it produces are its `Emits()`, and its configuration is the typed `Env`
its factory consumes. There is no manifest file to keep in sync with
the Go and no manifest-validation step at startup.

`plugin.yaml` exists **only for project-local plugins** under
`.sigcomply/plugins/<id>/`, where it is parsed by `LoadPluginManifest`
so `sigcomply build` knows what to wire in (see §How third parties
contribute a source and [`07-extensibility.md`](07-extensibility.md)).
In-tree plugins never use it.

---

## Evidence types — registered separately, validated by the collector

A plugin declares the set of evidence types it emits via `Emits()`. A
policy declares the types it accepts on each slot (`accepts: [...]`).
The evidence-type registry mediates: every type ID named on either side
must be a registered schema, and the collector validates every record's
payload against the registered JSON Schema before signing.

The full design — file format (JSON Schema documents), embedding via
`go:embed`, schema versioning, the cross-source identity field, the
rubric for "new type vs. extend `accepts:`," and the *planned*
project-local extension path under `.sigcomply/evidence_types/` — lives
in [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md).
Read that document before authoring a plugin or a policy that needs a
new evidence shape.

The short version a plugin author needs:

- Emit records with `Type` set to a registered type ID.
- Set the record's identity field when the type has a meaningful
  cross-source identity (e.g. email for `directory_user`); see
  [`03-policy-spec.md`](03-policy-spec.md) §Cross-source dedup.
- Trust the collector to validate payloads against the full draft-07
  schema; do not invent local schema enforcement. The first
  non-conforming record errors the binding (exit 3) — a malformed
  payload is a bug to fix in the plugin or the schema.

---

## Built-in plugin set (v1)

The CLI ships with a set of plugins compiled in. Each lives under
`internal/sources/<vendor>/<id>/` and self-registers a factory via
`init()` (see §The factory contract). The in-tree set is larger than
the table below and changes over time — **do not treat this as
exhaustive.** The two authoritative sources are each plugin's `Emits()`
method and the registered schemas under
`internal/evidence_types/schemas/`.

A representative slice of the built-in set, with the real emitted type
IDs:

| Plugin ID | Emits (real type IDs) | Notes |
|---|---|---|
| `aws.iam` | `directory_user.v2` | One AWS account per instance. Multiple instances via separate config blocks. |
| `aws.iam_access_key` | `iam_access_key` | |
| `aws.s3` | `object_storage_bucket` | Same neutral type as `gcp.storage` and `azure.storage`. |
| `aws.cloudtrail` | `audit_log_trail` | |
| `aws.kms` | `kms_key` | |
| `gcp.storage` | `object_storage_bucket` | Same neutral type as `aws.s3` and `azure.storage`. |
| `gcp.directory` | `directory_user` | Google Workspace / Cloud Identity users via the Admin SDK Directory API. Account/customer-scoped (optional `customer_id`, default `my_customer`). Same neutral type as `aws.iam`/`okta`/`github`/`gitlab`. |
| `gcp.firewall` | `firewall_rule` | VPC firewall rules (Compute `firewalls.list`), flattened to one record per protocol/port-range. Same neutral type as `aws.security_group`. |
| `gcp.kms` | `kms_key` | Cloud KMS crypto keys (CloudKMS `cryptoKeys.list`), walked across all project locations; `rotation_enabled` ← rotationPeriod set. Same neutral type as `aws.kms`. |
| `gcp.logging` | `log_group` | Cloud Logging log buckets (Logging `buckets.list`, all locations), one record per bucket; `retention_set` ← `retentionDays > 0`, `retention_days` ← `retentionDays` (every GCP bucket has finite retention — no "never expire"); `kms_encrypted` ← CMEK on `cmekSettings`. Same neutral type as `aws.cloudwatch`. |
| `gcp.artifactregistry` | `container_registry` | Artifact Registry repositories (`repositories.list`, walked across all project locations), one record per repo; `scan_on_push_enabled` ← `vulnerabilityScanningConfig.enablementState == SCANNING_ACTIVE`; `image_immutability_enabled` ← `dockerConfig.immutableTags`; `is_public` ← repo IAM policy grants `allUsers`/`allAuthenticatedUsers` (per-repo `getIamPolicy`); `encryption_enabled` ← always `true` (AR always encrypts at rest; CMEK distinction in the `is_customer_managed` extra). Same neutral type as `aws.ecr`. |
| `gcp.firestore` | `nosql_table` | Cloud Firestore databases (Firestore Admin `Projects.Databases.List` over `projects/{p}/databases`, one non-paginated call; errors on any `unreachable` location rather than returning a partial list), one record per database; `encryption_enabled` ← always `true` (Firestore always encrypts at rest — Google-managed default or CMEK; CMEK distinction in the `is_customer_managed` extra); `point_in_time_recovery_enabled` ← `pointInTimeRecoveryEnablement == POINT_IN_TIME_RECOVERY_ENABLED`; `deletion_protection` ← `deleteProtectionState == DELETE_PROTECTION_ENABLED`. Same neutral type as `aws.dynamodb`. |
| `gcp.gke` | `kubernetes_cluster` | GKE clusters (`Projects.Locations.Clusters.List` with the `locations/-` all-locations wildcard, one non-paginated call), one record per cluster; `secrets_encryption_enabled` ← `databaseEncryption.state == ENCRYPTED` (Application-layer Secrets Encryption with a customer KMS key — not always-on etcd-at-rest); `logging_enabled` ← `loggingConfig.componentConfig.enableComponents` non-empty or legacy `loggingService != none`; `is_private_endpoint` ← `privateClusterConfig.enablePrivateEndpoint`; `node_auto_upgrade_enabled` ← all node pools auto-upgrade. Same neutral type as `aws.eks`. |
| `gcp.backup` | `backup_plan` | Backup and DR Service backup plans (`Projects.Locations.BackupPlans.List` with the `locations/-` all-locations wildcard, paginated; errors on any `unreachable` location), one record per plan; `is_active` ← `state == ACTIVE` (real plan-state enum, unlike `aws.backup`); `has_retention_rule` ← any backup rule has `backupRetentionDays > 0`; `retention_days` ← max `backupRetentionDays` across rules (omitted when none). The direct AWS Backup analog (broader than GKE-only Backup-for-GKE). Same neutral type as `aws.backup`. |
| `gcp.certs` | `tls_certificate` | Certificate Manager certificates (`Projects.Locations.Certificates.List` with the `locations/-` all-locations wildcard, paginated; errors on any `unreachable` location), one record per certificate; `not_after` ← `expireTime` (RFC3339 UTC); `days_until_expiry` derived from it (negative once expired); `is_managed` ← `managed` set (vs. self-managed PEM); `auto_renew` ← `true` for managed certs, omitted for self-managed (matching `aws.acm`); `domain` ← first `sanDnsnames`; `status` ← honest enum (expired→`EXPIRED`, else `managed.state` ACTIVE→`ISSUED`/PROVISIONING→`PENDING_VALIDATION`/FAILED→`FAILED`/else `INACTIVE`, self-managed→`ISSUED`). Same neutral type as `aws.acm`. |
| `gcp.asset` | `config_change_tracking` | One record per project modeling Cloud Asset Inventory **feeds** (the opt-in change-tracking pipeline, not the always-on inventory). `is_recording` ← ≥1 feed exists; `all_resource_types` ← ≥1 feed is unrestricted by asset type (empty `assetTypes` or `.*`/`*` wildcard). Reads `Feeds.List` (single call). Same neutral type as `aws.config`. |
| `gcp.audit` | `audit_log_trail` | One record per project modeling the Cloud Audit Logs posture (not per-sink). `is_enabled`/`is_multi_region`/`log_file_validation_enabled` ← `true` (GCP platform constants: Admin Activity logging is always-on, global, and integrity-guaranteed via the locked `_Required` bucket); `kms_encrypted` ← CMEK on project logging `cmekSettings`. Reads CRM `GetIamPolicy` (audit configs / access) + Logging `GetCmekSettings`. Same neutral type as `aws.cloudtrail`. |
| `gcp.network` | `network` | VPC Networks (Compute `networks.list`), one record per network; `flow_logs_enabled` aggregated from subnetworks (all-must-be-on). Same neutral type as `aws.vpc`. |
| `gcp.secretmanager` | `secret` | Secret Manager secrets (`secrets.list`); `rotation_enabled` ← rotation policy attached; `kms_encrypted` ← CMEK on replication; `never_rotated`/`last_rotated_days` ← per-secret `versions.list` (no last-rotation timestamp on the resource). Same neutral type as `aws.secretsmanager`. |
| `gcp.scc` | `threat_detection_service`, `security_service`, `vulnerability_finding` | **Org-scoped** (`organization_id`, not `project_id`; needs org-level `securitycenter.findingsViewer`+`settingsViewer`). Security Command Center: ETD enablement → `threat_detection_service` (`aws.guardduty` analog); SHA enablement → `security_service` `service_type: "siem"` (`aws.security_services` analog); active `VULNERABILITY`/`MISCONFIGURATION` findings → `vulnerability_finding` (`aws.inspector` analog), severity/status mapped to the schema enums. Reads `sources/-/findings` (v1) + v1beta2 settings (`serviceEnablementState`). |
| `azure.entra` | `directory_user` | Microsoft Entra ID (Azure AD) users via Microsoft Graph (raw REST, not `msgraph-sdk-go`). Graph-plane (optional `tenant_id`, no `subscription_id`). `mfa_enabled` ← `userRegistrationDetails.isMfaRegistered`; `is_admin` ← `userRegistrationDetails.isAdmin` (Microsoft's computed flag — no `directoryRoles` traversal); `is_active` ← `users.accountEnabled`; `email` ← `users.mail` only; `last_login_at` ← `users.signInActivity.lastSignInDateTime` (omitted if absent). Needs `User.Read.All` + `AuditLog.Read.All` + Entra ID P1/P2; errors (not false MFA) when the report is inaccessible. Same neutral type as `aws.iam`/`okta`/`github`/`gitlab`/`gcp.directory`. |
| `azure.storage` | `object_storage_bucket` | Azure Storage accounts (armstorage `AccountsClient.NewListPager`). **ARM-plane** (`subscription_id` required). `encryption_at_rest_enabled` ← always `true` (Azure SSE is always-on; CMEK distinction in `kms_managed` ← `Encryption.keySource == Microsoft.Keyvault`); `public_access_blocked` ← `allowBlobPublicAccess == false` (nil ⇒ not blocked); `versioning_enabled` ← blob versioning OR blob soft-delete (per-account `blobServices/default` GET — an N+1, RG parsed from the account id). Errors (not false versioning) on a blob-service read failure. Same neutral type as `aws.s3` and `gcp.storage`. |
| `github` | `git_repository`, `directory_user` | Single org per instance. |
| `gitlab` | `git_repository`, `directory_user` | Single group per instance (`include_subgroups`); self-managed via `base_url`. Same neutral types as `github`. |
| `okta` | `directory_user`, `okta_app` | |
| `manual.pdf` | `signed_document` | **Project-level singleton.** Exactly one instance per project. See §The manual.pdf plugin. |

Note the cross-vendor pattern: `aws.s3`, `gcp.storage`, and `azure.storage`
all emit the single neutral `object_storage_bucket` type (the "reuse the
existing type" path, one type across three clouds), and `aws.iam`, `okta`,
`github`, `gitlab`, `gcp.directory`, and `azure.entra` all emit
`directory_user` (one type, six sources across IdP, code host, and three
clouds). The same pattern now spans
git hosts: `github` and `gitlab` both emit the neutral `git_repository`
type, so every branch-protection policy works against either without
change. Many more AWS and GCP subpackages exist; consult their `Emits()`
for the current list.

Additional vendors (Bitbucket, Auth0, BambooHR, Workday, …) and the
remaining ARM-plane Azure resource collectors ship as they land.

---

## The `manual.pdf` plugin

The `manual.pdf` plugin is a **project-level singleton.** Unlike API
plugins (which can be instantiated multiple times with different configs
— see §Multiple plugin instances), there is exactly one `manual.pdf`
instance per project, pointing at one bucket. The catalog declares which
evidence the customer provides as PDFs; the singleton resolves all of
them to deterministic paths under that single bucket.

This is a deliberate v1 simplification. Multiple manual buckets per
project (e.g. one per framework, or one per team) are not supported.
A project that wants stricter segregation of manual evidence runs the
CLI from separate projects, each with its own `.sigcomply.yaml`.

### Configuration

`manual.pdf` emits a single type, `signed_document`, and is configured
at the project level under `sources.manual.pdf` in `.sigcomply.yaml`
(one bucket, one prefix, one credential set). There is no in-tree
`plugin.yaml` — like every in-tree source it declares itself in code.
The config shape (`backend`, `bucket`, `prefix`, `region`, `endpoint`,
`force_path_style`, …) is the flat `VaultConfig`-style block documented
in [`08-project-config.md`](08-project-config.md). In-tree backends are
`local`, `s3`, `gcs`, and `azure_blob`; the `s3` backend also serves
on-prem S3-compatible stores (MinIO, Ceph, Wasabi, …) via `endpoint` +
`force_path_style`.

Backend selection goes through a self-registering reader registry
(`manual.RegisterReader`) — the same pattern source plugins and vault
backends use; the `manual.pdf` source dispatches generically with no
hardcoded switch. There is a small file-layout asymmetry: the `local`
backend is registered inline in `factory.go`, while `s3`/`gcs`/
`azureblob` are subpackages blank-imported via
`internal/sources/manual/builtin`. Registration is identical for all
four; only where the `init()` lives differs. See
[`00-three-plugin-axes.md`](00-three-plugin-axes.md) §Axis A.

### Manual catalog (generated in Go)

The manual catalog is **not** an on-disk YAML file. Each framework
generates its catalog in Go from a single list — `manualSpecs()` in
`policies_manual.go` — which feeds both `ManualCatalog()` (runtime path
resolution) and `ManualCatalogExport()` (the SPA-facing export). There
is no `.sigcomply/manual_catalog/*.yaml` and no embedded
`catalogs/*.yaml`. A catalog entry's logical fields (id, cadence, grace
period, temporal rule, and the SPA-only presentation hints) all come
from the framework's `manualPolicy{...}` builder. Inspect a catalog
with `sigcomply evidence catalog -o json`.

### Path resolution

For each catalog entry and each period, the plugin resolves to a
folder under the project's single configured bucket:

```
{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/
```

Default `prefix` is `manual/`. For AcmeCorp's quarterly access review
in Q1 2026, the plugin lists everything under:

```
s3://acme-evidence/manual/access_review_quarterly/2026-Q1/
```

Any number of files may be placed in that folder. Supported formats
are: **PDF** (pass-through), **JPEG**, **PNG**, **GIF**, **TIFF**,
**WebP**, and **BMP** (images are auto-converted to PDF). All files are
merged into a single PDF before evaluation. Files with unsupported
extensions (e.g. `.docx`, `.xlsx`) are surfaced as
`unsupported_file_type` validation failures so CI operators receive an
actionable error message without the policy silently ignoring files.

**This scheme is canonical.** The CLI computes the folder; customers
cannot remap it per-policy, per-catalog-entry, or per-framework. The
only knobs are the project-level `bucket` and `prefix`. This
determinism is what lets a missing-evidence error give the operator
the exact upload folder, and what lets an auditor recompute the
expected location from the catalog alone.

### Emitted record

```json
{
  "type": "signed_document",
  "id": "access_review_quarterly/2026-Q1",
  "source_id": "manual.pdf",
  "collected_at": "2026-05-23T14:00:01Z",
  "payload": {
    "evidence_id": "access_review_quarterly",
    "period_id":   "2026-Q1",
    "file_present": true,
    "file_hash":    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_size":    194523,
    "uploaded_at":  "2026-03-15T10:00:00Z",
    "in_temporal_window": true,
    "file_valid":   true,
    "validation_failures": [],
    "expected_uri": "s3://acme-evidence/manual/access_review_quarterly/2026-Q1/",
    "source_files": [
      {
        "filename":   "report.pdf",
        "type":       "pdf",
        "sha256":     "sha256:abc123...",
        "uploaded_at": "2026-03-14T09:00:00Z",
        "converted":  false
      },
      {
        "filename":   "screenshot.png",
        "type":       "png",
        "sha256":     "sha256:def456...",
        "uploaded_at": "2026-03-15T10:00:00Z",
        "converted":  true
      }
    ]
  }
}
```

`file_hash` and `file_size` describe the **merged** PDF (all source
files combined). `source_files` provides a per-file audit trail so
auditors can trace individual uploads back from the merged evidence.
`uploaded_at` is the latest upload time across all source files — used
for the temporal window check.

A rule consuming `signed_document` records checks `file_present`,
`in_temporal_window`, and `file_valid`. Future text-extraction
extends the schema additively.

### What the plugin checks — and what it deliberately does not

The `manual.pdf` plugin runs a fixed, narrow set of checks on every
collection. These detect upload mistakes and unsupported files, not
content correctness:

| Check | Failure code | Fails when |
|-------|-------------|-----------|
| **Extension filter** | `unsupported_file_type` | A file in the folder has an extension not in the supported set (pdf, jpg/jpeg, png, gif, tif/tiff, webp, bmp) |
| **Image conversion** | `conversion_failed` | An image file cannot be decoded or wrapped as a PDF page |
| **PDF merge** | `merge_failed` | Multiple PDF parts cannot be combined (e.g., structurally corrupt individual PDFs) |
| **Size floor** | `file_too_small` | Merged PDF is < 100 bytes (catches 0-byte uploads and trivially corrupt files) |
| **PDF magic bytes** | `missing_pdf_header` | Merged PDF does not start with `%PDF-` |
| **Page-object presence** | `no_pages` | Merged PDF contains no `/Page` token |
| **Prior-period duplication** | `copy_paste_of_prior_period` | The set of source files (identified by filename + SHA-256) is byte-identical to the prior period's folder |

Failures land in `validation_failures` (a list of strings) and flip
`file_valid` to `false`. The evaluator's universal PDF-presence check
(`internal/evaluator/manual_check.go`, not a Rego rule) requires
`file_valid == true` to pass; an auditor reading the envelope sees the
specific failure reasons in the manifest.

The size floor, magic bytes, and page-object checks run against the
**merged** PDF. Unsupported-type and conversion failures are per
individual file; the remaining supported files are still merged and
evaluated. If no supported files exist at all, the policy fails with
`file_valid = false` and the unsupported-type failures listed.

**Deliberately not checked at v1:**
- PDF contents (no text extraction, no `signed_by` parsing, no expiry-date detection inside the document)
- Whether the document is the *right* document for the policy (a wrong-but-valid PDF passes)
- Whether the population covered by the document matches the in-scope population (e.g. access review of 40 users when production has 120 — undetectable here)
- Whether signatures inside the PDF are present or valid
- Any form of fraud detection — a determined customer can produce a fabricated PDF that satisfies all checks; that is and remains the auditor's job

The reasoning is in [CLAUDE.md §Manual evidence design contract](../../CLAUDE.md) — the CLI is a custody-of-evidence layer, not a content reviewer. The auditor reads the PDF; the CLI gives the auditor a tamper-evident timeline of what was uploaded when.

### Missing evidence — error format

When the resolved folder contains no supported files (or the latest
upload falls outside the temporal window), the universal PDF-presence
check fails the policy with a violation whose reason names — crucially
— the **exact expected upload path verbatim**. The canonical message
emitted by `internal/evaluator/manual_check.go` is:

```
manual evidence not found; expected files in: <expected-uri>
```

where `<expected-uri>` is the resolved folder, e.g.
`s3://acme-evidence/manual/access_review_quarterly/2026-Q1/`. Because
the path is canonical (see §Path resolution), the operator can upload
the file(s) without consulting any other documentation — the message
carries the destination folder.

The same reason text is preserved in the policy's `result.json` under
the failing check, so an auditor reading the run folder offline, and
any `text`/`json` consumer, sees the exact expected location. (The CLI
has no SARIF output; see [CLAUDE.md](../../CLAUDE.md) — `report`
renders `text`/`json`/`csv` only.)

### PDF mirroring

The collector mirrors the merged PDF into the run folder as an
attachment:

```
soc2/2026-Q1/run_.../policies/<policy_id>/attachments/access_review_quarterly/merged.pdf
```

The attachment is sibling to the envelope. An auditor opening the run
folder sees both the signed manifest envelope (verifiable offline) and
the merged PDF (its SHA-256 matches `file_hash` in the manifest). The
`source_files` array in the manifest lists each original file with its
own SHA-256, providing a traceable link from the merged evidence back to
individual uploads.

---

## Multiple plugin instances (API plugins only)

API plugins may be instantiated multiple times with different configs.
Each instance gets a distinct instance ID derived from the config:

```yaml
sources:
  aws.iam:
    region: us-east-1            # default instance: aws.iam
  "aws.iam[backup]":
    region: us-west-2            # second instance: aws.iam[backup]
```

Bindings reference instances by ID:

```yaml
policies:
  soc2.cc6.1.mfa_enforced:
    bindings:
      user_directory: [aws.iam, "aws.iam[backup]"]
```

This is how a customer with multiple AWS accounts (or multiple GitHub
orgs) configures the CLI without multi-scope being a first-class
v1 concept — each account is a separate plugin instance.

**Exception: `manual.pdf` is a singleton.** The bracket-suffix
instancing pattern shown above applies to API plugins (`aws.iam`,
`gcp.iam`, `github`, `okta`, …). It does **not** apply to `manual.pdf`,
which is fixed to exactly one instance per project. Attempting to
declare `"manual.pdf[secondary]"` in `sources:` is rejected at config
validation with exit 3. The rationale is in §The manual.pdf plugin.

(Recall: v1 is single-scope at the run level, meaning one set of
credentials per run. Multiple API-plugin instances with credentials
from the same default chain do work; multi-scope as a first-class
*per-record* concept is deferred to v2.)

---

## Per-policy slot params

A binding can pass per-slot parameters to the plugin:

```yaml
policies:
  soc2.cc6.1.admin_mfa_enforced:
    bindings:
      user_directory:
        - source: aws.iam
          slot_params:
            filter_admins_only: true
```

`slot_params` are passed in `SlotRequest.Params` to the plugin's
`Collect`. Most plugins ignore them; some support filters that reduce
the records fetched.

This is the only mechanism for plugin-side filtering. Policies
themselves don't pre-filter; rules do post-filtering. Plugin
`slot_params` is for cases where filtering at the API boundary
materially reduces fetch cost.

---

## How third parties contribute a source

Customers needing a plugin for an internal system author one
project-locally under `.sigcomply/plugins/<id>/`. The same factory
pattern that the in-tree plugins use applies verbatim — the only
difference is *when* the package gets compiled in.

The short version:

1. Create the directory `.sigcomply/plugins/acme.internal_iam/`.
2. Author the project-local manifest `plugin.yaml` declaring `id`,
   `emits`, and `config_schema`. (This project-local manifest is real;
   in-tree plugins have none.)
3. Author `plugin.go` implementing `SourcePlugin` and calling
   `sources.RegisterFactory(...)` in `init()` — same signature, same
   registry as the in-tree plugins.
4. If the plugin needs an evidence shape not already shipped, drop a
   JSON Schema under `.sigcomply/evidence_types/<id>.v<n>.json` (see
   [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)).
   **Project-local evidence types are planned (part of `sigcomply
   build`), not yet shipped** — today only embedded in-tree types load.
5. Run `sigcomply build` — this scans `.sigcomply/plugins/`, generates
   a wrapper that blank-imports each project-local package (so their
   `init()` factories register at startup), and compiles a
   project-tailored binary `./bin/sigcomply`.
6. From that point, `./bin/sigcomply check` is the same as the shipped
   `sigcomply check` but with the project-local plugins available.

There is no runtime plugin loading, no shared library, no plugin DSL,
and no API surface beyond the `SourcePlugin` interface and the
`sources.RegisterFactory` registration call. Full walkthrough in
[`07-extensibility.md`](07-extensibility.md).

---

## Plugin invariants (checklist)

A plugin author must guarantee:

- **Deterministic per-call output** (same external state + same config
  → same returned records, ignoring fields explicitly marked as
  timestamps). Records must be **sorted by `ID` lexicographically**
  before returning; this makes envelope bytes stable across calls.
- **Set `IdentityKey`** when the evidence type has a meaningful
  cross-source identity (email, employee_id). See
  [`03-policy-spec.md`](03-policy-spec.md) §Cross-source dedup.
- **No state across `Init` and `Collect` calls beyond
  initialization** (caches OK if they don't change correctness).
- **Validates all emitted records against their evidence type
  schema**, or relies on the collector's downstream validation to
  reject malformed records.
- **Owns 100% of the vendor→canonical normalization.** For
  cross-vendor evidence types, every required field must be populated
  with a meaningful value — never `null`, `""`, `0`, or `false` as a
  placeholder when the vendor doesn't have the concept. If the vendor
  API returns a complex structure (e.g. an array of MFA device objects),
  compute the canonical boolean or count inside `Collect` and emit
  the normalized field. If a required field is genuinely impossible to
  populate for a given vendor, that is a schema design issue: the field
  does not belong in the shared schema. Escalate to fix the schema
  rather than emitting a sentinel. Sentinel values on required fields
  break substitutability silently: policy authors add null guards, which
  become implicit source-dispatch (see
  [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)
  §The null-trap antipattern).
- **No silent failures.** Every error in `Collect` is returned; the
  collector decides whether it's fatal for the consuming policy.
- **No transitive credential capture.** A plugin may not log,
  serialize, or persist credentials. The CLI's logging layer redacts
  known credential shapes (see [`02-layers.md`](02-layers.md)
  §Logging and redaction); plugins must use the shared logger and
  must not bypass redaction.
- **No mutation of external state.** `Collect` is read-only against
  the source system. A plugin that needs to write (e.g. to enable a
  CloudTrail event selector) is out of scope for this layer — the
  CLI is observational, never remediating.
- **Respect source rate limits.** Plugins SHOULD implement
  backoff-and-retry against documented rate limits of their target
  API (AWS IAM ~20 rps regional, Okta varies, GitHub 5000 req/hour
  per token). The KISS-no-DRY axiom means N policies → N invocations
  of `Collect`; the plugin is responsible for not melting the source
  API. Recommended: a per-plugin `rate.Limiter` initialized in
  `Init`, applied inside each `Collect`. Plugins MAY return an
  `error` after exhausting retries, which becomes `error` status on
  the consuming policies — not a silent partial-result.
