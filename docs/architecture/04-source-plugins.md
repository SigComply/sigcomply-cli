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

A plugin is a Go type implementing:

```go
type SourcePlugin interface {
    // ID returns the plugin's stable identifier, e.g. "aws.iam".
    ID() string

    // Emits returns the evidence type IDs this plugin can produce.
    Emits() []string

    // Init initializes the plugin with project-provided configuration.
    // Called once per plugin instance per run. After Init, Collect may
    // be called many times.
    Init(ctx context.Context, cfg map[string]any) error

    // Collect fetches records for the given slot. The slot is one of
    // the slots the plugin's bound policy declares. Collect may be
    // invoked multiple times within a run (once per policy binding,
    // per the no-shared-collection axiom).
    Collect(ctx context.Context, slot SlotRequest) ([]EvidenceRecord, error)
}

type SlotRequest struct {
    // PolicyID is the policy this Collect call serves; useful for
    // diagnostics, never for behavior branching.
    PolicyID string

    // AcceptedTypes is the slot's declared evidence-type set
    // (slot.Accepts). The plugin must return records whose Type is
    // in this set; the collector validates payloads against the
    // schemas registered for those types.
    AcceptedTypes []string

    // SlotName is the slot's name on the policy.
    SlotName string

    // Params are slot-specific parameters from the binding (rare; most
    // bindings have no params).
    Params map[string]any
}
```

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
// project config's `sources.aws.iam:` block.
func factory(ctx context.Context, cfg map[string]any) (core.SourcePlugin, error) {
    region, _ := cfg["region"].(string)
    profile, _ := cfg["profile"].(string)
    roleARN, _ := cfg["role_arn"].(string)
    return New(ctx, Options{
        Region:  region,
        Profile: profile,
        RoleARN: roleARN,
    })
}

func init() {
    sources.RegisterFactory(SourceID, factory)
}
```

The factory signature is fixed:

```go
type Factory func(ctx context.Context, cfg map[string]any) (core.SourcePlugin, error)

// In the sources package:
func RegisterFactory(id string, f Factory)
```

`cfg` is the YAML-unmarshalled map under `sources.<id>:` in
`.sigcomply.yaml`. The factory is responsible for translating the
generic map into the plugin's typed options. If config is missing
required fields or has invalid values, the factory returns an error
and the orchestrator exits with code 3.

**Why factories rather than constructors.** A factory takes the
generic `map[string]any` from project config and produces a configured
plugin instance. This is the only way to keep the orchestrator
generic: the orchestrator never imports `iam.New`, never knows that
`aws.iam` needs a region. It just calls `sources.NewByID(ctx,
"aws.iam", cfg)`, which delegates to the registered factory.

**Bootstrap-time registration.** The orchestrator imports each in-tree
source package purely for its side effect of calling
`sources.RegisterFactory` from `init()`. A typical bootstrap import
block:

```go
// internal/orchestrator/registrations.go
package orchestrator

import (
    // Each blank-import causes the package's init() to run, which
    // registers the source's factory with the global registry.
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/iam"
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/s3"
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/aws/cloudtrail"
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/iam"
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/gcp/storage"
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/github"
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/okta"
    _ "github.com/sigcomply/sigcomply-cli/internal/sources/manual"
    // …project-local plugins compiled in via `sigcomply build` are
    // appended here by the generated wrapper.
)
```

Adding a new in-tree source is a two-line change: write the package,
add a blank-import line. There is no central case statement to keep in
sync. Adding a project-local plugin is the same pattern, applied
through `sigcomply build` (M16).

**No runtime plugin loading.** Go's `plugin` package is fragile across
versions and Linux-only; we don't use it. Every source — in-tree or
third-party — is compiled in. `sigcomply build` is the build wrapper
that includes project-local plugins; see
[`07-extensibility.md`](07-extensibility.md).

---

## Plugin manifest

Each plugin ships with a manifest declaring its identity, the
evidence types it emits, and its configuration schema:

```yaml
# internal/sources/aws/iam/plugin.yaml (in-tree)
schema_version: plugin.v1
id: aws.iam
display_name: "AWS IAM"
version: "1.0.0"
description: |
  Fetches IAM users, roles, policies, and access keys from a single
  AWS account using SDK default credentials.

emits:
  - user_record
  - iam_role
  - iam_policy
  - access_key

config_schema:
  region:
    type: string
    required: true
    description: "AWS region for STS and IAM API calls."
  profile:
    type: string
    description: "AWS named profile (~/.aws/credentials). Optional."
  role_arn:
    type: string
    description: "Role to assume after initial auth. Optional."

requires_credentials:
  - source: env_or_default_chain   # AWS SDK default
```

The manifest is validated at startup. Any plugin in the registry whose
manifest fails validation aborts CLI startup with exit 3.

---

## Evidence types — registered separately, validated by the collector

A plugin declares the set of evidence types it emits via `Emits()` and
in its manifest. A policy declares the types it accepts on each slot
(`accepts: [...]`). The `EvidenceTypeRegistry` mediates: every type ID
named on either side must be a registered schema, and the collector
validates every record's payload against the registered schema before
signing.

The full design — file format, embedding via `go:embed`, schema
versioning, the cross-source `IdentityKey` field, the rubric for "new
type vs. extend `accepts:`," and the project-local extension path
under `.sigcomply/evidence_types/` — lives in
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md).
Read that document before authoring a plugin or a policy that needs
a new evidence shape.

The short version a plugin author needs:

- Emit records with `Type` set to a registered type ID.
- Set `IdentityKey` when the type has a meaningful cross-source
  identity; see
  [`03-policy-spec.md`](03-policy-spec.md) §Cross-source dedup.
- Trust the collector to validate payloads; do not invent local
  schema enforcement. If the validation fails, that's a bug in the
  emitted payload, not in the schema.

---

## Built-in plugin set (v1)

The CLI ships with these plugins compiled in. Each lives under
`internal/sources/<id>/` and self-registers a factory via `init()` (see
§The factory contract).

| Plugin ID | Emits | Notes |
|---|---|---|
| `aws.iam` | `user_record`, `iam_role`, `iam_policy`, `access_key` | One AWS account per instance. Multiple instances supported via separate config blocks. |
| `aws.s3` | `s3_bucket`, `s3_bucket_policy` | |
| `aws.cloudtrail` | `cloudtrail_trail`, `cloudtrail_event_selector` | |
| `aws.kms` | `kms_key`, `kms_key_policy` | |
| `aws.rds` | `rds_instance`, `rds_snapshot` | |
| `aws.ec2` | `ec2_instance`, `security_group`, `vpc`, `route_table` | |
| `aws.cloudwatch` | `cloudwatch_log_group`, `cloudwatch_alarm` | |
| `aws.guardduty` | `guardduty_detector`, `guardduty_finding` | |
| `aws.config` | `config_recorder`, `config_rule` | |
| `aws.eks` | `eks_cluster`, `eks_nodegroup` | |
| `gcp.iam` | `user_record`, `gcp_service_account`, `gcp_iam_policy` | `user_record` for human members; `gcp_service_account` for SAs. |
| `gcp.storage` | `storage_bucket`, `storage_bucket_policy` | |
| `gcp.compute` | `gcp_instance`, `security_group`, `vpc` | Note: `security_group` shared schema with AWS. |
| `gcp.sql` | `sql_instance` | |
| `github` | `vcs_repository`, `user_record`, `vcs_branch_protection` | Single org per instance. |
| `okta` | `user_record`, `okta_group`, `okta_application` | |
| `manual.pdf` | varies — declared per catalog entry | **Project-level singleton.** Exactly one instance per project. See §The manual.pdf plugin. |

Additional plugins (Azure, GitLab, Bitbucket, Auth0, BambooHR,
Workday, Slack, Notion) ship as the community contributes them.

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

### Plugin manifest

The singleton ships with a single bucket, single prefix, single set of
credentials, configured at the project level (`sources.manual.pdf` in
`.sigcomply.yaml`):

```yaml
schema_version: plugin.v1
id: manual.pdf
display_name: "Manual PDF Evidence"
description: |
  Lists all files in the catalog-resolved folder in the project's
  configured manual-evidence bucket. Supported images (JPEG, PNG, GIF,
  TIFF, WebP, BMP) are auto-converted to PDF; all files are merged into
  one PDF before signing. Emits one signed_document manifest record per
  catalog entry. The merged PDF is preserved alongside the envelope as
  an attachment. Singleton: exactly one instance per project.

emits: [signed_document]

singleton: true                  # cannot be instantiated with bracket suffix

config_schema:
  backend:
    type: string
    description: "Any registered manual-evidence backend ID. In-tree
                  backends ship as: local, s3, gcs, azure_blob. The s3
                  backend also serves on-prem S3-compatible stores
                  (MinIO, Ceph, Wasabi, …) via endpoint +
                  force_path_style. Third-party backends (SFTP, NFS,
                  custom object stores) register from
                  .sigcomply/plugins/ via manual.RegisterReader — see
                  Axis A in 00-three-plugin-axes.md and §Custom
                  manual-evidence backends in 07-extensibility.md."
    required: true
  bucket:
    type: string
    required: true
  prefix:
    type: string
    default: "manual/"
  region:
    type: string
  endpoint:
    type: string
    description: "For S3-compatible endpoints (on-prem MinIO, etc.)."
```

Backend selection goes through a self-registering factory registry —
the same pattern source plugins (Axis C) and vault backends (Axis B)
use. The `manual.pdf` source dispatches generically; no hardcoded
switch. See [`00-three-plugin-axes.md`](00-three-plugin-axes.md)
§Axis A for the unified rationale.

### Manual catalog (per project)

```yaml
# .sigcomply/manual_catalog/access_review_quarterly.yaml
schema_version: manual_catalog.v1

id: access_review_quarterly
emits_as: signed_document
cadence: quarterly               # continuous|hourly|daily|weekly|monthly|quarterly|annual
grace_period: 15d
temporal_rule: retrospective     # PDF dated within the period or grace window
filename: evidence.pdf           # kept for display purposes; ignored in collection
description: "Signed quarterly user access review."
```

The `filename` field is retained for backward compatibility and display
purposes (the Evidence SPA uses it as a suggested save-name). The
collector ignores it — all files found in the period folder are
collected regardless of name.

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
`file_valid` to `false`. The framework's manual-presence Rego rule
requires `file_valid == true` to pass; an auditor reading the envelope
sees the specific failure reasons in the manifest.

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

When the resolved path does not contain a PDF (or the PDF falls outside
the temporal window), the CLI emits a structured, multi-line error
naming the policy, the catalog entry, the period, and — crucially —
the **exact expected upload path verbatim**. This is the canonical
user-facing message:

```
[error] Policy soc2.cc6.1.access_review requires manual evidence.

   Evidence:   access_review_quarterly
   Period:     2026-Q1
   Expected:   s3://acme-evidence/manual/access_review_quarterly/2026-Q1/

   To remediate:
   1. Generate the evidence PDF (use the SigComply Evidence SPA
      at https://evidence.sigcomply.com, or your own tooling).
   2. Upload one or more files (PDF, JPEG, PNG, GIF, TIFF, WebP, or BMP)
      to the folder above. Any filename is accepted.
   3. Manually re-run the appropriate compliance workflow (Settings → Actions → Re-run).
```

The same message is preserved verbatim in two other places:

- The policy's `result.json` under the failing check, so an auditor
  reading the run folder offline sees the same remediation steps.
- The violation `reason` field, so JSON/JUnit/SARIF consumers receive
  the full text (not just a code).

Because the path is canonical (see §Path resolution), the operator can
upload the PDF without consulting any other documentation — the error
message is sufficient.

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
bindings:
  soc2.cc6.1.mfa_enforced:
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
bindings:
  soc2.cc6.1.admin_mfa_enforced:
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
2. Author the manifest `plugin.yaml` declaring `id`, `emits`, and
   `config_schema`.
3. Author `plugin.go` implementing `SourcePlugin` and calling
   `sources.RegisterFactory(...)` in `init()` — same signature, same
   registry as the in-tree plugins.
4. If the plugin needs an evidence shape not already shipped, drop a
   schema YAML under `.sigcomply/evidence_types/<id>.yaml`
   (see [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)).
5. Run `sigcomply build` (M16) — this scans `.sigcomply/plugins/`,
   generates a wrapper that blank-imports each project-local package
   (so their `init()` factories register at startup), and compiles a
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
