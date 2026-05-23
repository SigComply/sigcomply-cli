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

    // EvidenceType is the slot's declared type. The plugin must return
    // records of this type, validated against its schema.
    EvidenceType string

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

## Plugin manifest

Each plugin ships with a manifest declaring its identity, the
evidence types it emits, and its configuration schema:

```yaml
# internal/plugins/aws.iam/plugin.yaml (in-tree)
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

## Evidence types — first-class, registered separately

Evidence types live alongside plugins under
`internal/evidence_types/<id>/schema.json` (in-tree). Each is a JSON
Schema document:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://schemas.sigcomply.io/evidence_types/user_record/v1.json",
  "title": "user_record",
  "version": 1,
  "type": "object",
  "required": ["id", "mfa_enabled"],
  "properties": {
    "id":                 { "type": "string", "description": "Stable ID within the source." },
    "email":              { "type": "string", "format": "email" },
    "display_name":       { "type": "string" },
    "mfa_enabled":        { "type": "boolean" },
    "is_service_account": { "type": "boolean" },
    "is_admin":           { "type": "boolean" },
    "last_used_at":       { "type": "string", "format": "date-time" },
    "created_at":         { "type": "string", "format": "date-time" }
  },
  "additionalProperties": true
}
```

**Why types are separate from plugins.** A plugin declares "I emit
records conforming to `user_record.v1`." A policy declares "I consume
records conforming to `user_record.v1`." The registry mediates. Adding
a new plugin that emits an existing type makes that plugin
immediately consumable by every policy already using that type — no
policy change.

**Identity keys across sources.** When an evidence type represents an
entity that exists in multiple source systems (a `user_record` of
"alice@acme.com" exists in both AWS IAM and Okta), the plugin should
populate `EvidenceRecord.IdentityKey` with a cross-source-stable value
(typically email, employee_id). This lets rules dedupe across sources
bound to the same slot — see
[`03-policy-spec.md`](03-policy-spec.md) §Cross-source dedup.
For evidence types without a meaningful cross-source identity (e.g.
`firewall_rule`, `s3_bucket`), `IdentityKey` is omitted.

**Schema evolution.** Adding optional fields → same version. Removing
fields, changing field types, renaming → new version (`user_record.v2`).
Plugins emit one specific version per record; policies pin to one
version. A coexistence period (`user_record.v1` + `user_record.v2`)
gives plugins and policies time to migrate.

---

## Schema validation

The collector validates every record against the declared evidence
type schema before persisting it. Validation results:

| Outcome | Action |
|---|---|
| Record passes schema | Included in the envelope. |
| Record fails schema | Dropped; logged in envelope diagnostics. |
| >5% of records from a (plugin, slot) call fail | The whole call is marked `error`; policies depending on it become `error` status. |

This is what makes substitutability safe: a policy can rely on the
fields its evidence type declares, because the collector refuses to
pass through malformed records.

---

## Built-in plugin set (v1)

The CLI ships with these plugins compiled in. Each lives under
`internal/plugins/<id>/`.

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
  Reads customer-uploaded PDFs from the project's configured manual-
  evidence bucket and emits a small JSON manifest record for each. The
  PDF itself is preserved alongside the envelope as an attachment.
  Singleton: exactly one instance per project.

emits: [signed_document]

singleton: true                  # cannot be instantiated with bracket suffix

config_schema:
  backend:
    type: string
    enum: [local, s3, gcs, azure_blob]
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

### Manual catalog (per project)

```yaml
# .sigcomply/manual_catalog/access_review_quarterly.yaml
schema_version: manual_catalog.v1

id: access_review_quarterly
emits_as: signed_document
cadence: quarterly               # continuous|hourly|daily|weekly|monthly|quarterly|annual
grace_period: 15d
temporal_rule: retrospective     # PDF dated within the period or grace window
filename: evidence.pdf
description: "Signed quarterly user access review."
```

### Path resolution

For each catalog entry and each period, the plugin computes a fully-
qualified path under the project's single configured bucket:

```
{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/{filename}
```

Default `prefix` is `manual/`. Default `filename` is `evidence.pdf`. For
AcmeCorp's quarterly access review in Q1 2026:

```
s3://acme-evidence/manual/access_review_quarterly/2026-Q1/evidence.pdf
```

**This scheme is canonical.** The CLI computes the path; customers
cannot remap it per-policy, per-catalog-entry, or per-framework. The
only knobs are the project-level `bucket`, `prefix`, and (per catalog
entry) `filename`. This determinism is what lets a missing-evidence
error give the operator an exact upload path, and what lets an auditor
recompute the expected location from the catalog alone.

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
    "framework":   "soc2",
    "file_present": true,
    "file_hash":    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_size":    194523,
    "uploaded_at":  "2026-03-15T10:00:00Z",
    "in_temporal_window": true,
    "expected_uri": "s3://acme-evidence/manual/access_review_quarterly/2026-Q1/evidence.pdf"
  }
}
```

A rule consuming `signed_document` records typically checks `file_present` and
`in_temporal_window`. Future text-extraction (parsing the PDF and emitting
fields like `signed_by`, `signed_date`) extends the schema additively.

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
   Expected:   s3://acme-evidence/manual/access_review_quarterly/2026-Q1/evidence.pdf

   To remediate:
   1. Generate the access review PDF (use the SigComply Evidence SPA
      at https://evidence.sigcomply.com, or your own tooling).
   2. Upload it to the path above.
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

The collector mirrors the PDF bytes into the run folder as an
attachment:

```
soc2/2026-Q1/run_.../policies/<policy_id>/attachments/access_review_quarterly/evidence.pdf
```

The attachment is sibling to the envelope. An auditor opening the run
folder sees both the signed manifest envelope (verifiable offline) and
the actual PDF (their `file_hash` matches the envelope's manifest).

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

## Writing a custom plugin

Customers needing a plugin for an internal system can author one
project-locally under `.sigcomply/plugins/<id>/`. The full extension
workflow is documented in [`07-extensibility.md`](07-extensibility.md);
the short version:

1. Create the directory `.sigcomply/plugins/acme.internal_iam/`.
2. Author the manifest `plugin.yaml` declaring `id`, `emits`, and
   `config_schema`.
3. Author the implementation `plugin.go` implementing `SourcePlugin`.
4. Register evidence types under `.sigcomply/evidence_types/` if the
   plugin emits a type not already shipped.
5. The CLI loads `.sigcomply/plugins/` at startup and merges them into
   `SourceRegistry`.

There is no separate compilation step. Project-local plugins are
loaded as Go source via a build step the CLI orchestrates — see
[`07-extensibility.md`](07-extensibility.md) for the mechanism.

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
