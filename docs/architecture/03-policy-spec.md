# 03 — Policy Spec

A policy declares: what it asserts, what evidence mode it uses, what
evidence shapes it needs, what parameters can be tuned, and the
condition that determines pass/fail. Policies are framework-shipped
(curated, in-binary) or project-local (custom, under
`.sigcomply/policies/`). The spec format is identical for both.

The primary evaluation mechanism is the `pass_when:` declarative
condition DSL — a YAML block inside `policy.yaml` that expresses
"all records must satisfy X" without a separate rule file. For the
rare case that `pass_when:` cannot express the logic (multi-slot
joins, complex time math, cross-record aggregations), a `rule:`
escape hatch remains available.

Evidence collection is controlled by `evidence_mode: automated |
manual`. Automated (default) collects from bound API source plugins
and evaluates `pass_when:`. Manual binds `manual.pdf` and runs the
universal PDF-presence check — no `pass_when:` or `rule:` involved.

---

## File layout

For most policies, `policy.yaml` is the entire artifact — no
separate rule file required:

```
soc2/policies/cc6.1.mfa_enforced/
   policy.yaml        # spec + pass_when: condition — complete
```

Policies that need the `rule:` escape hatch add a rule implementation
alongside:

```
soc2/policies/cc6.1.complex_check/
   policy.yaml        # spec (with rule: reference instead of pass_when:)
   rule.rego          (one of)   # Rego implementation
   rule.go            (or)       # Go implementation
   tests/                        # rule unit tests
      passes_when_…yaml
      fails_when_…yaml
```

The `rule:` field names the rule reference
(`rules.complex_check.v1`); the registry resolves it to whichever
rule file is present. See §Escape-hatch rule implementations.

---

## The spec — `policy.yaml`

```yaml
schema_version: policy.v1

id: soc2.cc6.1.mfa_enforced

control: SOC2.CC6.1
severity: high               # info | low | medium | high | critical
category: access_control
evidence_mode: automated     # automated (default) | manual

cadence: daily               # continuous | hourly | daily | weekly | monthly | quarterly | annual
on_push: true                # run on every PR/push for fast feedback

description: |
  All users in the configured user directory must have multi-factor
  authentication enabled.

remediation: |
  Enable MFA for affected users via the relevant identity provider.

slots:
  user_directory:
    accepts: [directory_user]    # evidence type IDs this slot consumes
    cardinality: one-or-more
    required: true
    description: "Source(s) of users to evaluate for MFA."

parameters:
  exempt_service_accounts:
    type: bool
    default: true
    description: |
      When true, records where is_service_account == true are skipped.

pass_when:
  slot: user_directory
  filter:
    exclude:
      all_of:
        - { param: exempt_service_accounts, eq: true }
        - { field: is_service_account, eq: true }
  all:
    field: mfa_enabled
    eq: true
  violation_message: "MFA not enabled for {display_name} ({id})"

tags:
  - identity
```

### Field reference

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | Always `policy.v1` for v1 of the spec format. |
| `id` | yes | Globally unique policy ID. Must match the directory name's last segment. Convention: `<framework>.<control_lowercase>.<short_name>`. |
| `control` | yes | The control this policy contributes to. Must exist in the framework's control catalog. |
| `severity` | yes | Display severity. The rule cannot override this; if a single policy needs variable severity, split into multiple policies. |
| `category` | no | Free-form grouping label (e.g. `access_control`, `encryption`, `monitoring`). Used in summaries. |
| `evidence_mode` | no | `automated` (default) or `manual`. Controls the evidence collection path. `automated` collects from bound API source plugins and evaluates `pass_when:` or `rule:`. `manual` binds `manual.pdf` and runs the universal PDF-presence check — `pass_when:` and `rule:` are ignored. Projects can override the framework default via project config. See §evidence_mode. |
| `cadence` | yes | How often the policy must be evaluated. One of `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual`, or the custom-interval form `every:<duration>` (`every:6h`, `every:90m`; 5-minute floor). The CLI enforces cadence in scheduled mode via per-policy state shards — see [`11-cadence-model.md`](11-cadence-model.md). |
| `on_push` | no | Whether this policy is suitable for fast PR/push feedback. Defaults to `true` when `evidence_mode: automated`, `false` when `evidence_mode: manual`. CI workflows for on-push gates filter by this tag. |
| `description` | yes | Plain-English statement of what the policy asserts. |
| `remediation` | no | Plain-English remediation guidance, displayed alongside failures. |
| `slots` | no | Named typed inputs. Required when `evidence_mode: automated`. Omitted for manual policies (the planner creates an implicit slot). See §Slots. |
| `parameters` | no | Tunable per-project values. See §Parameters. |
| `pass_when` | no | Declarative condition DSL — the primary evaluation path. Required when `evidence_mode: automated` and `rule:` is absent. Ignored when `evidence_mode: manual`. See §pass_when. |
| `rule` | no | Escape-hatch rule reference. Used only when `pass_when:` cannot express the logic. If both are present, `rule:` takes precedence. Must resolve in `RuleRegistry`. See §Escape-hatch rule implementations. |
| `catalog_entry` | no | For `evidence_mode: manual`: the manual catalog entry ID that resolves to the PDF path. Defaults to the policy's short name (last segment of `id`). |
| `tags` | no | Free-form labels for filtering and reporting. |

---

## Slots

A slot is a named, multi-typed input on a policy. It is the interface
between the policy and the source plugins that fulfill it — and the
only place where a policy names evidence shapes. Slots are the contract
that makes a single policy spec satisfiable by any number of sources
across any number of vendor backends.

### The `accepts:` list

Every slot declares an `accepts:` list — the set of evidence type IDs
this slot will consume. The in-memory shape is
`Slot.Accepts []string`. There is no singular `type:` field.

```yaml
slots:
  user_directory:
    accepts: [user_record]                                       # single-type slot
  buckets:
    accepts: [s3_bucket, gcs_bucket, azure_blob_container]       # multi-type slot
```

A source matches a slot when **`source.Emits() ∩ slot.Accepts ≠ ∅`**.
The planner verifies this intersection at plan time; an empty
intersection fails with exit code 3.

A single-element `accepts:` list is the common case (most slots consume
exactly one evidence type). A multi-element list expresses a slot that
is genuinely backend-agnostic — see the decision rubric at the end of
this section for when to use it.

### Cardinality

| Value | Meaning | Project may bind |
|---|---|---|
| `exactly-one` | Slot must be fulfilled by exactly one source. | 1 source |
| `at-most-one` | Slot may be fulfilled by zero or one source. | 0 or 1 source |
| `one-or-more` | Slot must be fulfilled by at least one source. | 1+ sources |
| `optional` | Slot may be fulfilled by zero or more sources. | 0+ sources |

If `required: true` and the slot has no records at run time, the policy
result is `skip` with diagnostic `"no records for required slot
<name>"`.

If `required: false` and the slot has no records, the rule sees an
empty `input.slots.<name>` array; it is the rule's responsibility to
handle the absence.

### Multiple bound sources

When `cardinality: one-or-more` or `optional` allows multiple sources,
the rule receives the **union** of all bound sources' records under
`input.slots.<slot_name>`. The records remain tagged with their
`Type` and `SourceID`. Most rules ignore both and treat the union as a
flat set; rules that legitimately need to behave differently per
evidence type (because, say, an S3 bucket's encryption configuration
is structurally different from a GCS bucket's) switch on `record.Type`:

```rego
package rules.object_storage_encrypted.v1

violation contains v if {
    record := input.slots.buckets[_]
    record.Type == "s3_bucket"
    not record.payload.encryption.sse_enabled
    v := {"resource_id": record.id, "reason": "S3 bucket not encrypted"}
}

violation contains v if {
    record := input.slots.buckets[_]
    record.Type == "gcs_bucket"
    not record.payload.default_kms_key_name
    v := {"resource_id": record.id, "reason": "GCS bucket lacks default KMS key"}
}
```

In Go:

```go
for _, rec := range in.Records("buckets") {
    switch rec.Type {
    case "s3_bucket":     // ...
    case "gcs_bucket":    // ...
    }
}
```

Switching on `record.Type` is the **only** legitimate per-source
branch in rule logic. Branching on `record.SourceID` is a code smell —
it ties the rule to a specific plugin ID and breaks substitutability.
If a rule needs to know "this came from AWS rather than GCP," the
information is already encoded in `Type`.

### When to add a new evidence type vs. extend an existing slot's `accepts:`

This decision comes up whenever a new backend appears for a check that
SigComply already supports.

- **Same logical entity, same fields → reuse the existing type.** If
  AWS IAM, Okta, and BambooHR all represent "a human user with an MFA
  setting," they emit `user_record`. The slot keeps `accepts: [user_record]`
  and the new plugin just adds itself to the bindings. This is the
  default path.
- **Same logical entity, structurally divergent fields → new type, add
  to `accepts:`.** S3 buckets and GCS buckets are both "an object
  storage container," but their encryption configuration, IAM model,
  and lifecycle settings are structurally different. Forcing a shared
  schema would either lose fidelity (lowest-common-denominator) or
  bloat both schemas with each other's irrelevant fields. The right
  move is: define `s3_bucket` and `gcs_bucket` as separate types,
  declare `accepts: [s3_bucket, gcs_bucket]` on the slot, and let the
  rule switch on `record.Type`.
- **Different logical entity → keep slots separate.** A firewall rule
  in AWS is not the same entity as a GitHub branch protection rule.
  They go in different slots, not into one slot's `accepts:` list.

A useful test: if the rule would benefit from iterating "all the
buckets, regardless of cloud" (e.g., "count how many buckets are
unencrypted across all clouds"), the multi-type slot is correct. If
the rule would always handle each source's data in a fundamentally
different way, those are separate slots.

**Rule-of-thumb consequence.** Most slots have a single-element
`accepts:` list. Multi-element lists appear primarily in policies that
verify cloud-agnostic invariants (encryption at rest, network egress,
audit logging) where the same control applies across vendors with
different on-the-wire shapes.

### Cross-source dedup (read this if your slot has cardinality `one-or-more`)

The union is a **bag**, not a set. If Alice has an account in both AWS
IAM and Okta and a project's `user_directory` slot binds to
`[aws.iam, okta]`, Alice's two records arrive as two entries. A naive
rule that iterates and counts produces `resources_evaluated: <total>`
that double-counts every human with accounts in multiple sources.

This matters because the count crosses the privacy boundary as the
customer's compliance score input. A 47-record union of 30 AWS + 17
Okta where 5 humans appear in both should report 42 unique humans
evaluated, not 47.

**The dedup mechanism** is `identity_key`. Source plugins may set
`identity_key` on an `EvidenceRecord` to a stable cross-source
identifier — typically email, employee_id, or another value that
represents the same real-world entity across systems:

```go
// Inside aws.iam.Collect(...)
records = append(records, evidence.Record{
    Type:        "user_record",
    ID:          "AIDAEXAMPLE01",        // AWS-local ARN
    IdentityKey: "alice@acme.com",        // cross-source
    Payload:     payload,
    SourceID:    "aws.iam",
})

// Inside okta.Collect(...)
records = append(records, evidence.Record{
    Type:        "user_record",
    ID:          "okta-user-99",          // Okta-local ID
    IdentityKey: "alice@acme.com",        // same key — dedup possible
    Payload:     payload,
    SourceID:    "okta",
})
```

When a rule processes records with `IdentityKey` set, it should
**dedupe by identity_key first** before counting. The framework's Go
rule helpers expose `rule.DedupeByIdentity(records []Record) []Record`
which returns one record per identity_key (first-seen wins; rules
needing different semantics — e.g., "merge fields from both records"
— must implement that themselves).

Rego rules apply the same pattern via a `dedupe_by_identity` helper in
`data.sigcomply.lib`:

```rego
package rules.mfa_enforced.v1

import data.sigcomply.lib.dedupe_by_identity

violation contains v if {
    unique_users := dedupe_by_identity(input.slots.user_directory)
    record := unique_users[_]
    not record.payload.mfa_enabled
    v := {"resource_id": record.id, "reason": ...}
}
```

YAML DSL rules dedupe automatically when the evidence type schema
declares `identity_key` as a known field — the transpiler emits the
dedupe step.

**When `identity_key` is not set**, no dedup happens. This is correct
for evidence types where there is no cross-source identity (e.g.,
`firewall_rule` — a rule in AWS is not the same rule as a rule in
GCP). Plugin authors should set `identity_key` only when it
genuinely represents a shared real-world entity across sources.

**Effect on counts**: when dedup occurs, `resources_evaluated` and
`resources_failed` in the `PolicyResult` reflect the deduplicated
count. The vault's full violation list may still include all records
(for forensic visibility into which source reported which failure);
the cloud submission carries the deduplicated count only.

Shipped rules that consume types where `identity_key` is meaningful
(`user_record`, etc.) dedupe by default. Custom rule authors must
explicitly choose: dedupe (set-of-entities semantics) or no-dedupe
(bag-of-records semantics).

---

## Parameters

Parameters let projects tune policy behavior without forking. Each
parameter has a type, a default, and optional bounds.

```yaml
parameters:
  max_age_days:
    type: int
    default: 90
    min: 1
    max: 365
    description: "Maximum credential age in days before rotation is required."

  approved_kms_keys:
    type: list_of_string
    default: []
    description: "KMS key ARNs that are approved for encryption."

  enforce_in_grace_period:
    type: bool
    default: false
```

### Supported types

| Type | Project value form | Notes |
|---|---|---|
| `bool` | `true` / `false` | |
| `int` | integer | Optional `min` / `max` |
| `float` | number | Optional `min` / `max` |
| `string` | string | Optional `enum: [...]` or `pattern: <regex>` |
| `duration` | `"30d"`, `"24h"`, `"15m"` | Parsed via Go `time.ParseDuration` extended for days |
| `date` | `"2026-01-15"` | ISO 8601 date |
| `list_of_string` | `["a", "b"]` | Optional `item_pattern: <regex>` |
| `list_of_int` | `[1, 2, 3]` | |

### Effective values

The planner computes effective values as:

```
effective = policy.parameters.<name>.default
          ⊕ project_config.policy_parameters[policy_id].<name>
```

Validation runs against `min/max/enum/pattern`. Out-of-bounds values
cause a planning error (exit 3). The effective values are stamped into
the run's `manifest.json` so auditors see the exact thresholds used.

---

## evidence_mode

`evidence_mode` is a first-class field on every policy spec. It
controls the entire evidence collection and evaluation path for that
policy.

| Value | Collection | Evaluation |
|---|---|---|
| `automated` (default) | Planner binds configured API source plugins to the policy's declared slots. The collector calls `plugin.Collect()` for each binding. | The evaluator runs the `pass_when:` condition DSL, or the `rule:` escape hatch if `pass_when:` is absent. |
| `manual` | Planner binds `manual.pdf` to an implicit slot, resolving the PDF path via `catalog_entry`. No API calls. | The evaluator runs the universal PDF-presence check: `file_present`, `in_temporal_window`, `file_valid`. `pass_when:` and `rule:` are ignored entirely. |

### Project-level override

Projects can override the framework default for any policy in
`.sigcomply.yaml`:

```yaml
policy_overrides:
  soc2.cc6.1.mfa_enforced:
    evidence_mode: manual          # customer has no IAM integration yet
    catalog_entry: mfa_attestation # which catalog entry to use for the PDF
```

When overriding to `manual`, `catalog_entry` names the catalog entry
that resolves to the PDF path. If omitted, it defaults to the policy's
short name (the last segment of its ID: `mfa_enforced` for
`soc2.cc6.1.mfa_enforced`).

The project config override is the mechanism for customers who rely on
manual processes today and plan to wire up API integrations later. The
policy ID stays the same in both modes; the audit trail shows
`evidence_mode` so auditors see which path was used.

### `on_push` interaction

When `evidence_mode: manual`, `on_push` defaults to `false` — the PDF
is not expected on every commit. When `evidence_mode: automated`,
`on_push` defaults to `true`. Either can be overridden explicitly.

---

## `pass_when:` — declarative condition DSL

`pass_when:` is the **primary evaluation path** for automated policies.
It expresses "all records must satisfy X" directly in `policy.yaml` —
no separate rule file required. The evaluator interprets it against the
collected records from the policy's slots.

For logic the DSL cannot express (multi-slot joins, cross-record
aggregations, complex date computations not pre-computable by the
plugin), the `rule:` escape hatch is available (see §Escape-hatch rule
implementations). In practice, pre-computing derived fields in the
source plugin (e.g. emitting `days_since_rotation` instead of
`last_rotation_at`) eliminates most needs for the escape hatch.

`pass_when:` is ignored when `evidence_mode: manual`.

### Structure

```yaml
pass_when:
  slot: <slot_name>      # required if the policy has >1 slot; omit for single-slot policies
  filter:                # optional: pre-filter records before applying the quantifier
    include: <condition>   # only evaluate records matching this condition
    exclude: <condition>   # skip records matching this condition
  <quantifier>: <condition>   # one of: all | none | any | count
  violation_message: "<template>"  # optional; default auto-generated
```

### Quantifiers

| Quantifier | Semantics | Typical use |
|---|---|---|
| `all:` | Every record in the (filtered) slot must satisfy the condition. | MFA enforced, encryption at rest, branch protection enabled. |
| `none:` | No record in the (filtered) slot may satisfy the condition. | No buckets publicly accessible, no root API keys active. |
| `any:` | At least one record must satisfy the condition. | At least one CloudTrail trail enabled, at least one backup present. |
| `count:` | A threshold count or percentage must satisfy the condition. | ≥90% of employees completed security training. |

### Conditions

A condition tests a field on a record payload or a parameter value:

```yaml
# Equality / inequality
{ field: mfa_enabled, eq: true }
{ field: status, neq: "DELETED" }

# Numeric / date comparison (right-hand side can be a literal or param ref)
{ field: days_since_rotation, lt: 90 }
{ field: days_since_rotation, lte: { param: max_age_days } }
{ field: cert_expiry_days, gt: 30 }

# Set membership
{ field: region, in: ["us-east-1", "us-west-2"] }
{ field: protocol, not_in: ["http", "ftp"] }

# Existence (non-null, non-empty)
{ field: kms_key_id, is_set: true }

# Parameter value check (used in filter conditions)
{ param: exempt_service_accounts, eq: true }

# Compound — all_of (AND) / any_of (OR)
all_of:
  - { field: encryption_at_rest_enabled, eq: true }
  - { field: public_access_blocked, eq: true }
```

`field:` uses dot notation for nested fields
(`encryption.key_id`, `protection.required_reviewers_count`).
`param:` references the effective value of a declared parameter after
project-config overrides are applied.

### The `count:` quantifier

```yaml
pass_when:
  slot: employees
  count:
    min_percentage: 100     # 0–100; all must satisfy
    condition:
      field: training_completed_this_year
      eq: true
  violation_message: "Training not completed for {display_name}"
```

`count:` supports `min:` (absolute minimum), `max:` (absolute
maximum), `min_percentage:`, and `max_percentage:`. At least one of
these four is required.

### Violation message templates

The default message when a record fails: `"<field> is <actual_value>
for <id>"`. Override with `violation_message:` using `{token}`
interpolation. Available tokens: any field name from the record
payload, plus `{id}`, `{source_id}`, and `{type}`. Parameter values
are referenceable as `{param.<name>}`.

### Identity-key dedup

When the accepted evidence type declares an `identity_key` (e.g.
`directory_user` uses email as the cross-source dedup key), the DSL
evaluator deduplicates records by `identity_key` before applying the
quantifier. Records without `identity_key` set are never deduplicated.
Policy authors using `pass_when:` never need to write dedup logic
explicitly.

### Multi-slot policies

A policy with multiple slots provides a list of `pass_when:` blocks.
All blocks must pass for the policy to pass:

```yaml
pass_when:
  - slot: buckets
    all:
      field: encryption_at_rest_enabled
      eq: true
    violation_message: "Bucket {name} is not encrypted at rest"
  - slot: trails
    any:
      field: enabled
      eq: true
```

Cross-slot conditions (e.g. "every user in slot A must appear in slot
B") cannot be expressed in the DSL and require the `rule:` escape
hatch.

### Worked examples

**MFA enforced on all users (service accounts exempt by parameter):**

```yaml
pass_when:
  slot: user_directory
  filter:
    exclude:
      all_of:
        - { param: exempt_service_accounts, eq: true }
        - { field: is_service_account, eq: true }
  all:
    field: mfa_enabled
    eq: true
  violation_message: "MFA not enabled for {display_name} ({id})"
```

**Access key rotation within a configurable age limit:**

```yaml
pass_when:
  slot: access_keys
  filter:
    exclude: { field: is_active, eq: false }
  all:
    field: days_since_rotation
    lt: { param: max_age_days }
  violation_message: "Key {id} last rotated {days_since_rotation} days ago (limit: {param.max_age_days})"
```

**At least one CloudTrail trail enabled:**

```yaml
pass_when:
  slot: audit_trails
  any:
    field: enabled
    eq: true
```

**All S3 buckets encrypted and blocking public access:**

```yaml
pass_when:
  slot: buckets
  all:
    all_of:
      - { field: encryption_at_rest_enabled, eq: true }
      - { field: public_access_blocked, eq: true }
  violation_message: "Bucket {name}: encrypted={encryption_at_rest_enabled}, public_blocked={public_access_blocked}"
```

---

## Escape-hatch rule references

The `rule:` field is available for the rare cases that `pass_when:`
cannot express. If both `pass_when:` and `rule:` are present, `rule:`
takes precedence (escape hatch always wins). If neither is present and
`evidence_mode: automated`, the spec fails to load with exit 3.

The `rule:` field is a string in dotted-with-version notation:

```
rules.<name>.v<n>
```

The `RuleRegistry` resolves a reference to a `Rule` interface
implementation regardless of which language the rule is authored in.

**When to reach for `rule:` instead of `pass_when:`:**
- Cross-slot conditions: "every user in slot A must also exist in slot B"
- Computations the plugin could not pre-compute: multi-record
  aggregations, cross-field derivations
- Complex pass/fail logic that cannot be composed from the DSL's
  quantifier + condition primitives

**Versioning.** Bumping a rule's logic in a breaking way (changing the
meaning of pass/fail) requires a new version (`.v2`). Existing
policies pin to the older version until intentionally migrated. The
rule version is stamped into every `PolicyResult` so old runs in the
vault remain interpretable.

---

## Cadence and on-push tagging

`cadence` and `on_push` together describe **when** a policy should be
evaluated. Both live on the policy spec. In scheduled mode the CLI
enforces cadence via per-policy state shards in the vault; in PR mode
and manual mode the CLI evaluates every in-scope policy regardless of
cadence. Full algorithm in [`11-cadence-model.md`](11-cadence-model.md)
§The decision rule.

### Why cadence matters

A SOC 2 program does not benefit from re-checking every quarterly
access review on every commit, and a public-bucket drift check does
not want to wait a day to fire. Different policies need different
schedules. By tagging each policy with a cadence, the framework author
expresses what's reasonable; the CLI enforces it in scheduled mode
without needing the CI scheduler to know which policies are due.

The flow:

```
policy.yaml declares cadence ──→ project .sigcomply.yaml may override
                              ──→ scheduled CI workflow invokes
                                  `sigcomply check --scheduled`
                              ──→ CLI loads per-policy state shards,
                                  decides per-policy whether to re-
                                  evaluate or carry forward
                              ──→ carry-forward results reference the
                                  prior signed envelope; the auditor
                                  verifies that envelope independently
```

### Cadence values

The seven named cadences:

| Cadence | Typical policy examples |
|---|---|
| `continuous` | Branch protection on the default branch, encryption-at-rest defaults, IaC drift checks that read static config. |
| `hourly` | Public S3 buckets, root-account MFA, IMDSv1 detection — high-blast-radius drift. |
| `daily` | Most automated SOC 2 / ISO 27001 checks: IAM password policy, CloudTrail enabled, RDS encryption, GitHub default-branch protection. |
| `weekly` | Inactive-user reviews, access-key rotation reminders, dependency vulnerability summaries. |
| `monthly` | Backup verification, log retention sweep, vulnerability scan summary. |
| `quarterly` | Manual access reviews, risk acceptance declarations, signed acknowledgments — almost all manual evidence. |
| `annual` | Annual policy acknowledgment, security awareness training completion, business continuity test results. |

Plus the custom-interval form:

| Form | Meaning | Typical use |
|---|---|---|
| `every:<duration>` | Re-evaluate every `<duration>` since last pass | `every:6h` for tightly-monitored admin MFA; `every:90m` for high-frequency drift detection. Floor: 5 minutes. |

`every:24h` is NOT equivalent to `daily`. The named cadence has 1h
cron-drift slack baked in (interval = 23h) and is anchored against
last-pass-at; `every:24h` is exactly 24h from last pass and drifts
time-of-day across consecutive runs.

### The `on_push` tag

`on_push` is orthogonal to `cadence`. It answers a different question:
"Is this policy fast enough and stable enough to gate every PR on?"

- `on_push: true` (default when `evidence_mode: automated`) — the
  policy fetches quickly, fails deterministically, and produces a
  result that a PR author can act on. The on-push CI workflow runs all
  policies with this tag, regardless of their cadence.
- `on_push: false` (default when `evidence_mode: manual`) — the policy
  depends on out-of-band evidence (a PDF the human hasn't uploaded
  yet) and doesn't have an actionable failure mode at PR time. The
  on-push workflow skips it.

A manual quarterly access review has `cadence: quarterly, on_push:
false`: the quarterly workflow checks for the PDF's presence; the
on-push workflow ignores it entirely. A daily IAM MFA check has
`cadence: daily, on_push: true`: the daily workflow runs the full
sweep, and PRs touching IAM also get the policy as fast feedback.

### Cadence enforcement vs operator override

The CLI enforces cadence in scheduled mode but never traps the
operator. If a human types
`sigcomply check --scheduled --policies soc2.cc1.1.board_review`,
the explicit `--policies` filter wins and the policy runs regardless
of cadence state. The decision rule (full algorithm in
[`11-cadence-model.md`](11-cadence-model.md) §The decision rule) puts
operator filters at the top — they always bypass cadence gating.

PR mode (`sigcomply check --pr`) and manual mode (the default,
`sigcomply check`) don't read state at all — every in-scope policy
evaluates. Cadence enforcement is strictly a scheduled-mode behavior.

Effective cadence = `project_config.policy_cadences[id]` if set, else
`policy.cadence`. Per-policy state captures the effective cadence at
the time of the last evaluation so a later run can detect a
configuration change.

### Project override pattern

A project can override a shipped policy's cadence in its
`.sigcomply.yaml`:

```yaml
policy_cadences:
  soc2.cc6.1.mfa_enforced: hourly       # tighten — we care about drift
  soc2.cc6.6.public_access_blocked: continuous
  soc2.cc1.2.code_of_conduct_attested: annual   # loosen — we attest yearly
```

The full reference (precedence, validation, interaction with `--policies`
filtering) lives in [`08-project-config.md`](08-project-config.md).

### A manual policy's cadence in practice

```yaml
schema_version: policy.v1

id: soc2.cc1.4.quarterly_access_review
control: SOC2.CC1.4
severity: medium
category: governance

cadence: quarterly
on_push: false           # omitting is fine — defaults to false when evidence_mode: manual
evidence_mode: manual    # PDF presence check; pass_when: and rule: are not used

catalog_entry: access_review_quarterly   # resolves to the PDF path in manual catalog

description: |
  An access review of all privileged users must be completed and
  signed off each quarter. The reviewer uploads the signed review
  document to the configured manual-evidence bucket.

parameters:
  grace_period_days:
    type: int
    default: 30
    description: "Days after period end before the policy fails for a missing PDF."
```

No `slots:`, no `pass_when:`, no `rule:`. The `evidence_mode: manual`
declaration tells the planner to bind `manual.pdf` and tells the
evaluator to run the universal PDF-presence check: `file_present`,
`in_temporal_window`, `file_valid`. The `grace_period_days` parameter
is consumed by the presence check, not by a rule function.

The quarterly CI workflow (`.github/workflows/sigcomply-quarterly.yml`)
runs `sigcomply check --cadence quarterly` once per quarter on the
calendar boundary plus grace. The on-push workflow never sees this
policy because `on_push: false`. The CLI itself, given
`--policies soc2.cc1.4.quarterly_access_review`, will still evaluate
it on demand — the cadence value is guidance for the scheduler, not a
runtime gate.

---

## Escape-hatch rule implementations

The `rule:` field is used only when `pass_when:` cannot express the
policy logic. If you find yourself reaching for `rule:`, first ask:
can the source plugin pre-compute the derived field that makes the
condition expressible in the DSL? Usually it can.

When `rule:` is genuinely needed, it can be authored in either of two
flavors. Both implement the same `Rule` Go interface.

**When to use `rule:` instead of `pass_when:`:**
- Cross-slot conditions: "every user in slot A must exist in slot B"
- Multi-record aggregations the plugin cannot pre-compute
- Pass/fail logic that requires reasoning across the record set as a
  whole (not per-record)

### Flavor 1 — Go

```go
// rule.go
package complex_check_v1

import (
    "context"
    "fmt"

    "github.com/sigcomply/sigcomply-cli/internal/core/rule"
)

type Rule struct{}

func (Rule) ID() string { return "rules.complex_check.v1" }

func (Rule) Evaluate(ctx context.Context, in rule.Input) (rule.Result, error) {
    // Full Go expressiveness: joins, time math, cross-record logic.
    // Must be deterministic. Must not perform I/O.
    var violations []rule.Violation
    // ...
    return rule.Result{
        Status:     rule.StatusFromViolations(violations),
        Violations: violations,
    }, nil
}

func init() { rule.Register(Rule{}) }
```

**Conventions:**
- Package name `<rule_name>_v<n>`
- Implements `rule.Rule` interface; `init()` registers it
- Must be deterministic; must not perform I/O
- Reviewed at PR time for side-effect-freedom

### Flavor 2 — Rego

```rego
# rule.rego
package rules.complex_check.v1

violation contains v if {
    # Full Rego expressiveness. Sandboxed at runtime.
    # input.slots.<slot_name>[_] for records
    # input.params.<name> for effective parameter values
    # input.now for the current time
    v := { "resource_id": "...", "reason": "..." }
}
```

**Conventions:**
- Package name matches the rule reference: `package rules.<name>.v<n>`
- Rules emit `violation` (set of objects with `resource_id` and
  `reason`) and optionally `diag` (a free-form diagnostics map)
- No imports beyond `data.sigcomply.lib.*` shared helpers

**Rule input shape (both flavors):**

```
{
  "policy_id": "<policy_id>",
  "slots": {
    "<slot_name>": [
      { "type": "<evidence_type>", "id": "...", "source_id": "...",
        "collected_at": "...", "identity_key": "...", "payload": {...} },
      ...
    ]
  },
  "params": { "<name>": <effective_value>, ... },
  "now": "<ISO 8601 timestamp>"
}
```

Rules receive `input.params.<name>` for every declared parameter,
always populated (default if not overridden by project config).

---

## Testing rules

Every policy directory carries a `tests/` subdirectory with YAML
test cases. Each test specifies inputs and expected outputs:

```yaml
# tests/passes_when_all_mfa_on.yaml
name: passes when all users have MFA on
inputs:
  slots:
    user_directory:
      - id: alice
        payload: { email: alice@acme.com, mfa_enabled: true,  is_service_account: false }
      - id: bob
        payload: { email: bob@acme.com,   mfa_enabled: true,  is_service_account: false }
  params:
    exempt_service_accounts: true
  now: "2026-05-23T14:00:00Z"
expected:
  status: pass
  violations: []
```

```yaml
# tests/fails_when_any_mfa_off.yaml
name: fails when any non-service-account user lacks MFA
inputs:
  slots:
    user_directory:
      - id: alice
        payload: { email: alice@acme.com, mfa_enabled: false, is_service_account: false }
      - id: bob
        payload: { email: bob@acme.com,   mfa_enabled: true,  is_service_account: false }
      - id: deploy_bot
        payload: { email: deploy-bot@acme.com, mfa_enabled: false, is_service_account: true }
  params:
    exempt_service_accounts: true
expected:
  status: fail
  violations:
    - resource_id: alice
      reason: "MFA disabled for alice@acme.com"
```

A repo-wide test runner (`sigcomply test policies`) loads every
policy's tests and runs them against the registered rule, regardless
of language flavor.

---

## Policy versioning and lifecycle

- Policies are versionless from the project's perspective: there is one
  current spec per policy ID.
- Substantive logic changes happen in the *rule*, which is versioned.
  When a rule's `.v2` ships, the policy spec is updated to point at it.
  Old runs in the vault retain `rule_version: rules.X.v1` in their
  result.json, so prior results stay interpretable.
- Policies can be deprecated by marking `status: deprecated` (a
  forthcoming optional field). Deprecated policies still run; the
  output formatter surfaces a warning.
- A policy can be removed entirely from a framework only at a major
  framework version bump.

---

## Project-local custom policies

A customer can author policies under
`.sigcomply/policies/<id>/policy.yaml` using the identical schema. The
loader merges them into the registry alongside framework-shipped
policies. Conventions for custom policy IDs:

- Use a customer-specific prefix: `acme.custom.cc6.1.contractor_review`
- Reference framework controls if applicable (`control: SOC2.CC6.1`)
- Rules can reference framework-shipped rules (`rule: rules.mfa_enforced.v1`)
  if the slots align — encouraged when the same logic applies with
  different bindings.

Custom policies declare `evidence_mode`, `cadence`, and `on_push` the
same way framework-shipped policies do. If omitted, the loader applies
these defaults:

- `evidence_mode` absent → `automated`
- `cadence` absent → `daily` when `evidence_mode: automated`;
  `quarterly` when `evidence_mode: manual`
- `on_push` absent → `true` when `evidence_mode: automated`;
  `false` when `evidence_mode: manual`

Explicitly setting all three fields is encouraged — defaults exist to
keep small custom policies low-friction, not to hide intent.

Custom policies appear in run output and submission payloads just like
framework-shipped policies. They do not affect framework version pins.

See [`07-extensibility.md`](07-extensibility.md) for the full
extension workflow.
