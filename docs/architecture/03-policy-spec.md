# 03 — Policy Spec

A policy declares: what it asserts, what evidence mode it uses, what
evidence shapes it needs, what parameters can be tuned, and the
condition that determines pass/fail.

The primary evaluation mechanism is the `pass_when:` declarative
condition DSL — a condition tree that expresses "all records must
satisfy X" without a separate rule file. For the rare case that
`pass_when:` cannot express the logic (multi-slot joins, complex time
math, cross-record aggregations), a `rule:` escape hatch remains
available. **No shipped policy uses `rule:` today** — both SOC 2 and
ISO 27001 are 100% `pass_when:` (each framework's `Rules()` returns
nil). The escape-hatch infrastructure stays available for a future
check the DSL genuinely cannot express.

Evidence collection is controlled by `evidence_mode: automated |
manual`. Automated collects from bound API source plugins and
evaluates `pass_when:`. Manual binds `manual.pdf` and runs the
universal PDF-presence check — no `pass_when:` or `rule:` involved.

---

## Two authoring surfaces

There are two ways a policy reaches the registry, and they are not
symmetric:

- **Framework-shipped policies are authored in Go**, not YAML. Each is
  an `autoPolicy{...}.policy()` (or `manualPolicy{...}.policy()`)
  builder under `internal/frameworks/<fw>/policies_*.go`, using the
  compact clause builders in `builders.go`
  (`leaf`/`all`/`none`/`anyRec`/`allWhere`/`noneWhere`/`anyWhere`/
  `allOf`/`anyOf`). There are **no shipped `policy.yaml` files** and
  **no per-policy `tests/` directories** in-tree. To count a
  framework's policies, count `.policy()` calls.
- **Project-local custom policies are authored as `policy.yaml`** under
  `.sigcomply/policies/<id>/policy.yaml`. This on-disk YAML form is the
  *only* place `policy.yaml` exists. The loader (`internal/spec/
  policy.go`, decoded with `yaml.KnownFields(true)`) parses it into the
  same `core.Policy` the Go builders produce, so the two surfaces are
  semantically identical.

The rest of this document describes the **logical spec** — the fields
of a policy and the DSL — using YAML for legibility. For framework
authors, each YAML field maps directly to a builder argument; for
project authors, the YAML *is* the artifact.

---

## The spec (logical fields, shown as YAML)

```yaml
schema_version: policy.v1

id: soc2.cc6.1.mfa_enforced

control: SOC2.CC6.1
severity: high               # info | low | medium | high | critical
category: access_control
evidence_mode: automated     # automated | manual (required — no default)

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
  quantifier: all
  filter:
    op: eq
    field: payload.is_service_account
    value: false
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
  violation_message: "MFA not enabled for {{.payload.display_name}} ({{.id}})"

tags:
  - identity
```

### Field reference

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes (YAML) | Always `policy.v1`. Required in the on-disk project-local form; the Go builders set it implicitly. |
| `id` | yes | Globally unique policy ID. Convention: `<framework>.<control_lowercase>.<short_name>`. |
| `control` | yes | The control this policy contributes to. Must exist in the framework's control catalog (checked at L3, not at L0 load). |
| `severity` | yes | Display severity (`info`/`low`/`medium`/`high`/`critical`). Cannot be overridden per-record; if a single policy needs variable severity, split into multiple policies. |
| `category` | no | Free-form grouping label (e.g. `access_control`, `encryption`, `monitoring`). Used in summaries. |
| `evidence_mode` | **yes** | `automated` or `manual` — a required first-class field with **no default**. Missing → load fail (exit 3). `automated` collects from bound API source plugins and evaluates `pass_when:` (or the `rule:` escape hatch). `manual` binds `manual.pdf` and runs the universal PDF-presence check — `pass_when:` and `rule:` are ignored. Projects can override the framework default via project config. See §evidence_mode. |
| `cadence` | yes | How often the policy must be evaluated. One of `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual`, or the custom-interval form `every:<duration>` (`every:6h`, `every:90m`; 5-minute floor). A plain duration (`cadence: 24h`) is a config error. The CLI enforces cadence in scheduled mode via per-policy state shards — see [`10-cadence-model.md`](10-cadence-model.md). |
| `on_push` | no | Whether this policy is suitable for fast PR/push feedback. Defaults to `true` when `evidence_mode: automated`, `false` when `evidence_mode: manual`. CI workflows for on-push gates filter by this flag. |
| `description` | yes | Plain-English statement of what the policy asserts. |
| `remediation` | no | Plain-English remediation guidance, displayed alongside failures. |
| `slots` | conditional | Named typed inputs. **Required (≥1) when `evidence_mode: automated`; forbidden when `evidence_mode: manual`** (manual policies have no configurable slots — the planner binds the implicit `manual.pdf` slot). See §Slots. |
| `parameters` | no | Tunable per-project values. See §Parameters. |
| `pass_when` | conditional | Declarative condition DSL — the primary evaluation path. For `evidence_mode: automated`, exactly one of `pass_when:` or `rule:` is required. Forbidden when `evidence_mode: manual`. See §pass_when. |
| `rule` | conditional | Escape-hatch rule reference. Used only when `pass_when:` cannot express the logic. **`pass_when:` and `rule:` are mutually exclusive — declaring both is a load error (exit 3).** Must resolve in the rule registry (checked at L3). Unused by every shipped policy. See §Escape-hatch rule implementations. |
| `catalog_entry` | conditional | **Required when `evidence_mode: manual`** (there is no short-name default): the manual catalog entry ID that resolves to the PDF path. Forbidden for `automated` policies. |
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
    accepts: [directory_user]                # single-type slot, many sources
  buckets:
    accepts: [object_storage_bucket]         # single neutral type spans S3/GCS/Azure
```

The two examples above show the two real cross-vendor shapes. A
`directory_user` slot is satisfied by `aws.iam`, `okta`, and `github`
— three sources, one type. An `object_storage_bucket` slot is
satisfied by both `aws.s3` and `gcp.storage`, which **both emit the
same neutral type** — there are no separate `s3_bucket`/`gcs_bucket`
types. A genuinely multi-type `accepts:` list arises only when two
sources emit *different* registered types into one slot (the canonical
case being version migration — `accepts: [directory_user.v1,
directory_user.v2]`; see [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)
§Versioning).

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
the evaluator receives the **union** of all bound sources' records
under the slot. The records remain tagged with their `Type` and
`SourceID`. The `pass_when:` DSL treats the union as a flat set and
evaluates one condition tree over it; per-record `Type` is available
to filters and conditions via the `type` field if a clause needs it
(`{op: eq, field: type, value: directory_user.v2}`).

Branching on `source_id` for *behavior* is a code smell — it ties the
policy to a specific plugin ID and breaks substitutability. If logic
needs to know "this came from AWS rather than GCP," that distinction
should be encoded in the evidence `type` (or a normalized payload
field the plugin computes), not in `source_id`. See
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)
§The normalization boundary.

### When to add a new evidence type vs. extend an existing slot's `accepts:`

This decision comes up whenever a new backend appears for a check that
SigComply already supports. The full rubric (with the worked rationale)
lives in [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)
§Decision rubric. In brief:

- **Same logical entity, satisfiable by a shared schema → reuse the
  existing type.** AWS IAM, Okta, and GitHub all represent "a directory
  user," so they emit `directory_user`; AWS S3 and GCP storage both
  represent "an object storage bucket," so they emit
  `object_storage_bucket`. The slot keeps a single-type `accepts:` and
  the new plugin just adds itself to the bindings. This is the default
  and the most common path.
- **Same concept, structurally divergent fields that cannot share a
  schema → coin a new type and add it to `accepts:`.** This is rarer
  than it looks — the discipline in 04a is to design the schema
  top-down from the concept so the shared type *does* fit. When it
  genuinely cannot, the multi-type slot is the mechanism.
- **Different logical entity → keep slots separate.** A firewall rule
  in AWS is not the same entity as a GitHub branch protection rule.
  They go in different slots, not into one slot's `accepts:` list.

**Consequence.** Most slots have a single-element `accepts:` list,
because the neutral cross-vendor type usually covers all sources. A
multi-element list appears mainly during a version-migration window
(`accepts: [directory_user.v1, directory_user.v2]`).

### Cross-source dedup (clause-level `identity_key`)

The union is a **bag**, not a set. If Alice has an account in both AWS
IAM and Okta and a project's slot binds to `[aws.iam, okta]`, Alice's
two records arrive as two entries.

The `pass_when:` DSL deduplicates violations by a clause-level
`identity_key:`, which **defaults to `"id"`**. When two records that
both fail share the same value at the `identity_key` field, only one
violation is emitted. To dedupe by a cross-source identity instead of
the per-source ID, set `identity_key:` on the clause to a payload field
the plugins normalize consistently:

```yaml
pass_when:
  slot: user_directory
  quantifier: all
  identity_key: payload.email      # collapse the same human across sources
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
  violation_message: "MFA not enabled for {{.payload.display_name}}"
```

This dedup is **opt-in at the clause level and does NOT read the
evidence-type schema's identity_key** (the schema-level convention is
documentation only — see
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)). It
deduplicates the *violation list*, which in turn feeds
`resources_failed` in the `PolicyResult`. When `identity_key:` is
omitted, dedup is by `id` — correct for evidence types with no
cross-source identity (e.g. `firewall_rule`).

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
| `list_of_string` | `["a", "b"]` | Optional `item_pattern: <regex>` (parsed but not yet enforced) |
| `list_of_int` | `[1, 2, 3]` | |

### Effective values

The planner computes effective values as:

```
effective = policy.parameters.<name>.default
          ⊕ project_config.policies[policy_id].parameters.<name>
```

Validation runs against `min/max/enum/pattern`. Out-of-bounds values
cause a planning error (exit 3). The effective values are passed to the
evaluator and recorded in the per-policy `result.json` so auditors see
the exact thresholds used. (The run `manifest.json` is a minimal
integrity record — `file_hashes` plus run metadata — and does not carry
effective parameters; see [`05-vault-layout.md`](05-vault-layout.md).)

---

## evidence_mode

`evidence_mode` is a first-class field on every policy spec. It
controls the entire evidence collection and evaluation path for that
policy.

| Value | Collection | Evaluation |
|---|---|---|
| `automated` | Planner binds configured API source plugins to the policy's declared slots. The collector calls `plugin.Collect()` for each binding. | The evaluator runs the `pass_when:` condition DSL, or the `rule:` escape hatch if `pass_when:` is absent. |
| `manual` | Planner binds `manual.pdf` to an implicit slot, resolving the PDF path via `catalog_entry`. No API calls. | The evaluator runs the universal PDF-presence check: `file_present`, `in_temporal_window`, `file_valid`. `pass_when:` and `rule:` are ignored entirely. |

### Project-level override

Projects can override the framework default for any policy in
`.sigcomply.yaml`:

```yaml
policies:
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

`pass_when:` is the **primary evaluation path** for automated policies
— and the only one any shipped policy uses. It expresses "all records
must satisfy X" directly, no separate rule file. The evaluator
interprets it against the collected records from the policy's slot.

For logic the DSL cannot express (multi-slot joins, cross-record
aggregations, complex date computations not pre-computable by the
plugin), the `rule:` escape hatch is available (see §Escape-hatch rule
implementations). In practice, pre-computing derived fields in the
source plugin (e.g. emitting `age_days` instead of `last_rotation_at`)
eliminates most needs for the escape hatch — which is why no shipped
policy currently uses one.

`pass_when:` is ignored when `evidence_mode: manual`.

### Structure

A clause has a `quantifier`, a `condition` (the predicate tree), an
optional `filter` (another condition tree applied first), and an
optional `violation_message`. Conditions are **triples** —
`{op, field, value}` — never an `{op: ...}` shorthand keyed by the
operator.

```yaml
pass_when:
  slot: <slot_name>            # required on every clause
  quantifier: <all|none|any|count>
  filter:                      # optional: a condition tree; only records that
    op: <op>                   #   match it are passed to the quantifier
    field: <field_path>        #   (records whose filter field is absent are
    value: <literal|$params.x> #    excluded, never errored)
  condition:                   # required: the predicate evaluated per record
    op: <op>
    field: <field_path>
    value: <literal|$params.x>
  identity_key: <field_path>   # optional; default "id" — dedup key for violations
  min_percentage: <0-100>      # required iff quantifier == count; rejected otherwise
  violation_message: "<go template>"   # optional
```

### Quantifiers

| Quantifier | Semantics | Typical use |
|---|---|---|
| `all` | Every record in the (filtered) slot must satisfy `condition`. | MFA enforced, encryption at rest, branch protection enabled. |
| `none` | No record in the (filtered) slot may satisfy `condition`. | No buckets publicly accessible, no root API keys active. |
| `any` | At least one record must satisfy `condition` (an empty slot fails). | At least one audit trail enabled, at least one backup present. |
| `count` | At least `min_percentage`% of records must satisfy `condition`. | ≥90% of employees completed security training. |

### Conditions

A condition node is a triple. The leaf operators compare a record field
(LHS) against a `value` (RHS); the two compound operators nest a
`conditions:` list instead of a single field/value:

```yaml
# Equality / inequality
{ op: eq,  field: payload.mfa_enabled, value: true }
{ op: neq, field: payload.status,      value: "DELETED" }

# Numeric comparison (RHS may be a literal or a parameter ref)
{ op: lt,  field: payload.age_days, value: 90 }
{ op: lte, field: payload.age_days, value: "$params.max_age_days" }
{ op: gte, field: payload.min_length, value: 14 }

# Set membership
{ op: in,     field: payload.region,   value: ["us-east-1", "us-west-2"] }
{ op: not_in, field: payload.protocol, value: ["http", "ftp"] }

# Existence (field present and non-null) — the only op with no value
{ op: is_set, field: payload.kms_key_id }

# Compound — all_of (AND) / any_of (OR), nesting a conditions list
op: all_of
conditions:
  - { op: eq, field: payload.encryption_at_rest_enabled, value: true }
  - { op: eq, field: payload.public_access_blocked,       value: true }
```

The full operator set is `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`,
`not_in`, `is_set`, `all_of`, `any_of`.

**Field paths are explicit and prefixed.** A condition's `field`
resolves only `id`, `type`, `source_id`, or `payload.<dot.path>` (with
dot notation for nested payload fields, e.g.
`payload.encryption.key_id`). A bare field name without the `payload.`
prefix is *not found* and surfaces the policy as `error` — there is no
implicit payload scoping. A comparison against an absent field also
errors (rather than silently passing or failing); tolerate a
legitimately-absent field with `is_set` or by scoping it away in the
clause `filter`.

**Parameters are RHS-only.** Reference an effective parameter value as
the string `"$params.<name>"` on the `value` side. There is no
`{param: ...}` key, and the `field`/LHS side may never be a
`$params.*` reference.

### The `count` quantifier

```yaml
pass_when:
  slot: evidence
  quantifier: count
  min_percentage: 90          # ≥90% of records must satisfy the condition
  condition:
    op: eq
    field: payload.training_completed_this_year
    value: true
  violation_message: "training completion below threshold"
```

`min_percentage` (0–100) is **required for `count` and rejected for
every other quantifier**. `count` is the only quantifier with a
threshold knob; it is currently used by zero shipped policies (every
shipped check is `all`/`none`/`any`).

### Violation message templates

`violation_message` is a Go-template string. Substitution tokens are
`{{.payload.<field>}}` for payload fields (dot notation for nested
fields) and `{{.id}}` / `{{.type}}` / `{{.source_id}}` for the
top-level record fields. Unresolved tokens are left verbatim. There is
**no** `{token}` brace-only form and **no** parameter interpolation in
messages.

```yaml
violation_message: "user {{.payload.display_name}} ({{.id}}) does not have MFA enabled"
```

### Multi-slot policies

A policy with multiple slots provides a *list* of `pass_when:` clauses;
each names its own `slot:`. All clauses must pass for the policy to
pass:

```yaml
pass_when:
  - slot: buckets
    quantifier: all
    condition: { op: eq, field: payload.encryption_at_rest_enabled, value: true }
    violation_message: "bucket {{.payload.name}} is not encrypted at rest"
  - slot: trails
    quantifier: any
    condition: { op: eq, field: payload.enabled, value: true }
```

A clause evaluates against a single slot. Genuine cross-slot
conditions (e.g. "every user in slot A must appear in slot B") cannot
be expressed in the DSL and require the `rule:` escape hatch.

### Worked examples

These mirror real shipped checks (the Go builders in
`internal/frameworks/soc2/policies_cc6.go`); the YAML below is the
equivalent project-local form.

**MFA enforced on all users (service accounts scoped out by filter):**

```yaml
pass_when:
  slot: evidence
  quantifier: all
  filter:
    op: eq
    field: payload.is_service_account
    value: false
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
  violation_message: "user {{.payload.display_name}} does not have MFA enabled"
```

**Active access keys rotated within a configurable age limit:**

```yaml
pass_when:
  slot: evidence
  quantifier: all
  filter:
    op: eq
    field: payload.is_active
    value: true
  condition:
    op: lte
    field: payload.age_days
    value: "$params.max_age_days"
  violation_message: "access key {{.id}} exceeds the rotation age limit"
```

**At least one multi-region audit trail enabled:**

```yaml
pass_when:
  slot: evidence
  quantifier: any
  condition:
    op: all_of
    conditions:
      - { op: eq, field: payload.is_enabled,      value: true }
      - { op: eq, field: payload.is_multi_region, value: true }
  violation_message: "no enabled multi-region audit trail exists"
```

**No admin lacks MFA (none quantifier over a compound condition):**

```yaml
pass_when:
  slot: evidence
  quantifier: none
  condition:
    op: all_of
    conditions:
      - { op: eq, field: payload.is_admin,    value: true }
      - { op: eq, field: payload.mfa_enabled, value: false }
  violation_message: "admin user {{.payload.display_name}} does not have MFA enabled"
```

---

## Escape-hatch rule references

The `rule:` field is available for the rare cases that `pass_when:`
cannot express. **`pass_when:` and `rule:` are mutually exclusive** —
declaring both fails to load (exit 3), and so does declaring neither
when `evidence_mode: automated`. No shipped policy uses `rule:`; the
infrastructure exists for a future check the DSL cannot express.

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
cadence. Full algorithm in [`10-cadence-model.md`](10-cadence-model.md)
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

### Cadence enforcement vs explicit filters

The CLI enforces cadence in scheduled mode but never traps the
operator. When the operator passes an explicit filter flag
(`--cadence`, `--cadences`, `--on-push`, `--pr`, `--scheduled` — these
are mutually exclusive), that filter wins and the matching policies run
regardless of cadence state. The decision rule (full algorithm in
[`10-cadence-model.md`](10-cadence-model.md)) puts an explicit filter
at the top: branch 1 is "filter is explicit → evaluate," ahead of the
content-hash and due-time branches.

PR mode (`sigcomply check --pr`) and the default invocation
(`sigcomply check`) don't gate on cadence — every in-scope policy
evaluates. Cadence gating is strictly a scheduled-mode behavior.

Effective cadence = `project_config.policies[id].cadence` if set, else
`policy.cadence`. Per-policy state captures the effective cadence at
the time of the last evaluation so a later run can detect a
configuration change.

### Project override pattern

A project can override a shipped policy's cadence in its
`.sigcomply.yaml`:

```yaml
policies:
  soc2.cc6.1.mfa_enforced:
    cadence: hourly                     # tighten — we care about drift
  soc2.cc6.6.public_access_blocked:
    cadence: continuous
  soc2.cc1.2.code_of_conduct_attested:
    cadence: annual                     # loosen — we attest yearly
```

The full reference (precedence, validation, interaction with the
cadence filter flags) lives in [`08-project-config.md`](08-project-config.md).

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

The quarterly CI workflow (`.github/workflows/compliance-quarterly.yml`,
scaffolded by `sigcomply init-ci`) runs `sigcomply check --cadence
quarterly` once per quarter on the calendar boundary plus grace. The
on-push workflow never sees this policy because `on_push: false`. A
scheduled run is the gating mechanism — there is no `--policies`
operator filter flag on `check`; the in-scope set is selected by the
cadence/on-push filter flags (see [`09-ci-execution-model.md`](09-ci-execution-model.md)).

---

## Escape-hatch rule implementations

The `rule:` field is used only when `pass_when:` cannot express the
policy logic. If you find yourself reaching for `rule:`, first ask:
can the source plugin pre-compute the derived field that makes the
condition expressible in the DSL? Usually it can.

> **Shipped status.** No shipped policy uses `rule:` — both frameworks'
> `Rules()` return nil, so the rule registry is empty in practice. The
> rule types live in `internal/core` (there is no `internal/core/rule`
> package). The two flavors below describe the available surface.

**When to use `rule:` instead of `pass_when:`:**
- Cross-slot conditions: "every user in slot A must exist in slot B"
- Multi-record aggregations the plugin cannot pre-compute
- Pass/fail logic that requires reasoning across the record set as a
  whole (not per-record)

### Flavor 1 — Go

Go rules implement `core.Rule` and are registered through a framework's
`Rules()` method (the only mechanism that populates the per-`Set` rule
registry). **There is no project-local Go-rule registration hook today**
— a customer cannot drop a `rule.go` under `.sigcomply/` and have it
load. Project-local *Rego* rules and project-local *YAML policies* do
load; project-local Go rules are not wired (see §Project-local custom
policies and [`07-extensibility.md`](07-extensibility.md)).

```go
type Rule struct{}

func (Rule) ID() string { return "rules.complex_check.v1" }

func (Rule) Evaluate(ctx context.Context, in core.RuleInput) (core.RuleResult, error) {
    // Full Go expressiveness: joins, time math, cross-record logic.
    // Must be deterministic. Must not perform I/O.
    var violations []core.Violation
    // ...
    return core.RuleResult{ /* Status, Violations */ }, nil
}
```

A framework returns its Go rules from `Rules()`; the registry builder
registers them per framework `Set`. Both shipped frameworks return
`nil`.

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

Rules receive parameters for every declared parameter, always populated
(default if not overridden by project config).

---

## Testing policies

Framework-shipped policies are Go values and are exercised by ordinary
Go tests under `internal/frameworks/<fw>/` (and by the evaluator's own
tests against the `pass_when:` DSL). There are **no per-policy
`tests/` directories** and no `sigcomply test policies` command. The
DSL evaluator is unit-tested directly; the policy tables are validated
at build time (e.g. every accepted evidence type must have a registered
emitter — `internal/sources/builtin/coverage_test.go`).

---

## Policy versioning and lifecycle

- A framework ships exactly one current spec per policy ID.
- The escape-hatch `rule:` reference carries a version
  (`rules.X.v1`); when a rule's `.v2` would ship, the policy spec
  points at it and old runs in the vault retain the prior
  `rule_version` in their `result.json`, so prior results stay
  interpretable. (No shipped policy uses `rule:` today, so this is
  forward-looking.)
- A policy can be removed entirely from a framework only at a major
  framework version bump.

---

## Project-local custom policies

A customer can author policies under
`.sigcomply/policies/<id>/policy.yaml` using the logical spec above.
This on-disk YAML is the only `policy.yaml` form — framework policies
are Go. The loader merges project-local policies into the registry
alongside the framework-shipped ones. Conventions for custom policy IDs:

- Use a customer-specific prefix: `acme.custom.cc6.1.contractor_review`
- Reference framework controls if applicable (`control: SOC2.CC6.1`)
- The escape hatch a project-local policy may use is **Rego** (`rule:`
  resolving to a project-local `rule.rego`); project-local Go rules are
  not wired. A project-local policy may also reference a
  framework-shipped rule by name if the slots align.

A project-local `policy.yaml` is loaded with the same strict validation
as any spec: `evidence_mode` is **required** (no automated default),
`cadence` is required, and the `slots`/`pass_when`/`rule`/`catalog_entry`
combination rules above all apply. `on_push` is the only field with an
implicit default (true for automated, false for manual). There is no
"omit and we'll guess `evidence_mode`" behavior — a missing
`evidence_mode` fails the load (exit 3).

Custom policies appear in run output and submission payloads just like
framework-shipped policies. They do not affect framework version pins.

See [`07-extensibility.md`](07-extensibility.md) for the full
extension workflow.
