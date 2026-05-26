# 04a — Evidence Type Registry

The evidence-type registry is the mediator between policies and source
plugins. Policies declare which types they accept (`slots.*.accepts:
[...]`); source plugins declare which types they emit
(`Emits() []string`). Neither side knows about the other. The registry
is the only point of contact between the policy world and the source
world.

This is what makes the architecture cross-vendor. A single
"object-storage encrypted at rest" policy is satisfied by `aws.s3`
emitting `s3_bucket`, `gcp.storage` emitting `gcs_bucket`, or a future
`azure.blob` plugin emitting `azure_blob_container` — no policy fork,
no source-side normalization, no lowest-common-denominator schema.
Adding a new vendor is two artifacts: a source plugin and an evidence
type. The policies that already accepted that type now accept the new
vendor by transitivity.

This document specifies how evidence types are declared, embedded,
loaded, validated, versioned, and extended. Read
[`04-source-plugins.md`](04-source-plugins.md) and
[`03-policy-spec.md`](03-policy-spec.md) first if you haven't —
this document fills in the registry mechanics those two refer to.

---

## Current implementation status

This document describes the target design. Several pieces are simpler
in code than they are below; this table calls out the gaps so the rest
of the document can be read as design intent without misleading on
what's wired today.

| Aspect | Status | Notes |
|---|---|---|
| File format | **JSON Schema documents** | Schemas live at `internal/evidence_types/schemas/<id>.v<n>.json` — the file *is* a JSON Schema with extension fields (`title` used as the type ID, `version` for the type version). There is no separate YAML frontmatter wrapper. The YAML-with-frontmatter form described in §File format below is design intent, not current code. |
| Embedding | **Wired** | `//go:embed schemas/*.json` in `internal/evidence_types/loader.go`; merged into the `EvidenceTypeRegistry` at orchestrator bootstrap. |
| Schema-conformance validation | **Wired (minimal subset)** | The collector calls `evidence_types.Validate` before signing each envelope (`internal/collector/collector.go:134`). The current validator supports `type: object` at top level, `required: [...]`, and per-property `type` (`string`/`boolean`/`integer`/`number`/`object`/`array`). `format` (email, date-time, …), `enum`, `const`, `pattern`, length/range, `items`, nested-object recursion, `additionalProperties: false`, and composition (`oneOf`/`anyOf`/`allOf`) are **not** yet enforced — schemas may declare them, but those constraints are advisory until a richer validator lands. |
| Validation failure handling | **Wired (strict)** | The collector fails the binding on the first non-conforming record (exit 3 via the policy's error tag). The ">5% of records in a call" percentage cutoff described in §Schema-conformance validation is design intent for a future, more permissive mode; today behavior is "first failure errors the binding." |
| Planner check that a slot's `accepts:` only references registered types | **Wired** | Empty `source.Emits() ∩ slot.Accepts` fails at plan time (exit 3) in `internal/planner/bindings.go`. |
| Project-local evidence types under `.sigcomply/evidence_types/` | **Planned (roadmap M16)** | Today only embedded in-tree types load. The path to ship project-local types alongside project-local plugins is part of `sigcomply build`. |
| Per-type `identity_key` metadata in the schema file | **Not parsed** | `EvidenceRecord.IdentityKey` is fully wired and used by plugins (`aws.iam`, `okta`, `github`, etc. — see `core.EvidenceRecord`); rule-side dedup operates on it. The schema-level `identity_key.meaning` frontmatter described in §The cross-source identity story is not parsed today — for now, the convention is documented in the schema's `description` text instead. |

Bottom line: the load-bearing pieces (registry, embedded loading, planner check, basic schema validation, per-record identity for dedup) are wired and used in production today. The remaining items in the table above are deliberate v1 simplifications, not architectural gaps.

---

## Why evidence types are a separate artifact

In an earlier iteration of the design, each source package declared
its own `const EvidenceTypeID = "user_record"` as a bare string and
nothing else. There was no schema, no central registration, and
nothing prevented two sources from disagreeing about what `user_record`
meant. The current design fixes this by making evidence types
first-class artifacts:

- They live in their own directory (`internal/evidence_types/`)
  alongside (but separate from) the source plugins.
- They carry versioned JSON Schemas.
- They are embedded into the binary via `go:embed` so the registry is
  trivially deterministic — no filesystem search at runtime.
- The collector validates every emitted record's payload against the
  registered schema. A source that emits a malformed payload causes
  the policy depending on it to surface as `error`, not as a silent
  pass.

The separation has three consequences:

1. **A new vendor for an existing check is two artifacts.** Write the
   source plugin emitting `s3_bucket` (or whatever existing type
   fits); register it; done. The policies already accepting that type
   pick up the new vendor with zero code changes.
2. **Two sources cannot disagree about a type.** If `aws.iam` and
   `okta` both emit `user_record`, both must conform to the same
   schema. The collector enforces this — a payload that doesn't
   validate is dropped (or, in volume, errors out the whole
   collection).
3. **Policies can rely on payload fields.** A policy declaring
   `accepts: [user_record]` is guaranteed to receive records whose
   payloads have a `mfa_enabled` field (because the schema makes it
   required). No defensive `if record.payload.mfa_enabled != nil`
   checks; the schema is the precondition.

---

## File format

Evidence types are YAML files under `internal/evidence_types/<id>.yaml`
(in-tree) or `.sigcomply/evidence_types/<id>.yaml` (project-local). One
file per type per version.

```yaml
# internal/evidence_types/user_record.v1.yaml
schema_version: evidence_type.v1

id: user_record
version: 1
title: "User Record"
description: |
  A human or service-account user from an identity provider. Used by
  policies that verify MFA enforcement, access-key rotation, and
  similar identity-centric controls. Plugins emitting this type
  include aws.iam, gcp.iam, okta, github, and bamboohr.

identity_key:
  meaning: "email"
  description: |
    Cross-source dedup key. When a record is emitted for the same
    human from multiple sources (e.g. alice@acme.com exists in both
    AWS IAM and Okta), plugins should set EvidenceRecord.IdentityKey
    to the user's email to enable rule-level deduplication. See
    03-policy-spec.md §Cross-source dedup.

schema:
  $schema: "http://json-schema.org/draft-07/schema#"
  type: object
  required: [id, mfa_enabled]
  properties:
    id:
      type: string
      description: "Stable ID within the source (ARN, Okta user ID, etc.)."
    email:
      type: string
      format: email
    display_name:
      type: string
    mfa_enabled:
      type: boolean
    is_service_account:
      type: boolean
    is_admin:
      type: boolean
    last_used_at:
      type: string
      format: date-time
    created_at:
      type: string
      format: date-time
  additionalProperties: true
```

### Frontmatter fields

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | Always `evidence_type.v1` for v1 of this meta-format. |
| `id` | yes | The evidence type's stable identifier. Lowercase, snake_case, no version suffix on the ID itself — the version lives in the `version` field. |
| `version` | yes | Integer version. New versions are independent registrations (see §Versioning). |
| `title` | yes | Human-readable label for tooling and reports. |
| `description` | yes | What this type represents, why it exists, who emits it. Aimed at the next maintainer or third-party plugin author. |
| `identity_key.meaning` | no | When the type has a meaningful cross-source identity, names what it represents (`email`, `employee_id`, `resource_arn`). When omitted, plugins should leave `IdentityKey` unset. |
| `identity_key.description` | no | Free-form note expanding on `meaning`. |
| `schema` | yes | JSON Schema (Draft-07 subset) describing the `payload` field of an `EvidenceRecord` of this type. |

### Schema subset

The collector uses a JSON Schema Draft-07 validator. The supported
keywords are the subset that's stable across implementations:

- Type predicates: `type`, `required`, `properties`,
  `additionalProperties`, `patternProperties`, `items`, `minItems`,
  `maxItems`, `uniqueItems`.
- String constraints: `minLength`, `maxLength`, `pattern`, `format`
  (with `email`, `date-time`, `uri`, `ipv4`, `ipv6`).
- Number constraints: `minimum`, `maximum`, `exclusiveMinimum`,
  `exclusiveMaximum`, `multipleOf`.
- Composition: `enum`, `const`, `oneOf`, `anyOf`, `allOf`.

Keywords outside this list (`$ref` across files, `if`/`then`/`else`,
custom `format` values) are not supported in v1; a schema using them
fails to load with exit 3 at bootstrap.

---

## Embedding and loading

In-tree evidence types are embedded into the binary at compile time:

```go
// internal/evidence_types/embed.go
package evidence_types

import "embed"

//go:embed *.yaml
var FS embed.FS
```

At orchestrator bootstrap, the registry walks `FS`, parses each YAML
file, validates the meta-schema (frontmatter shape + the JSON Schema
itself being well-formed), and registers each type by its `id`. After
bootstrap, the registry is read-only — see
[`02-layers.md`](02-layers.md) §L2.

```go
// internal/registries/evidence_types.go (sketch)
type EvidenceTypeRegistry interface {
    Lookup(id string) (core.EvidenceType, bool)
    Validate(id string, payload json.RawMessage) error
    All() []core.EvidenceType
}
```

Project-local types under `.sigcomply/evidence_types/` are loaded the
same way, just from the project filesystem rather than the embedded
FS. They merge into the same registry. A project-local file
attempting to redefine an in-tree type ID fails at bootstrap with
exit 3 — types are append-only across the union of in-tree and
project-local sets.

---

## Schema-conformance validation

Validation happens once per emitted record, inside the collector,
before the record is wrapped in an envelope:

| Outcome | Action |
|---|---|
| Record's `Payload` validates against the schema for `Type` | Included in the envelope. |
| Single record fails validation | Dropped; logged in envelope diagnostics with the offending field path. |
| >5% of records from a (plugin, slot) call fail | The whole call is marked `error`; policies depending on it become `error` status (not silent partial results). |
| `Type` not in `EvidenceTypeRegistry` | Plan-time error, exit 3 (caught before any `Collect` runs). |
| `Type` not in the slot's `accepts:` list | Plan-time error, exit 3 (the planner refuses to bind a source for an unaccepted type). |

This is what makes substitutability **safe**. A policy author can rely
on the fields the schema declares because the collector refuses to
pass through malformed records. A plugin author can refactor freely
within the schema constraints because misalignments are caught
deterministically at run time, not weeks later when an unexpected
field shape silently makes a policy pass-by-vacuity.

**Schema-conformance failures are configuration errors, not runtime
errors.** They mean the plugin (or its config) is producing data the
registered type doesn't describe. The fix is in the plugin code or in
the schema, not at evaluation time. Exit code 3 makes this
unambiguous to CI.

---

## Versioning rule: schemas are append-only

Within a single version, schemas may only grow:

- **Adding an optional property** → same version. New plugins that
  emit it can be consumed by old policies that ignore it; old plugins
  that don't emit it still validate.
- **Loosening a constraint** (raising `maxLength`, widening an
  `enum`) → same version, as long as existing valid records remain
  valid.

Any of the following requires a new version:

- Removing a property.
- Renaming a property.
- Changing a property's type.
- Adding a property to `required`.
- Tightening a constraint such that previously-valid records fail.

A new version is a **new registration** with a distinct ID convention:
`user_record.v2`, registered as a separate file
(`user_record.v2.yaml`). Both `user_record.v1` and `user_record.v2`
coexist in the registry. Plugins emit one specific version per record
(by setting `Type` to e.g. `user_record.v1`). Policies accept one or
both versions in their `accepts:` list during migration windows:

```yaml
# during migration, accept both
slots:
  user_directory:
    accepts: [user_record.v1, user_record.v2]
```

This is the same multi-type slot mechanism described in
[`03-policy-spec.md`](03-policy-spec.md) §Slots — version migration is
just one application of it.

A type is **never silently mutated.** A schema change that breaks
existing records always coins a new ID. The vault written in 2026
remains interpretable in 2031 because the schema referenced by
`Type` in each record still loads.

---

## The cross-source identity story

When an evidence type represents an entity that can exist in multiple
source systems, plugin authors set `EvidenceRecord.IdentityKey` to a
cross-source-stable value (typically email for users, perhaps
`employee_id` for HR records). The type's frontmatter documents the
meaning:

```yaml
identity_key:
  meaning: "email"
```

This:

1. Tells plugin authors what to put in `IdentityKey` (no ambiguity
   between "use the email" vs "use the employee_id").
2. Tells rule authors that records of this type may legitimately
   appear from multiple sources for the same logical entity, so they
   should dedupe before counting.
3. Interacts with cardinality: in a `cardinality: one-or-more` slot
   bound to multiple sources, dedup-by-`IdentityKey` reduces the bag
   of records to a set of entities. The `resources_evaluated` count
   in the aggregation contract reflects the deduplicated count, so
   the compliance score input correctly represents "47 unique humans
   evaluated" rather than "47 + duplicates."

For evidence types where there is no meaningful cross-source identity
(e.g. `firewall_rule` — a rule in AWS is not the same rule as a rule
in GCP, even if both happen to allow port 22), omit `identity_key:`
in the frontmatter and leave `IdentityKey` unset on records. Rules
consuming the type then treat the union as a bag, not a set.

Full dedup mechanics — Go and Rego helpers, when shipped rules
auto-dedupe — live in [`03-policy-spec.md`](03-policy-spec.md)
§Cross-source dedup.

---

## A concrete worked example

A full `user_record` schema file as it would appear in-tree:

```yaml
# internal/evidence_types/user_record.v1.yaml
schema_version: evidence_type.v1

id: user_record
version: 1
title: "User Record"
description: |
  A human or service-account user from an identity provider. Used by
  policies that verify MFA enforcement, access-key rotation, dormant
  accounts, and similar identity-centric controls. Plugins emitting
  this type include aws.iam, gcp.iam, okta, github, and bamboohr.

identity_key:
  meaning: "email"
  description: |
    Used to deduplicate across sources when the same human has
    accounts in multiple identity providers. Plugins SHOULD populate
    EvidenceRecord.IdentityKey with the user's primary email for
    each emitted record. For service accounts (where there's no
    email), leave IdentityKey unset.

schema:
  $schema: "http://json-schema.org/draft-07/schema#"
  type: object
  required: [id, mfa_enabled]
  properties:
    id:
      type: string
      description: "Stable ID within the source. e.g. an AWS IAM user ARN, an Okta user ID, a GitHub login."
    email:
      type: string
      format: email
    display_name:
      type: string
    mfa_enabled:
      type: boolean
    is_service_account:
      type: boolean
    is_admin:
      type: boolean
    last_used_at:
      type: string
      format: date-time
    created_at:
      type: string
      format: date-time
    groups:
      type: array
      items: { type: string }
  additionalProperties: true
```

A plugin emitting this type:

```go
// inside aws.iam.Collect(...)
records = append(records, core.EvidenceRecord{
    Type:        "user_record",
    ID:          "AIDAEXAMPLE01",                 // AWS-local
    IdentityKey: "alice@acme.com",                 // cross-source
    SourceID:    "aws.iam",
    CollectedAt: now,
    Payload:     mustMarshal(map[string]any{
        "id":          "AIDAEXAMPLE01",
        "email":       "alice@acme.com",
        "mfa_enabled": false,
        "is_admin":    true,
        "last_used_at": "2026-05-20T09:14:00Z",
    }),
})
```

The collector validates each `Payload` against the registered schema.
Records pass through; malformed records are dropped (or, in volume,
the whole call errors out).

A policy declaring `accepts: [user_record]` can rely on `mfa_enabled`
existing and being a boolean on every record it sees. No defensive
checks; the registry is the precondition.

---

## Schema design: top-down from concept, not bottom-up from a vendor's API

This is the most consequential design decision when defining a new
evidence type. Getting it right makes every future source addition
trivial. Getting it wrong silently breaks the substitutability property
— often only discovered when a second vendor is being added and the
original schema turns out to be shaped around one vendor's API.

### The core discipline

A cross-vendor evidence type represents a *semantic domain concept* —
"a user in a directory," "an object storage bucket," "a source code
repository." Schema fields describe **what that concept universally
is**, not what one vendor's API happens to return.

**Wrong (bottom-up — modeled directly from AWS IAM's API response):**

```json
{
  "UserName": "alice",
  "Arn": "arn:aws:iam::123456789:user/alice",
  "MFADevices": [
    { "SerialNumber": "arn:aws:iam::123456789:mfa/alice", "EnableDate": "2024-01-15T09:00:00Z" }
  ],
  "PasswordLastUsed": "2026-05-20T09:14:00Z"
}
```

Okta, Azure AD, and Google Workspace cannot provide `Arn`, `MFADevices`,
or `PasswordLastUsed` without fabricating values. Any field that only
one vendor can populate meaningfully is the wrong level of abstraction
for a shared schema.

**Right (top-down — modeled from the concept "a directory user"):**

```json
{
  "id": "alice",
  "email": "alice@example.com",
  "mfa_enabled": true,
  "is_admin": false
}
```

Every directory system can answer "does this user have MFA enabled?"
The plugin for each vendor translates its native representation into
this canonical boolean. `mfa_enabled` is universal;
`MFADevices[].SerialNumber` is an AWS IAM artifact.

The shipped schemas in `internal/evidence_types/schemas/` —
`directory_user.v1.json`, `object_storage_bucket.v1.json`,
`git_repository.v1.json` — are concrete examples of this discipline
applied consistently. Read them before designing a new cross-vendor
type.

### The universal-field test

Before adding a field to a cross-vendor schema, apply this test:

> Can **every** plausible implementation of this concept provide this
> field with a meaningful, non-null value? If not, can it be safely
> optional — with documented semantics for what "absent" means to a
> policy consumer?

Applied to `directory_user` as illustration:

| Field | Universal? | Declaration |
|-------|-----------|-------------|
| `mfa_enabled: boolean` | Yes — all directories have this concept | `required` |
| `is_admin: boolean` | Yes — all directories have an elevated-privilege concept | optional (absent = unknown) |
| `email: string` | Mostly — not every system exposes email | optional (absent = unknown) |
| `iam_path: string` | No — AWS IAM only | does not belong in the shared schema |
| `okta_login: string` | No — Okta only | does not belong in the shared schema |

**The schema author must survey at least two or three plausible
implementations before declaring a field required.** Designing from a
single implementation and hoping the rest will fit is how bottom-up
schemas happen.

### The normalization boundary

The source plugin owns **100% of the translation** from vendor API
shape to canonical schema shape. Zero normalization belongs in policy
Rego.

Policy code must never contain:

- `record.type == "aws_iam_user"` — branching on source
- `count(record.mfa_devices) > 0` — re-deriving a computed field the
  plugin should have computed
- `record.arn != null` — gating on a vendor-specific field

Every one of these is a symptom that vendor-specific shape leaked into
policy code. The fix is always in the plugin, not the Rego.

How the `aws.iam` plugin handles MFA:

```
AWS IAM API returns: MFADevices: [{SerialNumber: "...", ...}]
Plugin computes:     mfa_enabled = len(mfaDevices) > 0
Plugin emits:        {"mfa_enabled": true}
Policy sees:         record.mfa_enabled == true
```

How the Okta plugin handles MFA:

```
Okta API returns:    factors: [{status: "ACTIVE", ...}]
Plugin computes:     mfa_enabled = any(factor.status == "ACTIVE")
Plugin emits:        {"mfa_enabled": true}
Policy sees:         record.mfa_enabled == true
```

Same policy, different plugins, identical Rego. That is the whole
point of the substitutability property.

### The null-trap antipattern

What happens when a schema is designed bottom-up and a second vendor
is forced to fit it:

1. A required field in the schema cannot be meaningfully populated by
   the new vendor.
2. The plugin author sets it to `null`, `""`, or `0` to satisfy schema
   validation.
3. Policy authors add `if field != null` guards to avoid false
   failures.
4. Those guards are implicit source-dispatching: the policy now
   silently behaves differently depending on which source is bound.
5. Substitutability is broken. Two sources nominally satisfying the
   same evidence type produce semantically different policy outcomes,
   and the discrepancy is invisible in CI.

**The fix is not to add null guards in Rego.** The fix is to find the
offending schema field and either:

- Relax it to optional, with clear documentation of what "absent"
  means for policy consumers.
- Move it to `additionalProperties` — vendor-specific extras that no
  policy depends on.
- Create a vendor-specific evidence type for the source that can't
  satisfy the universal schema (see §Two-tier type taxonomy).

`"additionalProperties": true` in the schema is the sanctioned escape
hatch for vendor-specific data that policies should never branch on.

### Two-tier type taxonomy

Both tiers are legitimate. The discipline is knowing which to use.

| Tier | Naming | Example | Use when |
|------|--------|---------|----------|
| **Semantic** (cross-vendor) | No vendor prefix | `directory_user`, `object_storage_bucket`, `git_repository` | The concept exists in ≥2 vendors and all required fields are universally satisfiable |
| **Vendor-specific** | Vendor prefix | `aws_cloudtrail_event`, `gcp_vpc_flow_log` | The concept is genuinely unique to one vendor's data model |

A policy accepting a semantic type is universally portable across every
source that emits it. A policy accepting a vendor-specific type is
honestly scoped and can use the full native API shape without
normalization constraints.

**Do not use vendor-specific types as an escape hatch from schema
design.** When a concept *could* be cross-vendor but the first
implementation was modeled bottom-up from a single API, shipping a
vendor-prefixed type defers the cost instead of eliminating it: every
future vendor for the same concept requires a new type and a policy
fork. The substitutability property costs one careful design decision
at schema-definition time, paid back at every subsequent source
addition.

### The "wrong schema" signal

The clearest diagnostic that a schema was designed bottom-up:
**implementing a second plugin for the same evidence type requires
setting a required field to null or a meaningless sentinel.**

If you're writing the Okta plugin and `directory_user.v1` has a
required field `iam_path` that Okta has no equivalent for, the schema
is wrong — not the plugin. Fix the schema (move `iam_path` to optional
or remove it), update the AWS plugin accordingly, and coin a v2 if the
change is breaking per §Versioning rule above.

Do not paper over a bad schema by emitting `null`, `""`, `0`, or
`false` where the vendor doesn't support the concept. That path ends
in silent policy miscounts that are difficult to trace to their root
cause.

---

## Decision rubric: new type vs. extend `accepts:`

This is the same rubric as in
[`03-policy-spec.md`](03-policy-spec.md) §When to add a new evidence
type vs. extend an existing slot's `accepts:`, repeated here for
discoverability when reading from the evidence-type-author's angle:

- **Same logical entity, same fields.** Reuse the existing type. The
  new plugin just emits it; no schema change, no slot change.
- **Same logical entity, structurally divergent fields.** Coin a new
  type. The relevant slots add the new type to their `accepts:` list.
  Rules switch on `record.Type` where they must, ignore the
  distinction otherwise.
- **Different logical entity.** Different slot entirely; do not lump
  the type into someone else's slot just because the cardinality
  feels similar.

A useful test for "same entity vs. different entity": ask whether a
human reviewing the result of a policy would naturally describe the
records together ("47 buckets across our clouds") or describe them
separately ("3 AWS firewall rules and 8 GitHub branch protections" —
two separate things). The first case wants one slot with multiple
accepted types. The second wants two slots.

Coin a new type rather than overfitting an existing one when in
doubt — types are cheap (one YAML file), and a too-broad type that
later needs to split is far more disruptive than two narrow types
that converge.

---

## Project-local extension

Customers can add evidence types under `.sigcomply/evidence_types/`
using the identical file format:

```
.sigcomply/
  evidence_types/
    acme_internal_user.v1.yaml         # custom shape for acme.internal_iam
```

These are loaded at bootstrap alongside in-tree types and merged into
the same registry. Project-local plugins reference them in `Emits()`
and project-local policies reference them in `accepts:`.

A project-local file attempting to redefine an in-tree type ID fails
at bootstrap with exit 3. Project-local types are append-only across
the union; the upstream-curated set is not overridable. This is the
same rationale as framework specs being non-overridable — auditors
need to trust that a shipped `user_record` means the shipped thing,
not a customer-tweaked variant.

The path from a project-local type to an upstream contribution is in
[`07-extensibility.md`](07-extensibility.md) §Contributing back
upstream.

---

## See also

- [`01-conceptual-model.md`](01-conceptual-model.md) §6 Evidence type
  and §Axiom 1 — the conceptual framing.
- [`02-layers.md`](02-layers.md) §L2 — the registry mechanism.
- [`03-policy-spec.md`](03-policy-spec.md) §Slots — how `accepts:`
  consumes types from this registry.
- [`04-source-plugins.md`](04-source-plugins.md) §The factory contract
  — how plugins produce records validated against this registry.
- [`07-extensibility.md`](07-extensibility.md) — project-local types,
  custom plugins, contribution path.
