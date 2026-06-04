# 04a — Evidence Type Registry

The evidence-type registry is the mediator between policies and source
plugins. Policies declare which types they accept (`slots.*.accepts:
[...]`); source plugins declare which types they emit
(`Emits() []string`). Neither side knows about the other. The registry
is the only point of contact between the policy world and the source
world.

This is what makes the architecture cross-vendor. A single
"object-storage encrypted at rest" policy is satisfied by `aws.s3` and
`gcp.storage`, which **both emit the same neutral type**
`object_storage_bucket` — no policy fork, no per-vendor type, no
lowest-common-denominator schema. Adding a new vendor for an
already-modeled concept is usually a single artifact: a source plugin
emitting the existing type. The policies that already accept that type
pick up the new vendor by transitivity.

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
| File format | **JSON Schema documents** | Schemas live at `internal/evidence_types/schemas/<id>.v<n>.json` — the file *is* a JSON Schema. The type ID is the schema's `title`; the version is its `version` field. There is **no** `schema_version`/`id`/`identity_key` frontmatter that is parsed. The YAML-with-frontmatter form once described below is not the shipped form; the §File format section below shows the real JSON shape. |
| Embedding | **Wired** | `//go:embed schemas/*.json` in `internal/evidence_types/loader.go`; merged into the registry at orchestrator bootstrap. |
| Schema-conformance validation | **Wired (full draft-07)** | The collector calls `evidence_types.Validate` before signing each envelope. The validator is **full JSON Schema draft-07** via `github.com/xeipuuv/gojsonschema` (`internal/evidence_types/validate.go`), content-hash cached: `enum`, `format`, `pattern`, `minimum`/`maximum`, length/range, `items`, nested-object recursion, and composition are all enforced — not just `type`/`required`. |
| Validation failure handling | **Wired (strict)** | The collector fails the binding on the **first** non-conforming record (exit 3 via the policy's error tag). There is **no** drop-and-continue and **no** ">5% of records" threshold — that permissive mode is design-intent only, not implemented. |
| Planner check that a slot's `accepts:` only references registered types | **Wired** | Empty `source.Emits() ∩ slot.Accepts` fails at plan time (exit 3). |
| Project-local evidence types under `.sigcomply/evidence_types/` | **Planned** | Today only embedded in-tree types load. Shipping project-local types alongside project-local plugins is part of `sigcomply build`, not yet wired. |
| Per-type `identity_key` metadata in the schema file | **Not parsed** | `EvidenceRecord.IdentityKey` is wired and set by plugins (`aws.iam`, `okta`, `github`, …), and the `pass_when:` DSL deduplicates via a clause-level `identity_key:`. A *schema-level* `identity_key` is **not parsed** — the convention lives in the schema's `description` text only. |

Bottom line: the load-bearing pieces — registry, embedded loading, planner check, full draft-07 validation, per-record identity for dedup — are wired and used in production today. The remaining items above are deliberate v1 simplifications, not architectural gaps.

---

## Why evidence types are a separate artifact

In an earlier iteration of the design, each source package declared
its own `const EvidenceTypeID = "directory_user"` as a bare string and
nothing else. There was no schema, no central registration, and
nothing prevented two sources from disagreeing about what
`directory_user` meant. The current design fixes this by making
evidence types first-class artifacts:

- They live in their own directory
  (`internal/evidence_types/schemas/`), separate from the source
  plugins.
- They are versioned JSON Schemas.
- They are embedded into the binary via `go:embed` so the registry is
  trivially deterministic — no filesystem search at runtime.
- The collector validates every emitted record's payload against the
  registered schema. A source that emits a malformed payload causes
  the policy depending on it to surface as `error`, not as a silent
  pass.

The separation has three consequences:

1. **A new vendor for an existing check is usually one artifact.**
   Write the source plugin emitting `object_storage_bucket` (or
   whatever existing type fits); register it; done. The policies
   already accepting that type pick up the new vendor with zero code
   changes.
2. **Two sources cannot disagree about a type.** If `aws.iam` and
   `okta` both emit `directory_user`, both must conform to the same
   schema. The collector enforces this — the first payload that
   doesn't validate errors the binding (exit 3); there is no
   silent drop.
3. **Policies can rely on payload fields.** A policy declaring
   `accepts: [directory_user]` is guaranteed to receive records whose
   payloads have an `mfa_enabled` field (because the schema makes it
   required). No defensive null checks; the schema is the precondition.

---

## File format

Evidence types are **JSON Schema documents** under
`internal/evidence_types/schemas/<id>.v<n>.json` (in-tree). The file
*is* a JSON Schema — there is no separate metadata wrapper. Two
extension fields carry the registry metadata: `title` holds the type ID
(e.g. `"directory_user.v2"`) and `version` holds the integer version.
One file per type per version. (Project-local types under
`.sigcomply/evidence_types/` use the same JSON form; that path is
planned, not yet shipped — see the status table.)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://schemas.sigcomply.io/evidence_types/directory_user/v1.json",
  "title": "directory_user.v1",
  "version": 1,
  "description": "Cross-vendor identity record. A human or service-account user from an identity provider, used by policies that verify MFA enforcement, access-key hygiene, and dormant-account controls. Plugins emitting this type include aws.iam, okta, and github. Cross-source dedup key (convention only — not parsed): email.",
  "type": "object",
  "required": ["id", "mfa_enabled"],
  "properties": {
    "id":                 { "type": "string", "description": "Stable ID within the emitting source." },
    "email":              { "type": "string" },
    "display_name":       { "type": "string" },
    "mfa_enabled":        { "type": "boolean" },
    "is_service_account": { "type": "boolean" },
    "is_admin":           { "type": "boolean" },
    "last_login_at":      { "type": "string" },
    "created_at":         { "type": "string" }
  },
  "additionalProperties": true
}
```

### Registry metadata fields

| Field | Required | Description |
|---|---|---|
| `title` | yes | The type ID, **with** its version suffix (`directory_user.v2`). This is what the registry keys on and what plugins set as `record.Type`. |
| `version` | yes | Integer version. New versions are independent registrations (see §Versioning). |
| `description` | yes | What this type represents, why it exists, who emits it — and, by convention, the cross-source identity field if any (there is **no** parsed `identity_key` key; see §The cross-source identity story). |
| the schema body (`type`, `required`, `properties`, …) | yes | A standard JSON Schema draft-07 document describing the `payload` of an `EvidenceRecord` of this type. |

There is **no** `schema_version`, `id`, or `identity_key` frontmatter
key — the file is a schema, not a wrapper around one.

### Schema validation

The collector validates payloads with a full JSON Schema draft-07
implementation (`github.com/xeipuuv/gojsonschema`, wired in
`internal/evidence_types/validate.go`; compiled schemas are cached by
content hash). Every keyword a schema declares is enforced — not just
`required`:

- Type predicates: `type`, `required`, `properties`,
  `additionalProperties`, `patternProperties`, `items`, `minItems`,
  `maxItems`, `uniqueItems` — including **recursive** validation of
  nested objects and array items.
- String constraints: `minLength`, `maxLength`, `pattern`, `format`.
- Number constraints: `minimum`, `maximum`, `exclusiveMinimum`,
  `exclusiveMaximum`, `multipleOf`.
- Composition: `enum`, `const`, `oneOf`, `anyOf`, `allOf`, `not`,
  `if`/`then`/`else`, and in-document `$ref`.

A schema that fails to compile fails at bootstrap (exit 3); a payload
that violates any constraint fails the binding — the **first**
non-conforming record tags the policy `error` (exit 3), with no
drop-and-continue.

---

## Embedding and loading

In-tree evidence types are embedded into the binary at compile time:

```go
// internal/evidence_types/loader.go
//go:embed schemas/*.json
var schemaFS embed.FS
```

At orchestrator bootstrap, the loader
(`internal/evidence_types/loader.go`) walks the embedded FS, parses
each JSON Schema, checks it compiles, and registers each type by its
`title`. The registry itself lives at
`internal/registry/evidence_type.go`. After bootstrap the registry is
read-only — see [`02-layers.md`](02-layers.md) §L2.

Project-local types under `.sigcomply/evidence_types/` are **planned**:
they would load the same way from the project filesystem and merge into
the same registry, with a project-local file that redefines an in-tree
type ID failing at bootstrap (types are append-only across the union).
Today only the embedded in-tree set loads.

---

## Schema-conformance validation

Validation happens once per emitted record, inside the collector,
before the record is wrapped in an envelope:

| Outcome | Action |
|---|---|
| Record's `Payload` validates against the schema for `Type` | Included in the envelope. |
| Any record fails validation | The **first** non-conforming record errors the binding; the consuming policy becomes `error` (exit 3). There is no drop-and-continue and no per-call percentage threshold. |
| `Type` not in the evidence-type registry | Plan-time error, exit 3 (caught before any `Collect` runs). |
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

A new version is a **new registration** with a distinct ID:
`directory_user.v2`, registered as a separate file
(`directory_user.v2.json`). Both `directory_user.v1` and
`directory_user.v2` coexist in the registry — exactly the situation in
the shipped tree today. Plugins emit one specific version per record
(by setting `Type` to e.g. `directory_user.v2`, as `aws.iam` does).
Policies accept one or both versions in their `accepts:` list during
migration windows:

```yaml
# during migration, accept both
slots:
  user_directory:
    accepts: [directory_user.v1, directory_user.v2]
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
source systems, plugin authors set `EvidenceRecord.IdentityKey` (and/or
emit a stable payload field like `email`) to a cross-source-stable
value. There is **no parsed `identity_key` key in the schema file** —
the convention is recorded in the schema's `description` text, e.g.
"cross-source dedup key: email."

This convention:

1. Tells plugin authors what to put in `IdentityKey` (no ambiguity
   between "use the email" vs "use the employee_id").
2. Tells policy authors that records of this type may legitimately
   appear from multiple sources for the same logical entity, so they
   should dedupe before counting.
3. Feeds the `pass_when:` clause-level `identity_key:` setting (default
   `"id"`), which deduplicates the violation list — and therefore
   `resources_failed` — by the chosen field. See
   [`03-policy-spec.md`](03-policy-spec.md) §Cross-source dedup. (This
   is the DSL's opt-in dedup; it does not read the schema description.)

For evidence types where there is no meaningful cross-source identity
(e.g. `firewall_rule` — a rule in AWS is not the same rule as a rule
in GCP, even if both happen to allow port 22), say nothing about it in
the description and leave `IdentityKey` unset on records; clauses then
dedupe by `id`, treating the union as a bag.

---

## A concrete worked example

The shipped `directory_user.v2` schema, verbatim
(`internal/evidence_types/schemas/directory_user.v2.json`):

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://schemas.sigcomply.io/evidence_types/directory_user/v2.json",
  "title": "directory_user.v2",
  "version": 2,
  "description": "Cross-vendor identity record (v2) — extends directory_user.v1 with privileged-access, access-key, and account-lifecycle fields needed for deeper IAM hygiene policies. Requires all v1 fields plus is_root, has_console_access, has_programmatic_access.",
  "type": "object",
  "required": ["id", "mfa_enabled", "is_root", "has_console_access", "has_programmatic_access"],
  "properties": {
    "id":                      { "type": "string" },
    "display_name":            { "type": "string" },
    "email":                   { "type": "string" },
    "mfa_enabled":             { "type": "boolean" },
    "is_admin":                { "type": "boolean" },
    "is_service_account":      { "type": "boolean" },
    "is_active":               { "type": "boolean" },
    "is_root":                 { "type": "boolean" },
    "has_console_access":      { "type": "boolean" },
    "has_programmatic_access": { "type": "boolean" },
    "direct_policy_count":     { "type": "integer" },
    "unused_days":             { "type": "integer" }
  },
  "additionalProperties": true
}
```

A plugin emitting this type:

```go
// inside aws.iam.Collect(...)
records = append(records, core.EvidenceRecord{
    Type:        "directory_user.v2",
    ID:          "AIDAEXAMPLE01",       // AWS-local
    IdentityKey: "alice@acme.com",       // cross-source
    SourceID:    "aws.iam",
    Payload:     mustMarshal(map[string]any{
        "id":                      "AIDAEXAMPLE01",
        "email":                   "alice@acme.com",
        "mfa_enabled":             false,
        "is_admin":                true,
        "is_root":                 false,
        "has_console_access":      true,
        "has_programmatic_access": true,
    }),
})
```

The collector validates each `Payload` against the registered schema.
The first non-conforming record errors the binding (exit 3) — there is
no silent drop.

A policy declaring `accepts: [directory_user.v2]` can rely on
`mfa_enabled` existing and being a boolean on every record it sees. No
defensive checks; the registry is the precondition.

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

## Project-local extension (planned)

The intended design lets customers add evidence types under
`.sigcomply/evidence_types/` using the identical JSON Schema file
format:

```
.sigcomply/
  evidence_types/
    acme_internal_user.v1.json         # custom shape for acme.internal_iam
```

These would load at bootstrap alongside in-tree types and merge into
the same registry; project-local plugins reference them in `Emits()`
and project-local policies in `accepts:`. A project-local file
redefining an in-tree type ID would fail at bootstrap (exit 3) —
project-local types are append-only across the union, and the
upstream-curated set is not overridable, so auditors can trust that a
shipped `directory_user` means the shipped thing, not a customer-tweaked
variant.

**This path is not yet wired** — today only the embedded in-tree set
loads. It ships alongside project-local plugins as part of `sigcomply
build`. The path from a project-local type to an upstream contribution
is in [`07-extensibility.md`](07-extensibility.md).

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
