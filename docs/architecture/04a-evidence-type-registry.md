# 04a: Evidence type registry

The evidence-type registry is the only link between policies and source plugins. A policy
declares the types it accepts (`slots.<name>.accepts: [...]`). A source plugin declares the
types it emits (`Emits() []string`). Neither names the other. Because `aws.s3`, `gcp.storage`
and `azure.storage` all emit `object_storage_bucket`, one "bucket encrypted at rest" policy
covers all three, and a new vendor for a modelled concept is one new plugin and zero policy
edits. The conceptual framing is [`01-conceptual-model.md`](01-conceptual-model.md) §Axiom 1.

Read [`03-policy-spec.md`](03-policy-spec.md) (§Slots) and
[`04-source-plugins.md`](04-source-plugins.md) first. This page owns how types are declared,
loaded, validated, versioned and designed.

## Not built

- A schema-level `identity_key`. The cross-source key is a convention in the schema's
  `description`; see [Cross-source identity](#cross-source-identity).
- Evidence types as Go packages (`.sigcomply/evidence_types/<id>/`). `sigcomply build`
  compiles one and warns that nothing registers it. Use a JSON file.
- A permissive validation mode (drop bad records, or tolerate up to some percentage). The first
  bad record fails the binding.

## File format

An evidence type is a JSON Schema (draft-07) document at
`internal/evidence_types/schemas/<id>.v<n>.json`. The file is the schema; there is no wrapper.
`spec.LoadEvidenceType` (`internal/spec/evidence_type.go`) reads the header:

| Field | Required | Meaning |
|---|---|---|
| `title` | yes | The type ID, and the value plugins set as `record.Type`. Bare for a first version (`directory_user`); version-suffixed for later ones (`directory_user.v2`). |
| `version` | yes | Positive integer. |
| `type` | yes | Must be `"object"`: the schema describes a record's `payload`. |
| `description` | convention | What the type represents, who emits it, and the cross-source key if any. |

The file name is a convention only; the registry keys on `title`. Read the shipped schemas in
`internal/evidence_types/schemas/` for real examples rather than copying one here.

## Loading

- In-tree types are embedded with `//go:embed schemas/*.json` and registered at orchestrator
  bootstrap by `evidencetypes.Register` (`internal/evidence_types/loader.go`). Registration reads
  the header only. That every embedded schema compiles is enforced by the test
  `TestValidate_AllEmbeddedSchemasCompile`.
- Project-local types: `loadProjectEvidenceTypes` (`internal/orchestrator/project_local.go`)
  reads every `*.json` file directly under `.sigcomply/evidence_types/` (subdirectories are
  skipped), compiles the schema, and registers it after the embedded set. A schema that does not
  compile, or a `title` that redefines a shipped type, is a config error (exit 3). No `sigcomply
  build` is needed. Project-local mechanics are in [`07-extensibility.md`](07-extensibility.md).
- After bootstrap the registry is read-only ([`02-layers.md`](02-layers.md) §L2).

## Where each check runs

| Check | Where | Outcome |
|---|---|---|
| Every type a registered source emits, and every type a registered policy accepts, has a schema | `evidencetypes.VerifyRegistrations`, at bootstrap | Exit 3 |
| An explicit `bindings:` entry whose source emits nothing the slot accepts | `internal/planner/bindings.go` (explicit path), at plan time | Exit 3, with a version-skew hint when the source emits a sibling version |
| Auto-binding finds no configured source that emits an accepted type | `autoBindSlot`, at plan time | Not an error. The slot gets no binding and the policy is skipped. |
| A record whose `Type` is outside the binding's accepted types | `checkAcceptedTypes` (`internal/collector/collector.go`) | Policy status `error` |
| A record whose `Type` has no schema, or whose payload fails its schema | `validateRecords` (`internal/collector/collector.go`) | Policy status `error` |

A policy with status `error` makes `sigcomply check` exit 2 (`renderAndExitCode`:
`c.errored > 0` returns `ExitExecution`). Exit 3 is only for bootstrap and plan errors.

## Validation

`evidencetypes.Validate` (`internal/evidence_types/validate.go`) runs full draft-07 through
`github.com/xeipuuv/gojsonschema`, with compiled schemas cached by content hash. Every keyword a
schema declares is enforced, including `enum`, `format`, `pattern`, numeric and length bounds,
nested objects and array items, composition (`oneOf`, `allOf`, `if`/`then`/`else`) and
in-document `$ref`.

The collector validates each record before it signs the envelope. The first non-conforming
record fails the binding and tags the policy `error`. Nothing is dropped and the run continues
with the next binding. The fix belongs in the plugin or the schema, never in a policy.

## Versioning: schemas are append-only

Within a version a schema may only grow:

- Add an optional property.
- Loosen a constraint, as long as every previously valid record stays valid.

These need a new version:

- Remove, rename or retype a property.
- Add a property to `required`.
- Tighten a constraint so that a previously valid record fails.

A new version is a new registration with its own ID and file (`directory_user.v2` in
`directory_user.v2.json`). The old version stays registered and frozen. A plugin emits one
version per record. A policy accepts both during a migration, which is the multi-type slot from
[`03-policy-spec.md`](03-policy-spec.md) §Slots:

```yaml
slots:
  evidence:
    accepts: [directory_user, directory_user.v2]   # v1's ID is the bare title
```

`directoryUserTypes` in `internal/frameworks/soc2/policies_cc6.go` is the shipped form of this.
Never mutate a type in a way that breaks existing records: every record in an old vault must
still validate against the schema its `Type` names.

Relaxing `required` is a breaking change for consumers, not producers. The evaluator errors on a
reference to a field the record does not carry, so every clause that reads a newly optional
field must gain an `is_set` guard.

### password_policy versions

`password_policy` (v1) required all eight answers AWS IAM gives: `min_length`, `max_age_days`,
`reuse_prevention_count` and four character-class booleans. A platform that rates password
strength on its own scale, or fixes length as a platform constant, could not emit a v1 record
without inventing values. `password_policy.v2` fixes the shape, not the vendors:

- It keeps v1's field names and meanings and makes the platform-dependent fields optional, so
  absence is expressible. Only `id`, `provider` and `scope` are required.
- `complexity_model` (`per_class` | `strength_enum` | `fixed` | `none`) says which kind of
  strength answer the record carries. `per_class` uses the four `requires_*` booleans,
  `strength_enum` uses `password_strength`, and `fixed` uses `complexity_description`. Omit it
  when the source cannot tell, which is different from `none`.
- `reuse_prevented` (boolean) answers the reuse question; `reuse_prevention_count` is an
  optional refinement.
- `scope` and `precedence` stop N records from being read as interchangeable.
- `not_configurable` names attributes the platform exposes no tenant setting for.
  `defaulted` names fields whose value came from the API's documented default for an omitted
  setting.

Rules any emitter of this type follows:

1. Absent means "this source did not observe a value". Never emit a zero, a floor or a vendor's
   documented default read from documentation: a default is a value the tenant may have
   overridden, so it says nothing about this tenant.
2. `fixed` is only for a rule the tenant cannot change. `azure.entra` does not emit it, because
   Entra's character-class rule can be disabled per user and, in a federated or synced domain,
   the rule in force is the external directory's.
3. `defaulted` is different from rule 1: the API was called, returned this tenant's policy, and
   the vendor's contract defines an omitted field as "the default applies"
   (`gcp.cloud_identity`).
4. Emit one version per record. Dual-emitting would double resource counts and sign two
   envelopes for one fact.

The consuming policies accept both versions (`passwordPolicyTypes` in
`internal/frameworks/soc2/builders.go`) so a project-local plugin still on v1 keeps binding. Find
the in-tree emitters with `grep -rln 'password_policy.v2' internal/sources`.

## Cross-source identity

When one entity can appear in several sources (a person in AWS IAM and in Okta), the plugin sets
`EvidenceRecord.IdentityKey` to a cross-source-stable value, such as the email, and the schema's
`description` names that field. A `pass_when:` clause can then dedupe violations, and so
`resources_failed`, with its clause-level `identity_key:` (default `id`); see
[`03-policy-spec.md`](03-policy-spec.md) §Cross-source dedup. The clause setting does not read
the schema description.

For a type with no cross-source identity (`firewall_rule`: an AWS rule is not the same rule as a
GCP one), say nothing in the description and leave `IdentityKey` unset. Clauses then dedupe by
`id`.

## Schema design: top-down from the concept

A cross-vendor type describes a concept ("a user in a directory", "an object storage bucket"),
not one vendor's API response. Before you add a new type, read `directory_user.v1.json`,
`object_storage_bucket.v1.json` and `git_repository.v1.json`.

Wrong, modelled on the AWS IAM response:

```json
{ "UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice",
  "MFADevices": [{ "SerialNumber": "arn:aws:iam::123456789012:mfa/alice" }] }
```

Right, modelled on the concept:

```json
{ "id": "alice", "email": "alice@example.com", "mfa_enabled": true, "is_admin": false }
```

### The universal-field test

Before you add a field, ask: can every plausible implementation of this concept fill it with a
real value? If not, make it optional and write down what "absent" means. Survey at least two
implementations before you mark a field `required`.

| `directory_user` field | Universal? | Declaration |
|---|---|---|
| `mfa_enabled` | Yes | `required` |
| `is_admin`, `email` | Most systems | optional |
| `iam_path` (AWS), `okta_login` (Okta) | No | not in the shared schema |

An optional field costs every reader an `is_set` guard. The evaluator errors on a reference to an
absent field, in a `filter` as much as in a `condition`, because silently skipping the record is
how an omitted field turns into a vacuous pass. `TestEveryFilterGuardsOptionalFields`
(`internal/manualcatalog/`) fails the build if a shipped filter reads a non-`required` field
without a guard.

### The normalization boundary

The plugin does all translation from vendor shape to canonical shape. Policy clauses must never:

- branch on the source (`record.type == "aws_iam_user"`);
- re-derive a field the plugin should compute (`count(record.mfa_devices) > 0`);
- gate on a vendor-specific field (`record.arn != null`).

Each of these means vendor shape leaked into the policy. Fix the plugin. For MFA, `aws.iam`
computes `mfa_enabled` from the user's MFA devices and `okta` from `MFAFactorCount > 0`; the
policy reads `mfa_enabled` either way.

### The null trap

When a schema is designed bottom-up and a second vendor must fit it, the plugin fills a required
field with `null`, `""`, `0` or `false`, policy authors add null guards, and the policy quietly
behaves differently per source. If a second plugin cannot fill a required field, the schema is
wrong. Do one of:

- make the field optional and document what absent means;
- leave it to `additionalProperties` (vendor extras no policy reads);
- coin a vendor-specific type.

Never emit a sentinel for a concept the vendor does not have.

### Two tiers of type

| Tier | Naming | Example | Use when |
|---|---|---|---|
| Semantic | no vendor prefix | `directory_user`, `object_storage_bucket` | The concept exists in two or more vendors and every required field is universal. |
| Vendor-specific | vendor prefix | `okta_app` | The concept exists in one vendor's model only. |

Don't use a vendor-specific type to avoid designing a shared schema: each later vendor for the
same concept then needs another type and a policy fork.

## Reuse a type, version it, or coin a new one

- Same entity, same fields: reuse the type. The new plugin emits it; no schema or slot change.
- Same entity, a breaking change to the fields: coin a new version (see
  [Versioning](#versioning-schemas-are-append-only)) and add it to the slots' `accepts:`.
- Same entity, structurally different fields: coin a new type and add it to the relevant slots'
  `accepts:`.
- Different entity: a different slot. Ask whether a reviewer would describe the records together
  ("47 buckets across our clouds") or separately ("3 firewall rules and 8 branch protections").
  Together means one slot with several accepted types; separately means two slots.

When in doubt, prefer two narrow types over one broad type that later has to split.

## See also

- [`01-conceptual-model.md`](01-conceptual-model.md): §Glossary, §Axiom 1.
- [`02-layers.md`](02-layers.md): §L2, the registry mechanism.
- [`03-policy-spec.md`](03-policy-spec.md): §Slots, how `accepts:` consumes types.
- [`04-source-plugins.md`](04-source-plugins.md): the factory contract.
- [`07-extensibility.md`](07-extensibility.md): project-local types and plugins.
