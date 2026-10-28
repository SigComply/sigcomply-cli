# 03: Policy spec

Reference for the fields of a policy, the `pass_when` DSL and the `rule:` escape hatch. Read it
before adding or changing a policy, in a framework or project-locally.

## Two authoring surfaces

- **Framework policies are Go.** Each is an `autoPolicy{...}.policy()`, `manualPolicy{...}.policy()`
  or `rosterPolicy{...}.policy()` value in `internal/frameworks/<fw>/policies_*.go`, built with the
  clause helpers in `builders.go` (`leaf`, `isSet`, `allOf`, `anyOf`, `inRoster`, `all`, `none`,
  `anyRec`, `allWhere`, `noneWhere`, `anyWhere`). There are no shipped `policy.yaml` files. To
  count a framework's policies, count `.policy()` calls.
- **Project-local policies are YAML** at `.sigcomply/policies/<id>/policy.yaml`, loaded by
  `spec.LoadPolicy` (strict: unknown keys fail) into the same `core.Policy`.

Both go through `spec.ValidatePassWhen`. Every shipped policy uses `pass_when`; both frameworks'
`Rules()` return nil. The YAML below is the project-local form; each field maps to a builder
argument.

## The spec

```yaml
schema_version: policy.v1
id: acme.cc6.1.mfa_enforced_all_users
control: CC6.1
severity: critical             # info | low | medium | high | critical
category: access_control
evidence_mode: automated       # automated | manual
cadence: daily
on_push: true                  # optional; default true for automated, false for manual

description: All directory users have multi-factor authentication enabled.
remediation: Enable MFA for every user in each bound identity source.

slots:
  evidence:
    accepts: [directory_user, directory_user.v2]
    cardinality: one-or-more
    required: true

pass_when:
  slot: evidence
  quantifier: all
  condition: { op: eq, field: payload.mfa_enabled, value: true }
  violation_message: "user {{.payload.display_name}} does not have MFA enabled"
```

### Field reference

| Field | Required | Rule |
|---|---|---|
| `schema_version` | yes (YAML) | `policy.v1`. |
| `id` | yes | Unique. Convention `<framework>.<control>.<short_name>`; project-local policies use their own prefix. |
| `control` | yes | Control ID as the framework writes it: `CC6.1`, `A.5.16`. Must be in the active framework's control catalog; otherwise the plan fails with exit 3 naming the policy and the control (`planner.validatePolicyControls`). Shipped policies are held to the same rule by `TestValidatePolicyControls_ShippedFrameworksPass`. |
| `severity` | yes | `info`, `low`, `medium`, `high` or `critical`. |
| `category` | no | Free-form grouping label. |
| `evidence_mode` | yes | `automated` or `manual`. No default; missing fails the load (exit 3). See §evidence_mode. |
| `cadence` | yes | `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual`, or `every:<duration>` (5-minute floor). A bare duration such as `24h` is rejected. Semantics: [10](10-cadence-model.md). |
| `on_push` | no | Whether the on-push CI filter (`--on-push`) selects the policy. |
| `description` | yes | What the policy asserts. |
| `remediation` | no | Shown with failures. |
| `slots` | automated: yes (1 or more); manual: forbidden | See §Slots. |
| `parameters` | no | See §Parameters. |
| `pass_when` | automated: this or `rule`; manual: forbidden | See §pass_when. |
| `rule` | automated: this or `pass_when`; manual: forbidden | Declaring both fails the load. See §The rule escape hatch. |
| `catalog_entry` | manual: yes; automated: forbidden | Manual catalog entry ID; it names the upload folder. |
| `tags` | no | Free-form labels. |

## Slots

A slot is a named input. It is the only place a policy names evidence shapes.

```yaml
slots:
  evidence:
    accepts: [directory_user, directory_user.v2]   # evidence-type IDs
    cardinality: one-or-more                       # required
    required: true
    role: roster_subject                           # optional; see §Multi-slot policies
```

A source binds to a slot when `source.Emits() ∩ slot.Accepts` is not empty. An explicit binding
with an empty intersection is a plan error (exit 3). Most slots list one type family; a second
entry is usually a schema version (`directory_user` and `directory_user.v2`). Whether to reuse a
type, add a version or coin a new type: [04a](04a-evidence-type-registry.md).

| `cardinality` | Sources the project may bind |
|---|---|
| `exactly-one` | 1 |
| `at-most-one` | 0 or 1 |
| `one-or-more` | 1 or more |
| `optional` | 0 or more |

A `required: true` slot with no records makes the policy `skip` ("required slot has no
records"), unless the slot sets `FailWhenEmpty` (below). A `required: false` slot with no records reaches the DSL as an empty set (see
§Empty-set semantics) or the rule as an empty array. When no slot has a bound source at all, the
policy skips ("no source bound to any slot") even if every slot is optional: it examined nothing,
so it cannot pass. One bound slot, even one whose source returned no records, is enough to
evaluate.

### Presence slots (`FailWhenEmpty`)

`core.Slot.FailWhenEmpty` marks a slot whose policy asks whether a service exists at all: an
audit trail, a threat detector, a configuration recorder, a backup plan, a security alert, a SIEM
or scanner, a password policy. When the slot has a bound source and that source returned no
records, the evaluator fails the policy before the DSL or rule runs. The failure is one
policy-level violation with the reason `no <accepts> records: <slot description> not enabled or
not found`, so `resources_failed` is 1 and `resources_evaluated` is 0. A slot with no bound
source still skips. Shipped policies set it through the `presence` field of `autoPolicy` in each
framework's `builders.go`; for-all policies leave it unset and keep skipping on zero records. It
is part of the policy content hash. Project-local YAML policies cannot set it.

### Multiple bound sources

The evaluator gets the union of all bound sources' records, each tagged with `type` and
`source_id`. Never branch on `source_id` in a condition: encode the difference in the evidence
type or in a normalized payload field.

### Empty-set semantics

| Quantifier | Empty set |
|---|---|
| `all`, `none` | pass |
| `any` | fail |
| `count` | fail if `min_percentage > 0`, else pass |

A vacuous pass can come from an empty `required: false` slot, a filter that matched nothing, or a
`matches_in` whose index is empty.
The evaluator records the slots in `diag.vacuous_clauses`; `check` and `report` explain the pass,
and the aggregator replaces the wire message with "Passed, but no resources matched the filter".
A clause naming an undeclared slot fails the load (`spec.ValidatePassWhen`). A filter that cannot
be evaluated makes the policy `error` (`filterRecords`), so it never empties the set silently.

`resources_evaluated` counts slot records before filtering. Slots read only through a
`matches_in` `in_slot` are not counted.

### Cross-source dedup (clause-level `identity_key`)

The union is a bag: the same person in AWS IAM and Okta arrives twice. A clause deduplicates its
violations by `identity_key` (default `id`). To collapse one person across sources, set it to a
field all plugins normalize, such as `payload.email` or `account.ref`. The clause key is
independent of the schema's identity convention ([04a](04a-evidence-type-registry.md)).
Deduplicated violations feed `resources_failed`.

## Parameters

```yaml
parameters:
  max_age_days:
    type: int
    default: 90
    min: 1
    max: 365
```

| Type | Value | Constraints |
|---|---|---|
| `bool` | `true`/`false` | |
| `int`, `float` | number | `min`, `max` |
| `string` | string | `enum` or `pattern` |
| `duration` | `"30d"`, `"24h"` | |
| `date` | `"2026-01-15"` | |
| `list_of_string` | list | `item_pattern` is parsed but not enforced |
| `list_of_int` | list | |

Effective value = the policy default, overridden by `policies.<id>.parameters.<name>` in
`.sigcomply.yaml`. An out-of-range value is a plan error (exit 3). Effective values are written
to `result.json`, not to `manifest.json`.

## evidence_mode

| Value | Collection | Evaluation |
|---|---|---|
| `automated` | The planner binds API sources to the slots; the collector calls `Collect`. | `pass_when`, or `rule:` |
| `manual` | The planner binds `manual.pdf` to an implicit slot using `catalog_entry`. | `manual_check.go` reads `file_present`, `in_temporal_window`, `file_valid` |

The upload window's grace period comes from the catalog entry (`manual.CatalogEntry.GracePeriod`,
derived from cadence by `manualcatalog.GraceForCadence`), not from a policy parameter. The manual
contract: [14-manual-evidence.md](14-manual-evidence.md).

### Project override

```yaml
policies:
  soc2.cc6.1.mfa_enforced_all_users:
    evidence_mode: manual
    catalog_entry: mfa_attestation   # required when evidence_mode is manual
```

`catalog_entry` is required with `evidence_mode: manual` and rejected otherwise
(`spec/project_config.go`). The policy ID stays the same; `PolicyResult` records `EvidenceMode`
and `EvidenceModeOverridden`, and both go on the wire.

## pass_when

A clause, or a list of clauses that must all pass:

```yaml
pass_when:
  slot: <slot_name>            # required
  quantifier: all              # all | none | any | count
  filter:                      # optional condition tree applied first
    op: eq
    field: payload.is_active
    value: true
  condition:                   # required
    op: lte
    field: payload.age_days
    value: "$params.max_age_days"
  identity_key: id             # optional, default "id"
  min_percentage: 90           # required for count, rejected otherwise
  violation_message: "access key {{.id}} is older than the limit"   # optional
```

| Quantifier | Passes when |
|---|---|
| `all` | every (filtered) record satisfies `condition` |
| `none` | no (filtered) record satisfies `condition` |
| `any` | at least one record satisfies `condition` |
| `count` | at least `min_percentage`% of records satisfy `condition` |

### Conditions

A condition is `{op, field, value}`. Operators: `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`,
`not_in`, `is_set` (no `value`), `all_of` and `any_of` (take a `conditions:` list), and
`matches_in`.

- `field` resolves `id`, `type`, `source_id`, `account.*`, or `payload.<dot.path>`. A bare name
  without `payload.` is not found. A missing field makes the policy `error`, in a `filter` too.
- Guard a schema-optional field with `is_set` inside `all_of` (which short-circuits; `any_of` does
  not). `TestEveryFilterGuardsOptionalFields` enforces this for shipped policies.
- Parameters go on the value side only, as the string `"$params.<name>"`.
- Keys are decoded strictly: `normalise:` fails the load.

### matches_in

```yaml
{ op: matches_in, field: account.key, in_slot: roster, remote_field: payload.email,
  normalize: lower_trim, where: { op: eq, field: payload.status, value: active } }
```

True when the record's `field` equals `remote_field` on some record in `in_slot` that satisfies
`where`.

- `in_slot` and `remote_field` are required; `in_slot` must be a declared slot. These keys, and
  `normalize` and `where`, are rejected on any other operator.
- `normalize` is omitted (exact) or `lower_trim`.
- `where` is strict: a missing field there is a policy `error`. `matches_in` may not appear inside
  `where`.
- A local record with a missing, non-string or empty `field` never matches. Remote records without
  a usable `remote_field` are left out of the lookup.
- An empty index adds the clause to `diag.vacuous_clauses`: an empty `in_slot`, or a `where` (or
  missing keys) that excluded every record in it. The roster policy for inactive personnel is
  vacuous whenever the roster marks nobody inactive.

### Virtual `account.*` fields

| Field | Value |
|---|---|
| `account.ref` | `source_id/id`; unique across sources. Use as `identity_key` and as an exception's `resource_id`. |
| `account.key` | Roster alias (lower-trimmed), else `payload.email`, else `payload.principal_id`, else `""`. |
| `account.linked_by` | `alias`, `email`, `principal` or `none`. |
| `account.non_human` | Listed in `experimental.roster.non_human[source_id]`, `payload.is_root == true`, or a `payload.principal_type` other than a person (`service_account`, `group`, `domain`, `allUsers`). An empty `principal_type` counts as a person. |
| `account.active` | `payload.is_active`; `true` when absent. |

Aliases and `non_human` entries match the record's `id`, `payload.username` or
`payload.principal_id`, case-insensitively, per source; never `display_name`.

### Violation messages

`violation_message` belongs inside the clause. Tokens `{{.id}}`, `{{.type}}`, `{{.source_id}}`,
`{{.payload.<path>}}` and `{{.account.<field>}}` are substituted by regex (`renderMsg`), not by Go
templates. Unresolved tokens stay verbatim. Parameters are not interpolated.

### Multi-slot policies

Each clause in a list names its own `slot:`. A condition reads another slot only through
`matches_in`. The roster policies are the shipped example:

```yaml
slots:
  roster:   { accepts: [roster_entry], cardinality: exactly-one, required: true, role: roster }
  accounts: { accepts: [directory_user, directory_user.v2, iam_binding], cardinality: one-or-more, required: true, role: roster_subject }
pass_when:
  slot: accounts
  quantifier: all
  identity_key: account.ref
  filter:
    op: all_of
    conditions:
      - { op: eq, field: account.active,    value: true }
      - { op: eq, field: account.non_human, value: false }
  condition: { op: matches_in, field: account.key, in_slot: roster, remote_field: payload.email, normalize: lower_trim }
  violation_message: "account {{.account.ref}} is not linked to anyone in the roster"
```

Slot roles:

- `roster` is never auto-bound. It binds to the policy's explicit `bindings:` entry, else
  `experimental.roster.source`, else nothing (the policy skips). Cardinality is forced to
  `exactly-one`; at most one per policy.
- `roster_subject` needs a `roster` slot. It auto-binds minus every source bound to the roster
  slot (a directory cannot vouch for its own accounts). Binding the roster source to it
  explicitly is a plan error (exit 3).
- Role slots must accept disjoint evidence types.

Customer guide: [identity-roster.md](../guides/identity-roster.md).

## The rule escape hatch

Use `rule:` only for logic the DSL cannot express: aggregations across records, or joins that are
more than equality on one normalized key. First ask whether the plugin can pre-compute a field
(`age_days` instead of `last_rotation_at`).

- `rule:` names an entry in `registry.Set.Rules`. It is resolved at evaluation: an unregistered
  name makes the policy `error`, not a plan error.
- Go rules implement `core.Rule` and are registered only through a framework's `Rules()`.
  Project-local Go rules are not wired.
- Project-local Rego: put `rule.rego` next to `policy.yaml`. `loadProjectRules` registers it under
  its `package` path and queries `data.<package>.result`. Set `rule:` to that package path.

The Rego module must define a `result` object:

```rego
package acme.rules.contractor_review

import rego.v1

result := {"status": status, "violations": violations}

violations := [v |
    some r in input.slots.evidence
    r.payload.is_contractor
    not r.payload.reviewed
    v := {"resource_id": r.id, "reason": "contractor not reviewed"}
]

status := "pass" if count(violations) == 0
status := "fail" if count(violations) > 0
```

- `result.status` is `pass`, `fail`, `error`, `skip` or `na`. A missing, non-string or other
  value (including `waived` and `carried_forward`) makes the policy `error`. Go rules follow the
  same rule.
- `result.violations` is optional, a list of `{resource_id, reason, details}`.
- Input: `policy_id`, `slots.<name>[]` (each `{id, identity_key, source_id, payload}`), `params`
  (every declared parameter, defaulted), `now` (RFC 3339).

Code: `internal/evaluator/rego_rule.go` (`NewRegoRule`, `projectRegoResult`),
`internal/orchestrator/project_local.go` (`loadProjectRules`).

## Cadence and on_push

`cadence` says how often the policy must be re-evaluated; `on_push` says whether the on-push
workflow selects it. Only `--scheduled` gates on cadence; the default run and `--pr` evaluate
every in-scope policy, and an explicit filter (`--cadence`, `--cadences`, `--on-push`) always
wins. A project overrides cadence with `policies.<id>.cadence`. A manual entry's upload folder
uses the policy's declared cadence, not the override. Decision rule, state shards and
`every:24h` versus `daily`: [10](10-cadence-model.md). How CI schedules each cadence:
[09](09-ci-execution-model.md).

## Testing policies

Framework policies are tested as Go under `internal/frameworks/<fw>/`. Build-time guards:
`spec.ValidatePassWhen` per framework, `TestEmitterCoverage_EveryAcceptedTypeHasAnEmitter`
(`internal/sources/builtin/coverage_test.go`: every accepted type has an emitter) and
`TestEveryFilterGuardsOptionalFields`. There are no per-policy `tests/` directories.

## Project-local policies

Put them at `.sigcomply/policies/<id>/policy.yaml`. They load with the same validation, join the
active framework, and appear in results and the cloud payload like shipped policies. Use your own
ID prefix. Walkthrough: [07-extensibility.md](07-extensibility.md).
