# 01: Conceptual model

The vocabulary used across the code and these docs, and the four design rules the code enforces.
When this page and the code disagree, the code wins: fix this page.

## Glossary

| Term | Meaning | In code | Owner doc |
|---|---|---|---|
| Framework | A compliance regime with a versioned ID. Registered: `soc2`, `iso27001`. | `core.Framework`, `internal/frameworks/<fw>/`, `frameworks.IDs()` | [13](13-isms-clauses-and-soa.md) for ISO clauses |
| Control | One requirement inside a framework, e.g. `CC6.1` (SOC 2) or `A.5.16` (ISO 27001:2022). `Kind` is `catalog` (selectable, can be declared not applicable) or `management_system` (ISO clause 4-10, `C.`-prefixed, never excludable). | `core.Control`, `core.ControlKind` | [13](13-isms-clauses-and-soa.md) |
| Policy | One checkable assertion that contributes to one or more controls (`controls[]`, each a `core.ControlRef`). Declares `evidence_mode`, `cadence`, slots and `pass_when` (or `rule:`). | `core.Policy`; built by `.policy()` builders in `internal/frameworks/<fw>/policies_*.go` | [03](03-policy-spec.md) |
| Evidence mode | `automated` (API sources + `pass_when`) or `manual` (uploaded documents + the presence check). The only two flows. | `core.EvidenceMode` | [03 §evidence_mode](03-policy-spec.md#evidence_mode), [14](14-manual-evidence.md) |
| Cadence | How often a policy must be re-evaluated: `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual`, or `every:<duration>`. | `planner/cadence.go` | [10](10-cadence-model.md) |
| Slot | A named input on a policy: `accepts` (evidence-type IDs), `cardinality`, `required`, optional `role`. | `core.Slot` | [03 §Slots](03-policy-spec.md#slots) |
| Evidence type | A versioned JSON Schema for one kind of record (`directory_user`, `directory_user.v2`, `object_storage_bucket`). | `internal/evidence_types/schemas/` | [04a](04a-evidence-type-registry.md) |
| Source (plugin) | Code that reads one external system and emits records of declared types. Configured under `sources:`; may have bracketed instances (`aws.iam[staging]`). | `core.SourcePlugin`, `internal/sources/` | [04](04-source-plugins.md) |
| Evidence record | One observed item: `type`, `id`, `identity_key`, `payload`, `source_id`, `collected_at`, optional `scope` (account, region or project it was read from). | `core.EvidenceRecord` | [04](04-source-plugins.md) |
| Envelope | Signed JSON file holding the records of one (policy, evidence type, source) group, with its own ephemeral Ed25519 key. | `core.Envelope`, `internal/sign` | [05](05-vault-layout.md), [`SECURITY.md`](../../SECURITY.md) |
| Binding | The planner's assignment of a source to a policy slot. Automatic by evidence type, or explicit under `policies.<id>.bindings`. | `planner/bindings.go` | [08](08-project-config.md) |
| Project | One repository with one `.sigcomply.yaml` and one framework. | `spec.ProjectConfig` | [08](08-project-config.md) |
| Period | The audit window a run belongs to (`2026-Q1`), taken from `planner.PeriodTime` (HEAD commit time, or wall clock under `period.time_basis: wall_clock`). A manual entry's upload folder uses its own cadence window instead (`planner.CadencePeriod`). | `internal/planner/period.go` | [10](10-cadence-model.md) |
| Run | One `sigcomply check` invocation. Writes one immutable folder `{framework}/{period_id}/run_{stamp}_{id8}/`. | `orchestrator.Run`, `buildRunRoot` | [05](05-vault-layout.md) |
| Mode | How `check` picks policies: default (all), `--pr`, or `--scheduled` (cadence-gated, reads state shards). | `orchestrator.Mode` | [09](09-ci-execution-model.md), [10](10-cadence-model.md) |
| State shard | Mutable, unsigned per-policy file `state/{framework}/policies/{policy_id}.json` used to decide whether a scheduled run re-evaluates or carries forward. Losing it is safe. | `orchestrator/state.go`, `core.PolicyState` | [10](10-cadence-model.md) |
| Policy status | `pass`, `fail`, `skip`, `error`, `na`, `waived`, `carried_forward`. | `core.PolicyStatus` | [06](06-aggregation.md) |
| Vault | Customer-owned storage that receives envelopes, results, summaries, manifests and state shards. | `core.Vault`, `internal/vault/` | [05](05-vault-layout.md) |
| Aggregation contract | The counts-only payload sent to SigComply Cloud when submission is enabled. | `core.SubmissionPayload` | [06](06-aggregation.md) |

## Axioms

### Axiom 1: evidence type is the join key

A policy names evidence types in `slots.<name>.accepts`. A plugin names evidence types in
`Emits()`. The planner binds a source to a slot when the two sets intersect. A policy has no
`source:` field, and `SlotRequest.PolicyID` is for logging only.

- Do: when a check "only works with AWS", add or widen an evidence type.
- Never: branch on `record.SourceID` in a policy, or on `SlotRequest.PolicyID` in a plugin.

Details: [04a](04a-evidence-type-registry.md). Extension points that rely on this:
[00](00-three-plugin-axes.md).

### Axiom 2: slot cardinality belongs to the policy

The policy declares how many sources a slot may take (`exactly-one`, `at-most-one`,
`one-or-more`, `optional`). The project picks sources within that limit. A `one-or-more` slot
evaluates the union of every bound source's records. See [03 §Slots](03-policy-spec.md#slots).

### Axiom 3: each policy fetches its own data

The collector calls `Collect` once per (policy, slot, source) binding. Ten policies on `aws.iam`
mean ten calls. There is no shared collection layer and no record cache across policies, so a
policy change has no side effect on another policy. The cost is API calls and a run that spans
minutes: each record's as-of time is its own `collected_at`.

### Axiom 4: CI schedules, the CLI enforces

CI cron jobs decide when `sigcomply check` runs and with which filter (`--cadence`, `--on-push`,
`--scheduled`). In scheduled mode the CLI reads each policy's state shard and either re-evaluates
or emits a `carried_forward` result that points at the prior signed envelope. The CLI never reads
another run's folder. Details: [09](09-ci-execution-model.md), [10](10-cadence-model.md).

## Scope and accounts

One project covers one framework, but can cover several accounts: configure a source more than
once with bracketed instance keys ([04 §Multiple plugin
instances](04-source-plugins.md#multiple-plugin-instances-api-plugins-only)). Records may carry a
signed `scope` as provenance ([04 §Record scope](04-source-plugins.md#record-scope-provenance-not-configuration)).
Nothing evaluates or aggregates by scope. Not built: per-scope aggregation on the wire.
