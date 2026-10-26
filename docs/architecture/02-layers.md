# 02: Layers and packages

The `sigcomply check` pipeline is ten numbered layers, L0 to L9. Higher layers import lower ones,
never the reverse. Each layer maps to a package under `internal/`, except L7, which is split
between `internal/vault` and `internal/orchestrator`. Read the section for the layer you change,
then the package's `doc.go`.

## Package map

| Layer | Package | Owns | Entry point |
|---|---|---|---|
| L0 Specifications | `internal/spec` | Parsing and validating `.sigcomply.yaml`, project-local `policy.yaml`, evidence-type files and plugin manifests | `spec.LoadProjectConfig`, `spec.LoadPolicy`, `spec.ValidatePassWhen` |
| L1 Core types | `internal/core` | Interfaces and shared types: `Policy`, `Slot`, `SourcePlugin`, `EvidenceRecord`, `Envelope`, `Vault`, `PolicyResult`, `SubmissionPayload` | none (types only) |
| L2 Registries | `internal/registry` | Per-run catalogs of frameworks, sources, rules, evidence types and policies | `registry.Set`, `registry.NewSet` |
| L3 Planner | `internal/planner` | Policy selection by mode and filter, bindings, effective parameters, exceptions, period, cadence decision | `planner.Plan` |
| L4 Collector | `internal/collector` | Calling `Collect` per binding, retry, schema validation, envelope signing and writing | `collector.Collect` |
| L5 Evaluator | `internal/evaluator` | `pass_when` DSL, `rule:` (Go or Rego), the manual presence check | `evaluator.Evaluate` |
| L6 Aggregator | `internal/aggregator` | Reducing results to the counts-only `SubmissionPayload` | `aggregator.Build` |
| L7 Persistence | `internal/vault` (backends), `internal/orchestrator` (`persistResults`, `writeManifest`, `state.go`) | Writing `result.json`, `summary.json`, the signed `manifest.json` and state shards | `vault.FromConfig` |
| L8 Submitter | `internal/submitter` | Deciding whether to submit, OIDC token, `POST /api/v1/runs` | `submitter.Decide`, `submitter.Submit` |
| L9 Orchestrator | `internal/orchestrator`, `cmd/sigcomply` | Wiring L3 to L8, run summary text, exit codes; Cobra commands | `orchestrator.Run`, `cmd/sigcomply/check.go` |

Support packages (outside the numbered stack):

| Package | Role | Used by |
|---|---|---|
| `internal/sign` | Canonical JSON (`sign.Encode`), envelope and manifest signing and verification | L4, L7, `report` |
| `internal/log` | Stderr logger with redaction (`log.Redact`) | `internal/orchestrator`, `cmd/sigcomply` |
| `internal/evidence_types` | Embedded JSON Schemas (`schemas/*.json`) | L2 |
| `internal/frameworks`, `frameworks/builtin`, `frameworks/soc2`, `frameworks/iso27001` | Framework registry and the Go-built controls, policies and manual catalogs | L2 |
| `internal/sources`, `sources/builtin`, `sources/<vendor>/...` | Source factory registry (`sources.RegisterFactory`, `sources.Build`), instances, token resolution, error classification, every in-tree plugin | `cmd/sigcomply`, L4 |
| `internal/sources/manual` (+ `builtin`, `s3`, `gcs`, `azureblob`, `fileconv`, `pdfmerge`) | The `manual.pdf` plugin and its reader backends | L4 |
| `internal/sources/sourcetest` | Shared plugin test harness (conformance, cassettes, spec validation) | tests |
| `internal/vault/vaulttest` | Backend-agnostic vault test suite | tests |
| `internal/manualcatalog` | The SPA-facing catalog export type and derive helpers | `evidence catalog` |
| `internal/manualdue` | `sigcomply evidence due`: lists manual entries whose current folder is empty | `evidence due` |
| `internal/vendorfanout` | Resolves fan-out catalog entries against `experimental.vendors` | L9 |
| `internal/scope` | Estate completeness check (`experimental.scope`) | L9 |
| `internal/report` | Read-only vault snapshot views and their text/JSON/CSV formatters | `report` |
| `internal/fixturehygiene` | Test that drives `scripts/check-fixtures.sh` | tests |
| `plugin/` (public) | Type aliases and `RegisterSource`, `RegisterVaultBackend`, `RegisterManualReader` for project-local Go code, which cannot import `internal/` | `.sigcomply/plugins/` code built by `sigcomply build` |

## L0: Specifications

`internal/spec` turns bytes into validated structs. Loaders are strict (`KnownFields(true)`)
except inside a `sources:` entry, whose keys each factory parses itself. A `schema_version` is
required on project-local `policy.yaml` (`policy.v1`). Shipped frameworks are Go, not files: they
never pass through L0.

## L1: Core types

`internal/core` holds types and interfaces only, no framework- or source-specific logic. Read the
struct definitions in code rather than copying them into docs.

## L2: Registries

`registry.Set` holds one `Registry[T]` per kind. It is filled at startup from the blank-imported
`builtin` packages, from project-local files (`orchestrator/project_local.go`:
`loadProjectEvidenceTypes`, `loadProjectRules`, `loadProjectPolicies`) and from
`cmd/sigcomply/check.go` (`registerProductionSources`). The registry pattern itself:
[04 §The factory contract](04-source-plugins.md#the-factory-contract).

## L3: Planner

Input: project config, registries, filter, prior state shards, period time. Output: a
`RunPlan` of `PlannedPolicy` values with bindings, effective parameters, exceptions and an
evaluate-or-carry-forward decision.

- The run period comes from `planner.PeriodTime` (`period.time_basis`: `commit` default, or
  `wall_clock`). Manual bindings get the entry's cadence window from `planner.CadencePeriod`.
- An empty `Emits() ∩ Accepts` for an explicit binding, an unknown source key, or a bad
  parameter is a config error (exit 3).
- Source plugins are built before planning, in `cmd/sigcomply/check.go`
  (`registerProductionSources`), so missing credentials fail before the plan exists.

## L4: Collector

For each planned policy that needs evaluation, and each binding:

1. Skip policies covered by a whole-policy exception.
2. Build the `SlotRequest` (`buildSlotRequest`), including planner-stamped params such as
   `period_start`, `period_end`, `catalog_id`, `period_id`, `prior_period_id`.
3. Call `Collect` through `withRetry`.
4. Validate every record against its schema (`validateRecords`), then check its type is in the
   slot's accepted set (`checkAcceptedTypes`). The first failure fails the binding; the
   evaluator marks the policy `error`, and the run exits 2.
5. Sort records by `ID`, group by evidence type (`groupByType`) and write one signed envelope per
   (policy, evidence type, source) at `envelopePath`.

`SourcePlugin.Init` is never called; factories fully configure the plugin.

## L5: Evaluator

Runs once per planned policy with the records grouped by slot.

- `automated`: the `pass_when` clauses, or the `rule:` looked up in `registry.Set.Rules`. An
  unregistered rule makes the policy `error`.
- `manual`: `manual_check.go` reads `file_present`, `in_temporal_window` and `file_valid` from the
  `signed_document` record. The window and grace are computed by the `manual.pdf` plugin, not
  here.
- Records missing a referenced field, or a filter that cannot be evaluated, make the policy
  `error`, never a silent pass. DSL rules: [03](03-policy-spec.md).

## L6: Aggregator

`aggregator.Build` turns `[]core.PolicyResult` into `core.SubmissionPayload`. Messages are
regenerated from counts. The payload type has no free-form fields;
`TestSubmissionPayload_StructurallyCountsOnly` (`internal/core/cloud_test.go`) fails the build if
one is added. Field list and versions: [06](06-aggregation.md).

## L7: Persistence

- `persistResults` writes each `result.json` and the run's `summary.json`. A failed write is a
  warning.
- `writeManifest` writes `manifest.json` with the SHA-256 of every file the run wrote
  (`recordingVault.FileHashes`) and signs it. A signing failure exits 2; a failed write is a
  warning.
- `state.go` reads and writes state shards in scheduled mode. It never reads run folders.
- The merged manual PDF is not written to the vault. The envelope records the hashes of the
  source files.

Layout: [05](05-vault-layout.md).

## L8: Submitter

`submitter.Decide` submits only when a cloud URL is set (`cloud.base_url` or `--cloud-url`) and
the run is in CI with an OIDC token; `--no-cloud` turns it off. A failed submission is a warning
and does not change the exit code. Auth details: [`docs/claude/auth.md`](../claude/auth.md);
payload: [06](06-aggregation.md).

## L9: Orchestrator

`orchestrator.Run` wires bootstrap, planning, collection, evaluation, scope check, persistence and
submission, then `renderAndExitCode` prints the summary and picks the exit code (see
§Layered errors). `cmd/sigcomply` owns flags, source construction and the other commands.

## Cross-cutting rules

### Determinism

Given the same records, config and `now`, a run writes the same bytes except signatures and
public keys (a fresh keypair per file).

- The collector sorts records by `ID`; a plugin's own order does not matter.
- Signing uses canonical JSON (`sign.Encode`).
- Rules get `now` from the input, never from `time.Now()`.
- Plugins set `IdentityKey` when the type has a cross-source identity
  ([03 §Cross-source dedup](03-policy-spec.md#cross-source-dedup-clause-level-identity_key)), and
  do not invent timestamps in payloads; `CollectedAt` is the fetch time.

Live sources are not deterministic (ordering, vendor timestamps). The guarantee is replay: the
same recorded records give the same result.

### Per-file signing

Each envelope is signed with its own ephemeral Ed25519 key over canonical JSON of
`{format_version, produced_at, records}` (`sign.Envelope`). The public key is in the file, so one
file verifies offline. The run manifest is signed the same way. What this does and does not
protect against: [`SECURITY.md`](../../SECURITY.md).

### Logging and redaction

| Output | Contents | Identifiers |
|---|---|---|
| stdout | `check` run summary; `report` views (text, JSON, CSV) | Reports can include policy IDs and violation reasons; never credentials |
| stderr | `internal/log` lines; `-v` adds debug lines | Passed through `log.Redact` (email, ARN, UUID, AWS key ID, JWT become `<redacted:type>`). No flag disables it |
| vault | Envelopes, results, manifest | Kept: the vault is the customer's |
| cloud | `SubmissionPayload` | Counts only |

Source plugins don't import `internal/log` and no lint rule checks their output. Rule for new
plugin code: return errors instead of printing, and never print credentials or payloads.

### Layered errors

| Where | Effect | Exit |
|---|---|---|
| Spec load, config validation, source construction (incl. missing credentials), planning, invalid flags | Run stops | 3 (invalid or conflicting flags: 2) |
| Collection or schema failure on a binding | Policy `error`, run continues | 2 |
| Rule or DSL evaluation error | Policy `error`, run continues | 2 |
| `result.json`/`summary.json`/`manifest.json` write | Warning | unchanged |
| Manifest signing | Run fails | 2 |
| Submission | Warning | unchanged |
| Any `fail`, or incomplete estate under `experimental.scope` | Reported | 1 (unless `ci.fail_on_violation: false`) |

An `error` status outranks `fail`: `renderAndExitCode` returns 2 when any policy errored. There is
no `recover()`; a panic exits 2 with a stack trace (Go's default).

### No telemetry

The CLI sends nothing anywhere except the optional cloud submission.

## Not layers

- No collection scheduler: L4 runs bindings in sequence.
- No evidence cache across policies (Axiom 3 in [01](01-conceptual-model.md)).
- Output formatting lives with its command: `check`'s summary in `orchestrator`, `report`'s
  formats in `internal/report`.
