# SigComply CLI architecture

The top-level map of the CLI. Detailed design lives in [`docs/architecture/`](docs/architecture/);
the code is the source of truth for what is wired, and
[`docs/reference/commands.md`](docs/reference/commands.md) lists the commands.

The CLI runs inside the customer's own CI. It has two evidence flows. Automated policies evaluate
configuration pulled from vendor APIs with the customer's read-only credentials. Manual policies
collect documents the customer uploads: the CLI checks that a supported file is present for the
period, merges the files into one PDF to validate it, and signs a record that carries each
file's hash and the merged PDF's hash. It never judges what the documents say. The merged PDF is
stored in the run folder next to the signed record. Every evidence file is signed locally and written to a vault the customer owns. Only when the
customer opts in does the CLI send per-policy counts (never identities) to the SigComply Cloud
dashboard. The architectural point is "evidence without access".

## CLI and dashboard

- **The CLI (open source)** runs once per invocation: plan, collect, evaluate, write the vault,
  optionally submit counts. It keeps no history across runs and has no database.
  `sigcomply report` renders snapshot views of the vault.
- **SigComply Cloud (paid, private Rails app)** receives the counts-only `SubmissionPayload` and
  keeps them over time. What it does with them: [`06-aggregation.md`](docs/architecture/06-aggregation.md)
  §What the dashboard does with it.

The vault is the customer's data layer for both. Without the paid dashboard, a customer still
collects, evaluates and signs evidence in their own vault, and `sigcomply report` reads it back.
What the CLI alone does not provide is any view across runs.

## Core principles

Code comments cite these by number. The Sacred Invariants in [`AGENTS.md`](AGENTS.md) are the
enforced subset.

1. **The aggregation boundary.** No resource identifier leaves the customer environment. The
   cloud submission type cannot carry ARNs, emails, usernames or file hashes: only counts,
   statuses and policy IDs. (AGENTS.md Invariant #1; [`SECURITY.md`](SECURITY.md).)
2. **No history across runs.** A run reads the project config and its sources. It never reads
   prior run folders, never consults a database. The one exception is the per-policy state shard
   under `{vault}/state/` (`LastPassAt`, `LastRunStatus`, `NextDueAt`, the policy content hash),
   which only answers "is this policy due?" (`planner.IsDue`). Losing `state/` is recoverable: the
   next run re-evaluates everything. Cadence scheduling is the CI cron's job; cadence enforcement
   is the CLI's. See [`09-ci-execution-model.md`](docs/architecture/09-ci-execution-model.md) and
   [`10-cadence-model.md`](docs/architecture/10-cadence-model.md).
3. **Evidence is append-only.** Each run writes its own folder and never rewrites an earlier
   one. Period-level views are derived from the runs in a period. `state/` is the one mutable
   area, guarded by a monotonic write rule (`shouldAcceptWrite` in
   `internal/orchestrator/state.go`).
4. **Every evidence file is independently verifiable.** Per-file ephemeral Ed25519 signing; the
   public key travels in the envelope, so one file can be verified offline. This detects
   accidental drift, not deliberate re-signing by someone with vault write access. Storage-level
   immutability is the customer's job. Threat model: [`SECURITY.md`](SECURITY.md).
5. **Evidence type is not source plugin.** A policy depends on an evidence shape
   (`directory_user`, `firewall_rule`); any plugin can produce it. Policies never ask which plugin
   produced a record. (AGENTS.md Invariant #4.)
6. **Each policy fetches its own data.** No collection cache spans policies
   (`internal/collector/collector.go`). The cost is runtime and point-in-time consistency: a run
   is a stream of observations, each with its own `collected_at`, so a cross-slot join such as
   the roster join compares observations taken minutes apart.
7. **Determinism.** Given the same source responses, config and clock, a run produces the same
   records and results. Signatures, public keys and run IDs differ every run, because keys are
   ephemeral. Auditors diff runs.
8. **Project config is the customer's source of truth.** Framework, sources, exceptions,
   parameters, fiscal calendar and cadence overrides live in `.sigcomply.yaml`, versioned in git.
   The vault carries evidence; git carries decisions.
9. **One project = one repository = one framework.** Customers pursuing several frameworks use
   several repos. One project may still cover several cloud accounts or orgs by configuring a
   source more than once (see [`04-source-plugins.md`](docs/architecture/04-source-plugins.md)).
   Manual evidence uses one bucket per project.

## Layers

```
L9  Orchestrator   cmd/sigcomply, internal/orchestrator: wiring, run summary, exit codes
L8  Submitter      internal/submitter: optional cloud submission (counts only)
L7  Persistence    internal/vault + orchestrator: results, summary, manifest, state
L6  Aggregator     internal/aggregator: the privacy boundary, counts-only payload
L5  Evaluator      internal/evaluator: pass_when, rule:, manual presence check
L4  Collector      internal/collector: per-policy fetches, schema validation, signing
L3  Planner        internal/planner: bindings, period, cadence decision
L2  Registries     internal/registry: frameworks, sources, rules, evidence types, policies
L1  Core           internal/core: stable interfaces and shared types
L0  Specifications internal/spec: config and spec parsing and validation
```

Higher layers import lower ones, never the reverse. The per-package table, including the support
packages outside the stack (`sign`, `log`, `evidence_types`, `frameworks`, `sources`,
`manualcatalog`, `manualdue`, `report`, `scope`, `vendorfanout`, `fixturehygiene`) and the public
`plugin/` package, is in [`02-layers.md`](docs/architecture/02-layers.md).

## Repository layout

| Path | What it holds |
|---|---|
| `main.go`, `cmd/sigcomply/` | Cobra commands; `cmd/sigcomply/templates/` holds the `init-ci` workflow templates |
| `internal/` | Every package above; frameworks under `internal/frameworks/<fw>/`, sources under `internal/sources/<vendor>/` |
| `plugin/` | The only non-`internal` package: the API project-local extensions compile against |
| `contracts/` | Vendor API spec snapshots for drift detection ([`contracts/README.md`](contracts/README.md)) |
| `scripts/` | Fixture scan, contract fetch and diff, install script |
| `examples/` | Copyable CI configs |
| `docs/` | Customer docs; `docs/architecture/` and `docs/claude/` are agent and contributor docs |

## Vocabulary

Full definitions in [`01-conceptual-model.md`](docs/architecture/01-conceptual-model.md).

| Term | Meaning |
|---|---|
| Framework | A compliance regime (SOC 2, ISO 27001). |
| Control | One requirement in a framework, for example `CC6.1`. |
| Policy | A verifiable assertion contributing to a control. |
| Policy cadence | How often a policy must be evaluated: `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual` or `every:<duration>`. |
| Rule | The logic deciding a policy's outcome: a `pass_when` clause, or a Go/Rego `rule:`. |
| Source | Something producing evidence (`aws.iam`, `okta`, `manual.pdf`). |
| Evidence type | The shape of a piece of evidence; a versioned JSON Schema. |
| Slot | A named, typed input on a policy. |
| Binding | The mapping from a slot to one or more sources. |
| Evidence record | One piece of collected data. |
| Envelope | A signed file wrapping a batch of evidence records. |
| Period | An audit window, for example `2026-Q1`. |
| Run | One CLI invocation, with a run ID, a period and a commit. |
| Vault | Customer-owned storage for envelopes, results and summaries. |
| Project | The customer's deployment: config, vault and bindings. |

## Document map

| Doc | Covers |
|---|---|
| [`00-three-plugin-axes.md`](docs/architecture/00-three-plugin-axes.md) | The three plugin axes (manual input storage, vault, API sources) and their shared factory pattern. |
| [`01-conceptual-model.md`](docs/architecture/01-conceptual-model.md) | Glossary and the substitutability axioms. |
| [`02-layers.md`](docs/architecture/02-layers.md) | Each layer and package, and the contracts between them. |
| [`03-policy-spec.md`](docs/architecture/03-policy-spec.md) | Policy fields, the `pass_when` DSL, the `rule:` escape hatch. |
| [`04-source-plugins.md`](docs/architecture/04-source-plugins.md) | The source plugin contract, the built-in plugin set, testing a plugin. |
| [`04a-evidence-type-registry.md`](docs/architecture/04a-evidence-type-registry.md) | Evidence types, schema design rules, substitutability. |
| [`05-vault-layout.md`](docs/architecture/05-vault-layout.md) | Vault layout, envelope format, signing and verification. |
| [`06-aggregation.md`](docs/architecture/06-aggregation.md) | The privacy boundary, the wire format, the submission decision. |
| [`07-extensibility.md`](docs/architecture/07-extensibility.md) | Project-local policies, sources and backends via `sigcomply build`. |
| [`08-project-config.md`](docs/architecture/08-project-config.md) | Design rationale for `.sigcomply.yaml`. The key reference is [`docs/configuration.md`](docs/configuration.md). |
| [`09-ci-execution-model.md`](docs/architecture/09-ci-execution-model.md) | How the CLI runs in CI; `init-ci` scaffolding. |
| [`10-cadence-model.md`](docs/architecture/10-cadence-model.md) | Cadence and period, state shards, carry-forward, manual evidence periods. |
| [`11-testing-strategy.md`](docs/architecture/11-testing-strategy.md) | Test layers L0 to L4b and their conventions. |
| [`12-multicloud-sources.md`](docs/architecture/12-multicloud-sources.md) | AWS, GCP and Azure parity across shared evidence types. |
| [`13-isms-clauses-and-soa.md`](docs/architecture/13-isms-clauses-and-soa.md) | ISO 27001 management-system controls and the Statement of Applicability. |
| [`14-manual-evidence.md`](docs/architecture/14-manual-evidence.md) | The manual-evidence contract: folders, checks, fan-out, non-goals. |
| [`examples/`](docs/architecture/examples/) | Example `.sigcomply.yaml` files (AcmeCorp, multi-account, GCP, Azure, GitLab self-managed, multi-cloud). |

## Reading order

- First pass: this file, then `00-three-plugin-axes.md`, `01-conceptual-model.md` and
  [`examples/acmecorp.sigcomply.yaml`](docs/architecture/examples/acmecorp.sigcomply.yaml).
- Changing a layer: `02-layers.md`, then the doc for that layer's inputs and outputs.
- Adding a source plugin: `04-source-plugins.md`, `04a-evidence-type-registry.md`,
  `07-extensibility.md`, and [`docs/claude/recipes.md`](docs/claude/recipes.md).
- Adding a policy: `03-policy-spec.md` and the recipes.
- Reviewing the privacy and verification story: `06-aggregation.md`, `05-vault-layout.md`,
  [`SECURITY.md`](SECURITY.md).
