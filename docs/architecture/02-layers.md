# 02 — Layers

The CLI is organized into ten layers. Each layer has a single
responsibility, a defined input and output, and an interface to the
layer above and below. Layers are numbered bottom-up; higher numbers
depend on lower numbers, never the reverse.

This document specifies what each layer owns, the contracts at the
seams, and the invariants that hold across the stack.

---

## The stack

```
┌────────────────────────────────────────────────────────────────────┐
│  L9  Orchestrator       Wires L3–L8; CLI command; CI integration   │
├────────────────────────────────────────────────────────────────────┤
│  L8  Submitter          Optional cloud submission                  │
├────────────────────────────────────────────────────────────────────┤
│  L7  Persistence        Vault writes: envelopes, results, summaries│
├────────────────────────────────────────────────────────────────────┤
│  L6  Aggregator         Privacy boundary; counts-only schema       │
├────────────────────────────────────────────────────────────────────┤
│  L5  Evaluator          Rule execution per policy                  │
├────────────────────────────────────────────────────────────────────┤
│  L4  Collector          Per-policy source fetches + envelope sign  │
├────────────────────────────────────────────────────────────────────┤
│  L3  Planner            Resolve bindings; order policies           │
├────────────────────────────────────────────────────────────────────┤
│  L2  Registries         Framework, Source, Rule, EvidenceType      │
├────────────────────────────────────────────────────────────────────┤
│  L1  Core domain types  Go interfaces and structs                  │
├────────────────────────────────────────────────────────────────────┤
│  L0  Specifications     YAML/JSON: frameworks, policies, ET, config│
└────────────────────────────────────────────────────────────────────┘
```

---

## L0 — Specifications

**Owns.** All declarative artifacts. Versioned. Data-as-code.

- Framework specs (shipped with the binary, one per framework)
- Policy specs: framework-shipped policies are authored in **Go** via
  `autoPolicy{...}.policy()` builders (no on-disk `policy.yaml`);
  project-local custom policies are on-disk `policy.yaml`. Either way a
  policy carries `evidence_mode`, and (for automated) `pass_when:` (the
  declarative condition DSL) or, rarely, `rule:` (escape hatch).
  `pass_when:` is the primary and only-shipped path; `rule:` is unused
  by any shipped policy.
- Evidence type schemas (JSON Schema documents, one per type+version,
  under `internal/evidence_types/schemas/`)
- Source plugins declare their emitted types in **code** via
  `Emits() []string` — there is no in-tree `plugin.yaml` manifest
  (`plugin.yaml` is only for project-local plugins under
  `.sigcomply/plugins/`)
- Project config (`.sigcomply.yaml`, customer-authored): includes
  `policy_overrides` for per-policy `evidence_mode` overrides
- Manual evidence catalog (generated in Go from each framework's
  `manualSpecs()`; no embedded `catalogs/*.yaml`)

**Format.** YAML for human-authored project config and project-local
policies; JSON Schema for evidence type schemas; JSON for
machine-emitted artifacts (run metadata, summaries). Framework-shipped
policies and manual catalogs are Go, not files.

**Stability rules.** Every spec carries a `schema_version`. Backward-
incompatible changes bump the major version of the relevant spec.
Evidence type schemas are append-only: new fields are optional; renames
and removals require a new version (`directory_user.v2`).

**No code in L0.** Nothing in this layer executes. Specs are parsed by
L1, validated by L2, and consumed by L3 onwards.

---

## L1 — Core domain types

**Owns.** The stable Go types and interfaces that every other layer
depends on. Frozen once published; changes here ripple everywhere.

**`internal/core/` is the source of truth for these signatures.** The
listings below are illustrative and elide fields; when they disagree
with the Go in `internal/core/`, the Go wins — read it rather than
trusting a stale snippet here.

```go
type Framework interface {
    ID() string
    Version() string
    Controls() []Control
    Policies() []PolicyRef       // refs to shipped policy specs
}

type Control struct {
    ID, Name, Description, Category string
    BaselineSeverity                Severity
}

// Illustrative — see internal/core and internal/spec for the real fields.
type Policy struct {
    ID, Description, Remediation string
    Controls                     []ControlRef   // multi-framework mapping
    Severity                     Severity
    EvidenceMode                 string         // "automated" | "manual" (required)
    Cadence                      string         // continuous|...|annual or every:<dur>
    OnPush                       bool
    Slots                        map[string]Slot // automated only
    Parameters                   map[string]ParameterSpec
    PassWhen                     *Condition      // primary evaluation path
    Rule                         string          // escape hatch; unused by shipped policies
    CatalogEntry                 string          // manual only
}

type Slot struct {
    Accepts     []string        // evidence type IDs the slot will consume;
                                // a source matches when source.Emits() ∩ Accepts ≠ ∅
    Cardinality SlotCardinality // exactly-one|one-or-more|optional|at-most-one
    Required    bool
}

type EvidenceType struct {
    ID             string
    Version        int
    Schema         json.RawMessage // JSON Schema
}

type EvidenceRecord struct {
    Type        string
    ID          string          // stable within source (e.g. AWS IAM ARN)
    IdentityKey string          // optional cross-source identity (e.g. email);
                                // when set, enables dedup across sources bound
                                // to the same slot. See 03-policy-spec.md
                                // §Cross-source dedup.
    Payload     json.RawMessage
    SourceID    string
    CollectedAt time.Time
}

type Envelope struct {
    FormatVersion string
    ProducedAt    time.Time
    Records       []EvidenceRecord
    Signature     EnvelopeSignature
}

type EnvelopeSignature struct {
    Algorithm string // "ed25519"
    PublicKey []byte
    Value     []byte
}

type SourcePlugin interface {
    ID() string
    Emits() []string                                       // evidence type IDs
    Init(...) error
    Collect(ctx context.Context, req SlotRequest) ([]EvidenceRecord, error)
}

type SlotRequest struct {
    PolicyID      string   // diagnostic-only — never branch on it
    AcceptedTypes []string // = slot.Accepts ∩ plugin.Emits(), NOT the raw slot.Accepts
    SlotName      string
    Params        map[string]any
}

type Rule interface {
    ID() string
    Evaluate(ctx context.Context, in RuleInput) (RuleResult, error)
}

type RuleInput struct {
    PolicyID string
    Slots    map[string][]EvidenceRecord
    Params   map[string]any
    Now      time.Time
}

type RuleResult struct {
    Status     PolicyStatus // pass|fail|skip|error|na|waived|carried_forward
    Violations []Violation
    Diag       map[string]any
}

type Violation struct {
    ResourceID string
    Reason     string
    Details    map[string]any
}

type Vault interface {
    Init(ctx context.Context) error
    PutEnvelope(ctx context.Context, path string, e *Envelope) error
    PutJSON(ctx context.Context, path string, body any) error
    PutBinary(ctx context.Context, path string, body []byte, meta map[string]string) error
    GetBinary(ctx context.Context, path string) ([]byte, error)
    List(ctx context.Context, prefix string) ([]string, error)
}

type CloudClient interface {
    Submit(ctx context.Context, payload SubmissionPayload) error
}
```

**Invariant.** No layer above L1 may add fields to these types
that carry resource identifiers across the L6 boundary. The
`SubmissionPayload` type in particular is the structural privacy
guarantee — see L6.

---

## L2 — Registries

**Owns.** In-process catalogs of the things that can be referenced by
ID. Populated at process startup; immutable thereafter.

| Registry | Populated from | Lookup key |
|---|---|---|
| `FrameworkRegistry` | In-binary framework specs (shipped) | `framework_id` |
| `SourceRegistry` | Source-plugin factories registered via `init()` from in-binary `internal/sources/...` packages and from project-local `.sigcomply/plugins/...` packages compiled in by `sigcomply build` | `source_id` |
| `RuleRegistry` | In-binary rules populated from each framework's `Rules()` (both shipped frameworks return nil — zero in-binary rules today). **Consulted only for policies with a `rule:` escape-hatch reference; no shipped policy uses one, so `pass_when:` policies never touch it.** Project-local *Rego* rules and YAML policies load; project-local *Go* rules are not yet wired (no `rule.Register` hook — the rule registry is per-`Set`, populated only from `framework.Rules()`). | `rule_ref` |
| `EvidenceTypeRegistry` | In-binary type schemas (JSON Schema files embedded via `//go:embed schemas/*.json` from `internal/evidence_types/schemas/`) + project-local under `.sigcomply/evidence_types/` | `evidence_type_id` |
| `PolicyRegistry` | Framework-shipped policy specs + project-local policies under `.sigcomply/policies/` | `policy_id` |

**Self-registering sources.** The `SourceRegistry` is populated by each
source package's `init()` function calling
`sources.RegisterFactory(id, factoryFn)`. The orchestrator imports the
in-tree source packages purely for their side effect of registration;
it has no `switch sourceID { case "aws.iam": ... }` and is generic
over the registered set. Third-party project-local plugins follow the
exact same pattern under `.sigcomply/plugins/`. Detail: see
[`04-source-plugins.md`](04-source-plugins.md) §The factory contract.

**Embedded evidence-type schemas.** Each
`internal/evidence_types/schemas/<id>.v<n>.json` (a JSON Schema
document) is compiled into the binary via `//go:embed schemas/*.json`.
The
`EvidenceTypeRegistry` is loaded at orchestrator bootstrap; the
collector validates every emitted `EvidenceRecord.Payload` against the
registered schema before signing. A schema-conformance failure is a
configuration error (exit code 3). Detail: see
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md).

**Loading sequence.**

1. Load in-binary registries (compiled-in via `embed.FS` and `init()`
   side effects).
2. Discover and load `.sigcomply/` extensions.
3. Validate:
   - Policies with `rule:` → reference resolves in `RuleRegistry`
   - Policies with `pass_when:` and no `rule:` → `pass_when:` is
     structurally valid (quantifier present, conditions reference
     real fields in the accepted evidence type schemas)
   - Policies with `evidence_mode: automated` and neither `pass_when:`
     nor `rule:` → exit 3 (no evaluation path declared)
   - Every `policy.slot.accepts[*]` resolves to a registered evidence
     type; every `binding.source` resolves to a registered plugin;
     every bound source emits at least one of the slot's accepted types
     (`source.Emits() ∩ slot.Accepts ≠ ∅`)
   - Policies with `evidence_mode: manual` do not require slot
     declarations or `pass_when:`/`rule:` (all handled implicitly)
4. If any validation fails, exit with config error (exit code 3).

**Invariant.** Registries are read-only after startup. No runtime
discovery, no hot-reload, no mutation mid-run.

---

## L3 — Planner

**Owns.** Reading the project config + selected framework + period,
producing an ordered, fully-resolved execution plan.

**Inputs.**

- Project config (`.sigcomply.yaml`)
- Framework spec (from `FrameworkRegistry`)
- All registries (L2)
- Current time (for period derivation)
- Cadence filter flags (`--cadence`, `--on-push`, `--cadences`, `--pr`,
  `--scheduled` — mutually exclusive; there is no `--policies`/`--controls`)

**Outputs.**

- `RunPlan`:
  - `run_id`, `framework`, `period_id`, `commit_sha`, `commit_time`
  - `policies []PlannedPolicy` — each with:
    - resolved `Policy` from registry
    - `evidence_mode` (from policy spec, overridden by project config)
    - for `automated` policies: resolved bindings (slot → source
      plugin instances), `pass_when` condition or resolved rule
    - for `manual` policies: resolved `manual.pdf` binding + catalog
      entry path, no `pass_when`/rule
    - effective parameter values (defaults overridden by project config)
  - `exceptions []ResolvedException`
  - `vault` configuration

**Behavior.**

- Period derived from `f(commit_time, fiscal_calendar)` (see
  `01-conceptual-model.md` §12).
- For `automated` policies: validates that every required slot has at
  least one binding; validates `source.Emits() ∩ slot.Accepts ≠ ∅`.
- For `manual` policies: resolves the `catalog_entry` to a PDF path;
  no slot bindings to validate.
- Resolves exception matchers against policy IDs.
- Fails fast: any unresolved binding, missing required slot, or
  parameter out-of-bounds value is a planning error (exit 3), not a
  runtime error.

**Invariant.** The planner does no I/O against external systems. It
reads config, registries, and the git context — that's it. No source
plugin is initialized at planning time.

---

## L4 — Collector

**Owns.** Executing per-policy source fetches and producing signed
envelopes. Each policy in the plan is processed independently.

**Per policy:**

1. For each slot in the policy:
   a. For each source bound to the slot:
      - Initialize the source plugin instance (if not yet for this run)
      - Invoke `plugin.Collect(ctx, req)` (a `core.SlotRequest` carrying
        `AcceptedTypes` = `slot.Accepts ∩ plugin.Emits()`, `SlotName`,
        `Params`, and a diagnostic-only `PolicyID`) to fetch records
      - Validate each record's `Payload` against the full draft-07 JSON
        Schema registered for `record.Type` in `EvidenceTypeRegistry`
        (enum/format/pattern/min/max/nested/required — not just
        `required`). Records for evidence types not in the slot's
        `Accepts` are rejected at planning time, so the collector only
        validates against the schemas of accepted types.
   b. Aggregate all records for the slot.
2. For each (slot, source) pair, write one envelope:
   - Generate a fresh Ed25519 keypair
   - Sign canonical JSON of `{format_version, produced_at, records}`
   - Discard the private key
   - Persist the envelope via the vault (L7) at the policy's envelope path
3. Hand the per-slot record collections to the evaluator (L5).

**Error handling.**

- A source-level error (network, auth) marks every policy depending on
  that source as `error` status, with a diagnostic. Other policies
  proceed.
- Schema validation is strict: the **first** non-conforming record
  fails the binding and tags the affected policy `error` (exit 3).
  There is no drop-and-continue and no ">5% of records" threshold. (A
  permissive drop-and-continue mode is design-intent only — not
  implemented; see [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md).)

**Invariant.** Per the KISS-no-DRY decision, no record cache spans
policies. Source `Collect` is invoked once per policy-binding even
if the same `(plugin, slot)` recurs across policies.

---

## L5 — Evaluator

**Owns.** Evaluating each policy's pass condition against the records
collected for it. Three paths, selected by `evidence_mode` and what
evaluation declaration the policy carries.

**Per policy:**

1. Skip if the policy is fully covered by a `na` or `waived` exception.
2. Skip with status `skip` if required slots have no records (e.g.
   collector returned empty for an automated policy).
3. Mark `error` if any of the policy's source bindings produced an
   error in L4.
4. Otherwise — evaluate via the appropriate path:

   **Path A — `evidence_mode: manual` (universal PDF-presence check):**
   Read the manifest produced by the `manual.pdf` collector. Check
   `file_present`, `in_temporal_window` (using the policy's
   `grace_period_days` parameter), and `file_valid`. No rule
   invocation, no `pass_when:` evaluation. Status is `pass` iff all
   three are true; `fail` otherwise with a structured message naming
   the expected upload path.

   **Path B — `evidence_mode: automated` with `pass_when:` (primary):**
   The evaluator interprets the `pass_when:` condition DSL directly
   against the collected records. Deduplicates by `identity_key` when
   the accepted evidence type declares one. Generates violations with
   the template from `violation_message:` or the default. Pure
   in-process evaluation; no OPA, no rule registry lookup.

   **Path C — `evidence_mode: automated` with `rule:` (escape hatch):**
   Construct `RuleInput` with slots, effective parameters, and `Now`.
   Call `rule.Evaluate(ctx, in)`. The rule returns `RuleResult` with
   status and violations. Rules are pure functions; they do no I/O.
   Rego rules run in OPA's sandbox; Go rules are reviewed at PR time
   for side-effect-freedom.

5. Apply exception suppression: resource-scoped exceptions reclassify
   matching violations as `waived` and recompute the per-policy status.

**Output.** Per-policy `PolicyResult`:

```go
type PolicyResult struct {
    PolicyID          string
    Controls          []ControlRef
    Status            PolicyStatus
    Severity          Severity
    EffectiveParams   map[string]any
    Violations        []Violation
    ResourcesEvaluated int
    ResourcesFailed    int
    EvidenceEnvelopes  []string  // paths into the vault
    Diag               map[string]any
}
```

---

## L6 — Aggregator

**Owns.** Producing the cloud submission payload from per-policy results.
This is the privacy boundary.

**The aggregation contract** (full detail in
[`06-aggregation.md`](06-aggregation.md)):

```go
type SubmissionPayload struct {
    Schema        string         // "sigcomply.cloud.v3"
    RunID         string
    Framework     string
    PeriodID      string
    CommitSHA     string         // exposed; user already opts in via repo
    CommitTime    time.Time
    CLIVersion    string
    Environment   CIEnvironment
    Summary       RunSummary     // counts only
    Policies      []AggregatedPolicy  // per-policy counts only
}

type AggregatedPolicy struct {
    PolicyID            string
    Controls            []ControlRef  // v3: multi-framework control mapping
    Status              PolicyStatus
    Severity            Severity
    Category            string
    ResourcesEvaluated  int
    ResourcesFailed     int
    Message             string  // generated from counts; never forwarded violation text
}
```

There is no field for violations, no field for resource IDs, no
`map[string]any` extensibility hook. Widening the contract is a code
change at the L6 boundary, gated by review.

**Behavior.**

1. For each `PolicyResult`, project into `AggregatedPolicy`.
   `Message` is regenerated from counts using a deterministic
   template, *never* copied from the rule's violation text.
2. Compute `RunSummary` (total/passed/failed/skipped/error counts,
   compliance score).
3. Stamp environment metadata (CI detection from L9).

**Invariant.** L6 is the only producer of `SubmissionPayload`.
L7 (vault) never touches `SubmissionPayload`. L8 (cloud) only
*consumes* `SubmissionPayload`.

---

## L7 — Persistence

**Owns.** Writing to the customer's vault. Append-only per run.

**Writes per run** (see [`05-vault-layout.md`](05-vault-layout.md) for
the full structure):

- `manifest.json` at run root — schema `"run.v1"`, a single-level
  Merkle of `file_hashes`, itself signed once with its own ephemeral
  keypair. Fields: `schema_version`, `run_id`, `framework`, `period_id`,
  `started_at`, `completed_at`, `file_hashes`, `exceptions_applied`,
  `signature` (and nothing else — the elaborate multi-field manifest
  with commit_sha / cli_version / evidence_type_versions / etc. is not
  implemented).
- `summary.json` at run root (full-fidelity run summary)
- For each policy:
  - `envelopes/...json` (signed evidence envelopes from L4)
  - `attachments/...` (manual PDFs mirrored as siblings)
  - `result.json` (full `PolicyResult` including violations)

**Period membership** is reflected in the run path; there is no
authoritative period-state file. (No `period_state.json` cache exists —
period state is derived by readers from the union of run folders.)

**Behavior.**

- All writes go through the `Vault` interface (L1), backend-agnostic.
- Writes are idempotent at the path level: a run's path includes its
  run_id, so the run cannot collide with another.
- Vault errors are warnings, not fatal — the cloud submission carries
  the same data anyway (in aggregated form), and re-runs can re-persist.

**Invariant.** L7 never reads from the vault during the same run.
The vault is one-way for the CLI; bidirectional reads are the auditor's
or dashboard's job.

---

## L8 — Submitter

**Owns.** Sending the `SubmissionPayload` to the configured cloud
endpoint, if cloud submission is enabled.

**Behavior.**

1. Check whether submission is enabled (project config + CI
   auto-detection + flags).
2. If enabled and not in CI without OIDC, attempt to acquire an OIDC
   token from the CI provider (GitHub Actions, GitLab CI).
3. POST the `SubmissionPayload` (and only the `SubmissionPayload`) to
   `{cloud_base_url}/api/v1/runs`.
4. Handle response: log success, log failures, never block the run.

**The cloud is optional.** If `cloud_base_url` is unset and no
managed-mode flag is on, L8 is a no-op. Self-hosted deployments swap
the `CloudClient` implementation (still gated by the same
`SubmissionPayload` contract).

**Invariant.** L8 never sees `PolicyResult`, only `SubmissionPayload`.
Type system prevents the boundary leak.

---

## L9 — Orchestrator

**Owns.** The CLI command itself. Wires L3 through L8. Handles flags,
config, CI environment detection, exit codes, and human-facing output.

**Sequence for `sigcomply check`:**

1. Load config (`--config` flag or default search path); apply env
   and flag overrides.
2. Init registries (L2) — load shipped + project-local extensions.
3. Plan (L3) → `RunPlan`. On planning error → exit 3.
4. Collect (L4) → records + envelopes (writes via L7).
5. Evaluate (L5) → `[]PolicyResult` (writes results via L7).
6. Persist run summary (L7).
7. Aggregate (L6) → `SubmissionPayload`.
8. Submit (L8) if enabled.
9. Render output and exit with the appropriate code. `sigcomply check`
   emits one fixed text summary (no `-o`/format flag); only `sigcomply
   report` renders alternate formats (`text`/`json`/`csv`; pdf is
   deferred). The `output.format` config key validates `text`/`json`/
   `junit` but no formatter renders `junit`, and `sarif` is rejected by
   the validator — there is no SARIF formatter.
   Exit codes:
   - `0`: all policies pass (or are NA/waived)
   - `1`: at least one fail
   - `2`: execution error (collector errors, panics)
   - `3`: config / planning error

**The orchestrator is the only layer that talks to the human.** All
other layers communicate via typed inputs and outputs.

---

## Cross-cutting invariants

These don't fit neatly in any single layer; they bind the stack.

### Determinism

The CLI is deterministic with respect to its **inputs**: given
identical config, identical evidence records, and identical `now`,
the CLI produces byte-identical outputs except for the ephemeral
signing keypairs (a fresh keypair per envelope and per manifest is
generated each invocation, and the signature value changes
accordingly).

Achieved inside the CLI by:

- Sorting all map iterations before serialization
- Canonical JSON for signing (RFC 8785-style)
- Stamping all timestamps from a single `now` captured at run start
- No `time.Now()` calls inside rule evaluation; rules see `input.Now`
- Sorting evidence records by `ID` before serializing them into
  envelopes
- No randomness in rules (Ed25519 keypair generation uses the system
  CSPRNG, but the keypair lives only in the envelope — given the
  *recorded* public key, signature verification is deterministic)

**What's not deterministic** — back-to-back runs against the same
live source system will *not* produce byte-identical outputs because:

- Source APIs return non-deterministic ordering across calls; plugins
  normalize this by sorting records by `id` before emitting them.
- Source APIs embed their own timestamps in payloads (`last_used_at`,
  `created_at`); these change continuously even when the underlying
  state is stable. The payload reflects what the source reported at
  `collected_at`; this is by design.
- Each run mints a fresh Ed25519 keypair per envelope. The signature
  value differs even when the signed bytes are identical.

The practical determinism guarantee is: **two runs given the same
recorded inputs (e.g., replaying a vault's records) produce
byte-identical results modulo signature values**. This makes evidence
auditable (an auditor can re-run the rule against the envelope's
records and confirm the policy result) without making it
reproducible-from-scratch-against-live-systems (which would be
neither achievable nor desirable).

### Plugin determinism invariant

Source plugins are required to:

1. **Sort emitted records by `ID` lexicographically** before returning
   from `Collect`. This makes envelope bytes stable across calls when
   the underlying source state is stable.
2. **Set `IdentityKey` whenever the evidence type has a meaningful
   cross-source identity.** See
   [`03-policy-spec.md`](03-policy-spec.md) §Cross-source dedup.
3. **Not embed wall-clock timestamps in records beyond what the
   source itself provides.** Use `EvidenceRecord.CollectedAt` for the
   fetch time, not a synthetic timestamp inside the payload.

### Versioning at every join

Persisted artifacts carry the version of their schema:

- `Envelope.FormatVersion` = `"envelope.v1"`
- `manifest.json` carries `schema_version` = `"run.v1"` (plus
  `run_id`, `framework`, `period_id`, `file_hashes`, signature — see
  L7; it does **not** embed cli_version or an evidence-type-version set)
- `result.json` carries the policy's `rule_version`

A vault written in 2026 is readable in 2031 without ambiguity.

### Per-file signing

Every envelope is independently verifiable. An auditor with a single
`.json` file can:

1. Read the envelope's embedded public key.
2. Recompute canonical JSON of `{format_version, produced_at, records}`.
3. Verify the signature against the public key.

No external state required. The CLI binary is not required for
verification. (The Manual Evidence SPA's `/verify` page implements
exactly this check.)

### The aggregation boundary, structurally enforced

`SubmissionPayload` is the only type L8 sees. It has no
`map[string]any`, no `Details` blob, no `Violations` slice, no fields
typed as `interface{}`. Every field is concretely typed and represents
either a count, a status, or already-public metadata (commit SHA, repo
name — which the customer already published).

Adding any field that *could* leak identity (`failed_users []string`,
`details map[string]any`, etc.) requires a type change here. That's
the gate.

### Failure visibility

Every policy result has one of: `pass | fail | skip | error | na |
waived`. Silent degradation is forbidden. A collector error becomes
`error` status with a diagnostic, surfaced in both the vault and the
aggregated submission. Auditors learn why each policy produced its
result.

### Logging and redaction

The CLI emits two output streams plus on-disk artifacts:

| Stream | Contents | Identifiers allowed? |
|---|---|---|
| **stdout** | `sigcomply check` emits one fixed text run summary (counts + control names). `sigcomply report` can render `text`/`json`/`csv`, where JSON/CSV may include policy IDs and violation reasons. | **Never raw credentials, never source payload fields beyond what the formatter explicitly extracts.** |
| **stderr** | Operational log lines: collection start/end, per-source errors, planning errors, vault write confirmations. | Resource identifiers (resource IDs, emails, etc.) are **redacted** at the logger boundary. Each log record passes through `internal/log/redact.go` which strips known PII shapes (emails, ARNs, UUIDs in identifier position) and replaces them with `<redacted:type>`. |
| **vault `diagnostics.json`** | Source-level errors, schema validation drops, partial collector failures. | Resource identifiers are **retained** here because diagnostics live in the customer's own vault, on their side of the privacy boundary. |
| **cloud submission** | The `SubmissionPayload` only (see L6). | Counts only, structurally enforced. |

**Redaction policy** (mandatory for all log writes from the CLI core
and from plugins via the shared logger):

1. Email addresses → `<redacted:email>`
2. AWS ARNs → `<redacted:arn>`
3. UUIDs in identifier position → `<redacted:uuid>`
4. AWS access key IDs (`AKIA…`, `ASIA…`) → `<redacted:aws-key>`
5. OIDC JWTs → `<redacted:token>`
6. Anything matching configured plugin-secret-shape regexes →
   `<redacted:secret>`

Plugins **MUST** use the shared logger (`internal/log`) for all
informational/diagnostic output. Direct writes to `os.Stdout` or
`os.Stderr` from plugin code are forbidden and detected by the
project's vet check.

**Verbose mode** (`-v` / `--verbose`) increases the stderr volume
(per-policy lifecycle events, per-source HTTP request summaries) but
does **not** disable redaction. There is no flag that turns off
redaction.

**Why this matters**: CI providers (GitHub Actions, GitLab CI) capture
stderr into their own log storage, which is third-party infrastructure.
A `--verbose` run that leaked ARNs into those logs would invalidate
the non-custodial pitch on day one. Redaction at the logger boundary
makes the invariant structural rather than convention.

### No telemetry

The CLI emits no metrics, traces, or other telemetry to external
endpoints. Operational visibility comes from the CLI's own
stderr/stdout and from the customer's CI provider's log storage.
A future opt-in OpenTelemetry exporter is a v2 consideration; v1 is
silent.

### Layered errors

| Layer | Error class | Effect |
|---|---|---|
| L0 / L2 | Spec validation | Exit 3 (config error) |
| L3 | Planning | Exit 3 (config error) |
| L4 | Per-source | Marks dependent policies `error`; run continues |
| L5 | Per-rule | Marks that policy `error`; other policies continue |
| L6 / L7 | Aggregation / persistence | Logged; submission may still succeed |
| L8 | Submission | Logged; exit code unaffected |
| L9 | Argument / CLI | Exit 3 |

Panics anywhere → exit 2.

---

## Support packages (outside the numbered stack)

Not every package is one of the ten layers. The following are
cross-cutting support packages the layers call into:

| Package | Role | Used by |
|---|---|---|
| `internal/sign` | Ed25519 envelope + manifest signing/verification (`sign.Envelope`, `sign.VerifyEnvelope`, `sign.VerifyManifest`). Per-file ephemeral keypair; the manifest is signed once with its own ephemeral keypair. | L4 (envelopes), L7 (manifest) |
| `internal/log` | Shared logger + redaction (`internal/log/redact.go`). | all layers, plugins |
| `internal/manualcatalog` | SPA-facing manual-evidence catalog export (`ManualCatalogExport()`), generated in Go from each framework's `manualSpecs()`. | `evidence catalog` command |
| `internal/report` | Read-only auditor snapshot of the vault. | `report` command |
| `internal/frameworks`, `internal/sources`, `internal/evidence_types` | Self-registering framework/source/schema providers that populate the L2 registries via blank-imported `builtin` packages. | L2 |

**Cadence / Mode subsystem.** The two-axis cadence machinery
(`internal/planner/{cadence.go,period.go}`,
`internal/orchestrator/state.go`) decides evaluate-vs-carry-forward per
policy and reads/writes the mutable, never-signed cadence state at
`state/{framework}/policies/{policy_id}.json`. It is layered across L3
(planner) and L9 (orchestrator) rather than being its own layer. Full
design: [`10-cadence-model.md`](10-cadence-model.md).

**Manifest signing.** L7 writes the per-run `manifest.json` and signs it
via `internal/sign`; the persistence/manifest assembly lives partly in
L7 and partly in the orchestrator. Vault layout and the manifest's
single-level Merkle structure: [`05-vault-layout.md`](05-vault-layout.md).

---

## What's deliberately not a layer

A few things might look like they should be layers but aren't —
recording them here to prevent the design from drifting.

- **No "collection scheduler" layer.** Policies fetch independently;
  there is no orchestration of fetches beyond simple sequencing inside
  L4. If parallelism becomes necessary, it lives within L4 as an
  implementation detail, not a new layer.
- **No "evidence cache" layer.** The vault is the persistence layer;
  there is no in-memory or on-disk cache of records spanning runs or
  spanning policies within a run.
- **No "policy library" layer.** Policies are just specs in L0,
  registered in L2. There is no dynamic policy resolution layer.
- **No "result transformer" layer.** Output formatting (the fixed
  `check` text summary, and `report`'s text/json/csv) lives in L9
  alongside the orchestrator, because it's human-facing and tightly
  coupled to CLI flags.

If a future change feels like it needs one of these, treat that as a
signal to re-read this document, not to add the layer.
