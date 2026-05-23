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
- Policy specs (one per policy, framework-shipped or project-local)
- Evidence type schemas (JSON Schema, one per type)
- Source plugin manifests (one per plugin, declaring emitted types)
- Project config (`.sigcomply.yaml`, customer-authored)
- Manual evidence catalog (entries for `manual.pdf` source)

**Format.** YAML for human-authored specs; JSON Schema for evidence
type schemas; JSON for machine-emitted artifacts (run metadata,
summaries).

**Stability rules.** Every spec carries a `schema_version`. Backward-
incompatible changes bump the major version of the relevant spec.
Evidence type schemas are append-only: new fields are optional; renames
and removals require a new version (`user_record.v2`).

**No code in L0.** Nothing in this layer executes. Specs are parsed by
L1, validated by L2, and consumed by L3 onwards.

---

## L1 — Core domain types

**Owns.** The stable Go types and interfaces that every other layer
depends on. Frozen once published; changes here ripple everywhere.

Key types (canonical names; full signatures live in
`internal/core/`):

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

type Policy struct {
    ID, Control, Description, Remediation string
    Severity                              Severity
    Slots                                 map[string]Slot
    Parameters                            map[string]ParameterSpec
    RuleRef                               string  // "rules.mfa_enforced.v1"
}

type Slot struct {
    Type        string          // evidence type ID
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
    Init(ctx context.Context, cfg map[string]any) error
    Collect(ctx context.Context, slot string) ([]EvidenceRecord, error)
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
    Status     PolicyStatus // pass|fail|skip|error|na|waived
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
| `SourceRegistry` | In-binary plugins + project-local plugins under `.sigcomply/plugins/` | `source_id` |
| `RuleRegistry` | In-binary rules + project-local rules under `.sigcomply/policies/.../rules/` | `rule_ref` |
| `EvidenceTypeRegistry` | In-binary type schemas + project-local under `.sigcomply/evidence_types/` | `evidence_type_id` |
| `PolicyRegistry` | Framework-shipped policy specs + project-local policies under `.sigcomply/policies/` | `policy_id` |

**Loading sequence.**

1. Load in-binary registries (compiled-in via `embed.FS`).
2. Discover and load `.sigcomply/` extensions.
3. Validate: every `policy.rule` resolves to a registered rule; every
   `policy.slot.type` resolves to a registered evidence type; every
   `binding.source` resolves to a registered plugin.
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
- Filter flags (`--policies`, `--controls`)

**Outputs.**

- `RunPlan`:
  - `run_id`, `framework`, `period_id`, `commit_sha`, `commit_time`
  - `policies []PlannedPolicy` — each with:
    - resolved `Policy` from registry
    - resolved bindings (slot → list of source plugin instances)
    - effective parameter values (defaults overridden by project config)
    - resolved rule from registry
  - `exceptions []ResolvedException`
  - `vault` configuration

**Behavior.**

- Period derived from `f(commit_time, fiscal_calendar)` (see
  `01-conceptual-model.md` §12).
- Validates that every policy's required slots have at least one
  binding.
- Validates that every binding's source emits records of the slot's
  type.
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
      - Invoke `plugin.Collect(ctx, slot)` to fetch records
      - Validate each record against its evidence type schema
   b. Aggregate all records for the slot.
2. For each (slot, source) pair, write one envelope:
   - Generate a fresh Ed25519 keypair
   - Sign canonical JSON of `{format_version, produced_at, records}`
   - Discard the private key
   - Persist the envelope via the vault (L7) at the policy's envelope path
3. Hand the per-slot record collections to the evaluator (L5).

**Error handling.**

- A source-level error (network, auth, schema validation) marks every
  policy depending on that source as `error` status, with a diagnostic.
  Other policies proceed.
- A schema-validation error is fatal for that specific record but not
  for the batch; the bad record is dropped and noted in the envelope's
  diagnostics. Schema validation failures at scale (>5%) cause the
  source's contribution to be marked `error`.

**Invariant.** Per the KISS-no-DRY decision, no record cache spans
policies. Source `Collect` is invoked once per policy-binding even
if the same `(plugin, slot)` recurs across policies.

---

## L5 — Evaluator

**Owns.** Running each policy's rule with the records collected for it.

**Per policy:**

1. Skip if the policy is fully covered by a `na` or `waived` exception.
2. Skip with status `skip` if required slots have no records (e.g.
   collector returned empty).
3. Mark `error` if any of the policy's source bindings produced an
   error in L4.
4. Otherwise: invoke the policy's rule.
   - Construct `RuleInput` with slots, effective parameters, and `Now`.
   - Call `rule.Evaluate(ctx, in)`.
   - The rule returns `RuleResult` with status and violations.
5. Apply exception suppression: resource-scoped exceptions reclassify
   matching violations as `waived` and recompute the per-policy status.

**Rule isolation.** Rules are pure functions over `RuleInput`. They
do no I/O. Rego rules run in OPA's sandbox; Go rules are
reviewed at PR time to enforce side-effect-freedom; YAML DSL rules
compile to Rego.

**Output.** Per-policy `PolicyResult`:

```go
type PolicyResult struct {
    PolicyID          string
    ControlID         string
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
    Schema        string         // "sigcomply.cloud.v1"
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
    ControlID           string
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

- `manifest.json` at run root (run identity, versions)
- `summary.json` at run root (full-fidelity run summary including
  per-policy violations)
- For each policy:
  - `envelopes/...json` (signed evidence envelopes from L4)
  - `attachments/...` (manual PDFs mirrored as siblings)
  - `result.json` (full `PolicyResult` including violations)

**Writes for the framework period**:

- The vault layout reflects period membership in the path; period state
  is not stored authoritatively. (Optional materialized cache file:
  `period_state.json`, but always regenerable from run folders.)

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
9. Render output (text / json / junit / sarif), exit with appropriate
   code:
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

Every persisted artifact carries the version of its schema:

- `Envelope.FormatVersion` = `"envelope.v1"`
- `manifest.json` carries `schema_version`, `cli_version`, the
  framework version, and the set of evidence type schemas used
- `result.json` carries `policy_version`, `rule_version`

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
| **stdout** | Final structured run summary in the chosen output format (text/json/junit/sarif). Same content the operator sees. | Per format: text shows counts + control names. JSON and JUnit may include policy IDs and violation reasons. SARIF includes the same. **Never raw credentials, never source payload fields beyond what the formatter explicitly extracts.** |
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
- **No "result transformer" layer.** Output formatting (text/json/junit/
  sarif) lives in L9 alongside the orchestrator, because it's
  human-facing and tightly coupled to CLI flags.

If a future change feels like it needs one of these, treat that as a
signal to re-read this document, not to add the layer.
