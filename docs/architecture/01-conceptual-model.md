# 01 — Conceptual Model

This is the vocabulary. Every other document in this tree, and every
identifier in the codebase, uses these terms with the meanings given
here. If a term ever drifts, fix it here first; the rest follows.

---

## The sixteen abstractions

| # | Term | One-line definition |
|---|---|---|
| 1 | Framework | A published compliance regime with versioned identity. |
| 2 | Control | A single requirement inside a framework. |
| 3 | Policy | A verifiable assertion contributing to a control. |
| 4 | Policy cadence | How often a policy must be evaluated. |
| 5 | Slot | A named, typed input on a policy. |
| 6 | Evidence type | The shape of evidence — a versioned schema. |
| 7 | Source (plugin) | Code that produces evidence of declared types. |
| 8 | Evidence record | One fulfilled item: `{type, identity, payload, source_id, collected_at}`. |
| 9 | Envelope | Signed wrapper around a batch of evidence records. |
| 10 | Evaluation logic | `pass_when:` (primary) decides a policy's outcome from its bound evidence; `rule:` is an unused escape hatch. |
| 11 | Binding | Project-level mapping: "for policy X, fulfill slot Y from source Z." |
| 12 | Project | One source-control repo; the unit of compliance posture. |
| 13 | Period | A first-class audit window (e.g. `2026-Q1`). |
| 14 | Run | One orchestrated execution `(project, framework, period, commit, invocation_id)`. |
| 15 | Vault | Customer-owned storage receiving envelopes and summaries. |
| 16 | Aggregation contract | The frozen schema crossing the privacy boundary to the dashboard. |

Each is expanded below with a definition, an example, and an explicit
"what it is *not*."

---

### 1. Framework

**Definition.** A published compliance regime — SOC 2 (Type II), ISO
27001:2022, HIPAA Security Rule, PCI DSS 4.0, etc. A framework owns a
versioned control catalog and a set of policies that verify those
controls. Frameworks are shipped with the CLI binary; customers do not
author their own framework specs.

**Example.** `framework: soc2` selects the SOC 2 framework spec
embedded in the binary. The binary's release version pins the
framework version.

**What it is *not*.** A framework is not a configuration choice the
customer can edit. Customers select among shipped frameworks, narrow
their scope via the policy catalog, and override parameters — they do
not redefine what SOC 2 means.

---

### 2. Control

**Definition.** A single requirement inside a framework — `SOC2.CC6.1`
("logical access controls in place"), `ISO27001.A.9.2.1` ("user
registration and de-registration"). Controls have an identifier,
description, severity baseline, and category. Each control is verified
by zero or more policies.

**Example.** `CC6.1` in SOC 2 is verified (in part) by:
`soc2.cc6.1.mfa_enforced`, `soc2.cc6.1.access_key_rotation`,
`soc2.cc6.1.inactive_users_disabled`, and others.

**What it is *not*.** A control is not the policy. A single control
typically requires many policies to fully verify; a single policy
typically maps to one control but may map to several. The
control-to-policy relationship is many-to-many.

---

### 3. Policy

**Definition.** A verifiable assertion that contributes to a control.
A policy has an ID, one or more target controls, severity, a
description, a required `evidence_mode` (`automated | manual`), a set
of *slots* declaring what evidence it consumes (automated only), an
optional parameter schema, and a `pass_when:` condition (the primary
evaluation path). Policies are framework-shipped or project-local
(custom).

**`evidence_mode` is first-class and required.** Every policy declares
`evidence_mode: automated` or `evidence_mode: manual` explicitly — it
is never inferred from the slot types, the accepted evidence types, or
the presence of a `rule:`. A missing `evidence_mode` fails validation
at load (exit 3); it is never defaulted silently. The evaluator
branches on this field and nothing else (see #10 and Axiom 4).
Automated policies declare `slots:` and a `pass_when:`; manual policies
declare a `catalog_entry:` and carry neither slots nor `pass_when:`. A
project may override the framework's default per policy via
`policies.<id>.evidence_mode` in `.sigcomply.yaml` (same policy ID).

**Example.** `soc2.cc6.1.mfa_enforced` (`evidence_mode: automated`)
asserts "every user in the configured user-directory source has MFA
enabled." It has one slot (`user_directory`) accepting `directory_user`,
no parameters, and a `pass_when:` clause requiring
`payload.mfa_enabled == true` across all records.

**What it is *not*.** A policy is not its evaluation logic. The policy
is the declaration of what's being checked and what evidence is needed;
the `pass_when:` clause (or, rarely, the `rule:` escape hatch) is the
executable part. The policy is not source-specific: the same policy can
be satisfied by Okta evidence in one project and by an HR-system PDF in
another.

---

### 4. Policy cadence

**Definition.** How often a policy must be evaluated. Declared by the
policy spec, overridable in project config, used by CI workflow files to
schedule the appropriate workflow. Cadence is a first-class attribute of
every policy — it pairs with severity and category as part of a policy's
identity.

**Values.** `continuous` | `hourly` | `daily` | `weekly` | `monthly` |
`quarterly` | `annual`.

| Cadence | Typical use |
|---|---|
| `continuous` | Per-PR fast checks (branch protection, encryption-at-rest defaults). |
| `hourly` | Drift detection on high-blast-radius config (public S3 buckets, root MFA). |
| `daily` | Most automated SOC 2 / ISO 27001 checks. |
| `weekly` | Access reviews of inactive users, key rotation reminders. |
| `monthly` | Vulnerability scan summaries, backup verification. |
| `quarterly` | Manual access reviews, declarations, attestations. |
| `annual` | Policy acknowledgment, training completion. |

**Example.** A policy spec declares:

```yaml
id: soc2.cc6.1.mfa_enforced
cadence: daily
on_push: true
```

A project may override per policy in `.sigcomply.yaml`:

```yaml
policies:
  soc2.cc6.1.mfa_enforced:
    cadence: hourly
```

Cadence can also be expressed as `every:<duration>` (5-minute floor)
when a named bucket doesn't fit; a bare `cadence: 24h` is a config
error. When a policy is selected for a run but its interval has not
elapsed and nothing material changed, the planner **carries forward**
the prior signed result (a pointer to the previous envelope, no
re-sign) rather than re-evaluating — yielding the `carried_forward`
status (see #16 and [`10-cadence-model.md`](10-cadence-model.md)).

**What it is *not*.** Cadence scheduling state is mutable and never
signed — it is not audit evidence, and losing it just means the next
run treats the policy as first-run. The CI scheduler triggers runs (see
Axiom 4 below and [`09-ci-execution-model.md`](09-ci-execution-model.md));
the CLI's per-policy cadence check then decides evaluate-vs-carry-forward
within the run. Asking the CLI to run a `quarterly` policy on demand is
legal and the CLI will execute it.

---

### 5. Slot

**Definition.** A named, multi-typed input on a policy. A slot declares:
a name (`user_directory`), the **set** of evidence types it accepts
(`accepts: [directory_user]`, or a multi-type slot such as
`accepts: [directory_user]` bound to several user sources), a
cardinality (`exactly-one` | `one-or-more` | `optional` |
`at-most-one`), and whether it's required. Slots are the interface
between a policy and the data it needs, and the only abstraction that
knows about evidence types — neither policies nor sources mention each
other by ID.

**Example.** `soc2.cc6.1.mfa_enforced` declares:

```yaml
slots:
  user_directory:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
```

This one slot is satisfiable by several user sources at once —
`aws.iam` (emitting `directory_user.v2`), `okta`, and `github` (both
emitting `directory_user`) — because they all emit the same neutral
evidence type. A cross-cloud "object storage encrypted at rest" policy
works the same way through a **single** neutral type rather than a
union of per-vendor types:

```yaml
slots:
  buckets:
    accepts: [object_storage_bucket]
    cardinality: one-or-more
    required: true
```

`aws.s3`, `gcp.storage`, and `azure.storage` all emit
`object_storage_bucket`, so the slot accepts one type and spans all
three clouds. A project binds one or
more sources to a slot. A source matches a slot when
**`source.Emits() ∩ slot.Accepts ≠ ∅`**. The evaluator receives all
records produced by all bound sources, unioned, under the slot. Records
carry their `Type` and `SourceID`, so logic that must behave
differently per evidence type switches on `record.Type`; most
`pass_when:` clauses just quantify over the union.

**Slots are the contract.** Policies declare what shapes they accept;
sources declare what shapes they emit; the planner verifies the
intersection at plan time. Adding another object-store source
(Cloudflare R2, Backblaze B2) that emits `object_storage_bucket` to the
cross-cloud policy above is zero policy-logic changes and zero
source-side translation — the new source is immediately usable, exactly
as `azure.storage` already joins `aws.s3` and `gcp.storage` on that one
neutral type. (When a genuinely
*new* shape is needed, extending a slot's `accepts:` list with another
type ID is one line of YAML.) This is what makes the architecture
cross-vendor without polluting either side with knowledge of the other.

**What it is *not*.** A slot is not a source. A slot says "I accept
records of types X, Y, or Z"; the project's binding decides which
source(s) provide them. Slots are the abstraction that makes sources
interchangeable per project.

---

### 6. Evidence type

**Definition.** The *shape* of a piece of evidence — a versioned JSON
schema with a stable ID. Evidence types are first-class: they are
registered separately from the source plugins that emit them, and
separately from the policies that consume them. The same evidence type
can be emitted by multiple plugins and consumed by multiple policies.

**Example.** `directory_user.v1` schema (JSON Schema, embedded as
`internal/evidence_types/schemas/directory_user.v1.json`):

```json
{
  "title": "directory_user",
  "version": 1,
  "type": "object",
  "required": ["id", "mfa_enabled"],
  "properties": {
    "id":           { "type": "string" },
    "email":        { "type": "string" },
    "mfa_enabled":  { "type": "boolean" },
    "last_used_at": { "type": "string", "format": "date-time" },
    "is_admin":     { "type": "boolean" }
  }
}
```

This shape can be emitted by `aws.iam` (transformed from the AWS IAM
API response; it emits the `directory_user.v2` revision), by `okta`
(transformed from the Okta Users API), by `github`, or by a customer's
`internal.ldap` plugin. Any policy whose slot declares
`accepts: [directory_user]` can consume any of them, alone or in
combination.

**What it is *not*.** An evidence type is not a source plugin. Source
plugins know about specific APIs; evidence types know nothing about
where data comes from. The full registry semantics — embedding,
schema-conformance validation at collection time, append-only
versioning, and the project-local extension path under
`.sigcomply/evidence_types/` — live in
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md). This
separation is the substitutability axiom (see below).

---

### 7. Source (plugin)

**Definition.** A unit of code that knows how to fetch data from a
specific external system and emit evidence records of declared types.
A source plugin has a stable ID (`aws.iam`, `okta`, `manual.pdf`,
`acme.internal_iam`), a configuration schema, an initialization step
(credentials, scope), and a `Collect` entry point. It declares which
evidence types it emits.

**Example.** The `aws.iam` plugin emits `directory_user` (the `.v2`
revision); a sibling `aws.iam_access_key` plugin emits `iam_access_key`.
A plugin declares its emitted types in Go via `Emits() []string` — there
is no in-tree `plugin.yaml` manifest. Credentials come from the ambient
SDK chain (region, optionally a profile or assumed role configured under
`sources:`).

```go
func (p *iamPlugin) ID() string      { return "aws.iam" }
func (p *iamPlugin) Emits() []string { return []string{"directory_user.v2"} }
```

**What it is *not*.** A source plugin is not a policy. A source plugin
fetches and shapes data; it knows nothing about which controls or
policies will consume that data. Plugins are reusable across policies
and across frameworks.

---

### 8. Evidence record

**Definition.** One fulfilled piece of data. Carries:

- `type`: the evidence type ID (e.g. `directory_user`)
- `id`: a stable identifier within the source (the resource's natural ID)
- `payload`: a JSON value conforming to the type's schema
- `source_id`: the plugin that produced it (e.g. `aws.iam`)
- `collected_at`: the timestamp of the fetch

**Example.**

```json
{
  "type": "directory_user",
  "id": "AIDAEXAMPLEUSER01",
  "source_id": "aws.iam",
  "collected_at": "2026-05-23T14:00:01Z",
  "payload": {
    "id": "AIDAEXAMPLEUSER01",
    "email": "alice@acme.com",
    "mfa_enabled": false,
    "last_used_at": "2026-05-20T09:14:00Z",
    "is_admin": true
  }
}
```

**What it is *not*.** An evidence record is not the source's raw API
response. The plugin's job is to *transform* the raw response into the
declared evidence type. Raw responses can be preserved (signed,
verifiable) alongside the structured records if needed for audit
forensics.

---

### 9. Envelope

**Definition.** A signed wrapper around a batch of evidence records.
Each envelope:

- Carries a `format_version` string for forward-compatibility
- Contains a `produced_at` timestamp
- Contains the array of evidence records
- Carries a fresh Ed25519 public key generated at write time
- Carries an Ed25519 signature over the canonical JSON of
  `{format_version, produced_at, records}`

The private key is generated, used once to sign, and discarded
immediately. The public key lives in the file forever.

**Example shape.**

```json
{
  "format_version": "envelope.v1",
  "produced_at": "2026-05-23T14:00:02Z",
  "records": [ /* evidence records */ ],
  "signature": {
    "algorithm": "ed25519",
    "public_key": "base64-encoded-32-bytes",
    "value":      "base64-encoded-64-bytes"
  }
}
```

**What it is *not*.** An envelope is not a per-run signed bundle.
Signing is per-envelope; a run typically writes many envelopes (one
per policy per evidence batch). The granularity allows an auditor to
verify any single file independently, without needing the rest of the
run.

---

### 10. Evaluation logic (`pass_when:`, with a `rule:` escape hatch)

**Definition.** The logic that decides an automated policy's outcome
from its bound evidence. It produces a status (`pass` | `fail` | `skip`
| `error`), a list of violations (each tied to a resource identity),
and optional diagnostic metadata.

There are two ways to express it, and they are **mutually exclusive**
(declaring both is a load error, exit 3):

- **`pass_when:` (the primary path — and the only one any shipped
  policy uses).** A declarative condition DSL evaluated in-process: a
  quantifier (`all | none | any | count`) over a condition triple
  (`{op, field, value}`) on the records in a slot. ~95% of compliance
  checks are "for every record, assert field X" — that is exactly what
  `pass_when:` expresses, with no Go or Rego. **Both shipped frameworks
  (SOC 2 and ISO 27001) are 100% `pass_when:`; each framework's
  `Rules()` returns nil.**
- **`rule:` (the escape hatch — present but unused).** A Go or inline
  Rego rule, for the rare check the DSL genuinely cannot express
  (cross-slot joins, complex aggregations). The infrastructure remains
  available and OPA stays a dependency for it, but no shipped policy
  reaches for it. Rego rules run in OPA's sandbox; Go rules are
  reviewed for side-effect-freedom at PR time.

Manual policies use neither — they run the universal PDF-presence
check (see #3, `evidence_mode: manual`).

**Example (`pass_when:`, the real shape).**

```yaml
pass_when:
  quantifier: all
  slot: user_directory
  condition: { op: eq, field: "payload.mfa_enabled", value: true }
violation_message: "MFA disabled for {{.payload.email}}"
```

A field path resolves `id`, `type`, `source_id`, or `payload.<dot.path>`;
a bare name without the `payload.` prefix errors the policy. Violation
message tokens are Go-template form (`{{.payload.field}}`), not
`{token}`.

**What it is *not*.** The evaluation logic is not the policy. A policy
that needs the escape hatch may share a `rule:` across frameworks (e.g.
the same rule referenced by both a SOC 2 and an ISO 27001 policy), but
the common, shipped case is a per-policy `pass_when:` clause. `rule:`
is not "the default with `pass_when:` as sugar" — it is the exception,
and currently the unused one.

---

### 11. Binding

**Definition.** A project-level declaration that maps a policy's slots
to concrete sources. Bindings live in `.sigcomply.yaml`. A binding may
list multiple sources for a single slot (if the slot's cardinality
allows it); the records from all bound sources are unioned into the
rule input.

**Example.**

```yaml
policies:
  soc2.cc6.1.mfa_enforced:
    bindings:
      user_directory: [aws.iam, okta]
  soc2.cc6.1.access_key_rotation:
    bindings:
      access_keys: [aws.iam_access_key]
```

For `mfa_enforced`, AcmeCorp wants both AWS IAM users and Okta users
checked under the same policy. Both plugins emit `directory_user`, so
the evaluation operates on the union.

**What it is *not*.** A binding is not a source configuration. The
source's credentials and scope live in the `sources:` section of the
project config; the binding only names sources by ID and ties them to
policy slots.

---

### 12. Project

**Definition.** A project corresponds to one source-control repository
(GitHub or GitLab). The repo's `org/name` is the project identity:
`acme/infrastructure`, `sigcomply/sigcomply-cli`. A project is fully
described by:

- A `.sigcomply.yaml` at the repo root (framework, period config,
  source configurations, the `policies:` object — bindings, exceptions,
  parameter and cadence overrides — the `controls:` section, and the
  vault location)
- A `.sigcomply/` directory for custom code (custom policies, custom
  source plugins)
- A vault (customer-owned storage; configured in `.sigcomply.yaml`)

A project is single-tenant and (for v1) single-scope: one set of
credentials, one organizational unit.

**One project = one framework.** Customers pursuing SOC 2 + ISO 27001
typically use two repositories: each holds its own `.sigcomply.yaml`,
its own bindings, its own CI workflow files, and its own vault prefix.
`check` has no `--framework` override — it reads `framework:` from
`.sigcomply.yaml` — so the canonical pattern is one-framework-per-project. Multi-framework
within one repo creates ambiguity at the CI scheduling layer (which
framework's daily cadence does the daily workflow run?) and is not the
supported configuration.

**Example.** AcmeCorp's SOC 2 project lives in the repo
`acme/infrastructure-soc2`. Their ISO 27001 work lives in
`acme/infrastructure-iso27001`. Each has its own framework selection,
calendar, sources, bindings, and vault prefix.

**What it is *not*.**

- A project is not a deployment environment (prod/staging/dev). The
  repo's compliance posture covers whatever scope its source configs
  describe; staging-vs-prod is modeled inside source configurations,
  not at the project layer.
- A project is not a single CLI run. A project persists across runs;
  a run is an instant in the project's history.
- A project is not the framework. The framework is a shipped artifact;
  the project is the customer's selection and configuration of that
  artifact.
- A project is not "the customer." A customer (AcmeCorp) may own
  several projects (one per framework they're pursuing).

---

### 13. Period

**Definition.** A first-class audit window — `2026-Q1`, `FY2026`, or a
custom range — derived from a pure function `f(commit_time,
fiscal_calendar)` defined in project config. Every run is stamped with
its period. The vault layout groups runs by period.

**Example.** Project config:

```yaml
period:
  fiscal_calendar:
    type: calendar_quarter
```

A commit timestamped `2026-02-15T13:55:00Z` lands in period
`2026-Q1`. A commit timestamped `2026-04-01T00:01:00Z` lands in
`2026-Q2`.

**What it is *not*.** A period is not stored state. The period
*definition* lives in config (versioned in git); the period *for a
given run* is computed at run time and stamped into immutable run
metadata. No "period_state.json" is the authoritative truth — period
state is derived from the union of runs in the period folder.

---

### 14. Run

**Definition.** One CLI invocation. A run has:

- `run_id`: a UUID minted at invocation start
- `project`: the customer's project identity
- `framework`: the selected framework
- `period_id`: derived from commit time + fiscal calendar
- `commit_sha`, `commit_time`: from the git context
- `invocation_id`: a CI-provided identifier when available
- A set of policies it evaluated (which may be a subset, if filters were
  applied)

A run writes one folder under
`{vault_root}/{framework}/{period_id}/run_{timestamp}_{run_id_short}/`.
That folder is immutable once the run completes.

**Example.** AcmeCorp's nightly CI runs `sigcomply check` (the framework
is read from `.sigcomply.yaml`). The run lands in
`soc2/2026-Q1/run_20260223T030000Z_a3f8b2c1/`.

**What it is *not*.** A run is not the audit period. A period
typically contains many runs. A run is not the unit auditors ultimately
look at; they look at period state, which is the latest-result-per-policy
roll-up across runs in the period.

---

### 15. Vault

**Definition.** Customer-owned storage receiving signed envelopes,
per-policy result files, and per-run summaries. The vault is the
durable record. It is append-only at the run level (each run's folder
is written once, never modified).

Supported backends: local filesystem, AWS S3 (and S3-compatible
endpoints), Google Cloud Storage, Azure Blob Storage. The vault's
location is configured in `.sigcomply.yaml`.

**Example.** AcmeCorp uses `s3://acme-evidence/sigcomply/` in
`us-east-1`, encrypted with their own KMS key.

**What it is *not*.** The vault is not the cloud dashboard. The vault
holds raw evidence and never leaves the customer's environment. The
cloud dashboard receives only aggregated counts (see #16).

---

### 16. Aggregation contract

**Definition.** The frozen schema that crosses the privacy boundary to
the hosted dashboard. It carries:

- Per-policy: policy ID, `controls []ControlRef` (the multi-framework
  control mapping — each `{framework, framework_version, control_id,
  relationship}`, a public taxonomy carrying no identity), status,
  severity, message (count-based, regenerated, never forwarded from
  violation text), category, resources_evaluated count, resources_failed
  count, plus the per-policy cadence scalars (`ConfiguredCadence`,
  `LastEvaluatedAt`, `NextDueAt`, `IsCarriedForward`,
  `PolicyContentHash`)
- Per-run summary: total/passed/failed/skipped/error/na/waived policy
  counts, compliance score
- Environment metadata: CI provider, repository name, branch, commit
  SHA, CLI version

The aggregation contract is implemented as a Go struct that
*physically cannot* express a resource identifier. Adding such a field
requires a code change at the boundary, which is a code-review gate.

**Example.** What goes to the cloud:

```json
{
  "policy_id":          "soc2.cc6.1.mfa_enforced",
  "controls":           [{ "framework": "soc2", "control_id": "CC6.1", "relationship": "equal" }],
  "status":             "fail",
  "severity":           "high",
  "resources_evaluated": 47,
  "resources_failed":    3,
  "message":            "3 of 47 users do not have MFA enabled",
  "category":           "access_control"
}
```

What does *not* go to the cloud: the three users' identities, their
emails, their resource ARNs, the full violation list, the underlying
evidence, the file hashes, the envelope public keys.

**What it is *not*.** The aggregation contract is not the vault
format. The vault holds full fidelity; the contract is a deliberate
information loss step at the boundary.

---

## The substitutability axioms

These statements are the load-bearing claims of the design. Everything
else follows from them. Axioms 1–4 cover the policy/source/CLI seams;
Axioms 5–6 cover the two storage seams (output vault, manual-evidence
input). Together they articulate the **three plugin axes** described
in [`00-three-plugin-axes.md`](00-three-plugin-axes.md): Axiom 1
covers Axis C (API sources), Axiom 5 covers Axis B (output vault),
Axiom 6 covers Axis A (manual input storage).

### Axiom 1 — Evidence type is the join key, not the source plugin

A policy declares `slots → accepts: [evidence types]`. A source plugin
declares `source ID → emits: [evidence types]`. A project binding
declares `policy slot → [source plugin IDs]`. The planner matches a
source to a slot whenever `source.Emits() ∩ slot.Accepts ≠ ∅`. The
evaluation logic only sees evidence records grouped by slot, each
tagged with its `Type` and `SourceID` — but it has no API to
special-case "which plugin produced this?", and policies have no syntax
to name a source.

**The canonical example: MFA enforced on admin users.** SigComply
ships one policy: `soc2.cc6.1.admin_mfa_enforced`, declaring a single
slot `user_directory` with `accepts: [directory_user]`. AcmeCorp uses
AWS IAM; their `.sigcomply.yaml` binds `aws.iam` to that slot. BetaCorp
uses Okta; their config binds `okta`. GammaCorp uses both; theirs
binds `[aws.iam, okta]`. DeltaCorp uses an internal LDAP and writes a
project-local plugin emitting `directory_user`; theirs binds
`acme.internal_iam`. **There is one policy in the binary, four
different bindings in four different projects, zero forks.**

**Consequence.** Two customers can satisfy the same policy with
different sources. Adding a new source plugin that emits an existing
evidence type immediately makes that plugin usable by every policy
already accepting that type — no policy change, no source-side
normalization to a lowest-common-denominator schema. Adding a new
evidence type to an existing slot's `accepts:` list (e.g., extending a
storage-encryption policy from AWS-only to AWS+GCP) is one line of
YAML.

**Non-goal — and how the design enforces it.** Policies must not name
sources by ID; sources must not know which policies consume them.
This is structural, not stylistic:

- A policy spec has no `source:` field anywhere — only `slots.*.accepts:`.
- A source plugin's `SourcePlugin` interface has no `PolicyID` input
  beyond a diagnostic-only tag (the `SlotRequest.PolicyID` field is
  documented as "for logging, never for behavior branching"; the same
  rule applies in reverse — policies never get a source ID at evaluation
  time except as a record-level tag for diagnostics).
- The binding lives in `.sigcomply.yaml` — the project's config, not
  the framework's policies and not the source's manifest. The
  evidence-type registry (see [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md))
  is the *only* point of contact between the policy world and the
  source world.

If you ever feel the urge to add a "this policy only works with AWS"
escape hatch, that's the signal that an evidence-type contract is
missing. Add the type, not the special case.

### Axiom 2 — Slot cardinality is a property of the policy, not the project

A slot declares whether one or many sources may be bound to it. The
project chooses sources within that cardinality constraint. A policy
that fundamentally needs exactly one user directory declares
`cardinality: exactly-one`. A policy that aggregates across all
configured user directories declares `cardinality: one-or-more`.

**Consequence.** Customers with N sources for the same kind of data
(e.g. three HR systems) can bind all three to a single
`one-or-more` slot. Customers with one source bind just one. The
policy logic operates on the unioned set either way.

### Axiom 3 — Each policy fetches independently

There is no cross-policy collection sharing. If policies A, B, and C
each bind source X to one of their slots, source X is invoked three
times, once per policy. Per-policy logic stays maximally
self-contained; no orchestration layer assumes shared state.

**Consequence.** Adding, removing, or modifying a policy has zero
side effects on other policies. The runtime cost scales linearly with
the number of policies that consume each source, traded for
authorship simplicity.

### Axiom 4 — CI is the orchestrator, not the CLI

The CLI is a leaf invocation: it runs whatever set of policies its
flags select, signs and writes the resulting envelopes, optionally
submits aggregated counts, and exits. **Which cadences run when** is
decided entirely by **CI workflow files** — one per cadence, scheduled
by cron — not by the CLI maintaining its own schedule. (Within a
selected run the CLI consults mutable, never-signed per-policy cadence
state to decide evaluate-vs-carry-forward — see #4 and
[`10-cadence-model.md`](10-cadence-model.md) — but it never decides
*which workflow fires*.) A daily workflow invokes
`sigcomply check --cadence daily`; an hourly workflow invokes
`sigcomply check --cadence hourly`; a PR workflow invokes
`sigcomply check --on-push`. Re-running after a fix is a manual workflow
trigger, not a CLI feature.

**Consequence.** The CLI carries no cross-run *scheduling* state beyond
the small, recoverable, never-signed per-policy cadence file. Workflow
fan-out across cadences, retries, and the cron schedule all live in
human-readable workflow YAML the customer owns and audits. The CLI
itself is trivially testable: given flags, it produces a deterministic
set of outputs. Replacing or extending the orchestrator (cron → Argo →
Airflow → whatever) does not require CLI changes. This is the property
that lets the same `sigcomply` binary serve hourly automated sweeps,
daily SOC 2 sweeps, quarterly access reviews, and on-push fast checks
without internal mode flags or state files.

### Axiom 5 — Vault backends are interchangeable

The customer-owned vault — append-only object storage receiving every
signed envelope, every PDF mirror, every per-policy result, every
per-run manifest — is named only through its config-string ID. The L4
(Collector), L7 (Persistence), and L8 (Submitter) layers consume
`core.Vault` abstractly; they never know or care which backend is
behind it.

Backend selection is by self-registering factory: each in-tree backend
(`local`, `s3`, `gcs`, `azure_blob`) registers itself via `init()`
into `vault.RegisterBackend`. `internal/vault/builtin` blank-imports
them; `cmd/sigcomply` blank-imports `vault/builtin`. The factory in
`internal/vault/factory.go` does a registry lookup — no hardcoded
switch, no per-backend knowledge.

**Consequence.** Adding a new vault backend (SFTP, MinIO, NFS, an
internal object store, anything) is one new package implementing
`core.Vault` plus one `init()` call to `vault.RegisterBackend`. No
edits anywhere in `internal/vault`, `internal/collector`,
`internal/orchestrator`, or `cmd/sigcomply`. The pattern matches
Axiom 1 mechanically — same `RegisterX` shape, same blank-import
bootstrap, same project-local extension surface (`.sigcomply/plugins/`
compiled in by `sigcomply build` at M16). See
[`07-extensibility.md`](07-extensibility.md) §Custom vault backends.

### Axiom 6 — Manual-evidence input backends are interchangeable

The customer-owned bucket that holds the manual-evidence PDFs the CLI
reads (quarterly access reviews, signed NDAs, training certificates,
declarations) is named only through its config-string ID. The
`manual.pdf` source plugin consumes a `manual.Reader` interface
abstractly; it never knows or cares which backend is behind it. The
folder scheme — `{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/`
— is identical regardless of backend, so the folder presence and
temporal-window check the manual evaluator runs is identical across
backends, frameworks, and customers.

Backend selection is by self-registering factory inside the manual
package: each backend registers itself via `init()` into
`manual.RegisterReader`. `manual.buildReader` does a registry lookup —
no hardcoded switch.

**Consequence.** Adding a new manual-evidence backend (SFTP, MinIO,
NFS, an internal object store, an in-house workflow tool that mirrors
its uploads, anything) is one new subpackage implementing
`manual.Reader` plus one `init()` call to `manual.RegisterReader`. No
edits to the `manual.pdf` plugin core, no edits to the evaluator, no
edits to any policy. Same mechanical pattern as Axioms 1 and 5. See
[`07-extensibility.md`](07-extensibility.md) §Custom manual-evidence
backends.

---

## How the abstractions compose: a tiny worked example

A SOC 2 customer wants to verify that all users with admin access have
MFA enabled. They have users in both AWS IAM and Okta.

**Step 1 — Policy spec (shipped with the framework):**

```yaml
id: soc2.cc6.1.admin_mfa_enforced
control: CC6.1
severity: high
evidence_mode: automated
description: "All admin users must have MFA enabled."
slots:
  user_directory:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
parameters: {}
pass_when:
  quantifier: all
  slot: user_directory
  condition: { op: eq, field: "payload.mfa_enabled", value: true }
violation_message: "MFA disabled for {{.payload.email}}"
```

(Shipped policies are authored in Go via `autoPolicy{...}.policy()`
builders, not on-disk YAML; the YAML here mirrors the same fields for
readability. On-disk `policy.yaml` is only for project-local custom
policies.)

**Step 2 — Project binding (in `.sigcomply.yaml`):**

```yaml
sources:
  aws.iam: { region: us-east-1 }
  okta:    { domain: acme.okta.com }

policies:
  soc2.cc6.1.admin_mfa_enforced:
    bindings:
      user_directory: [aws.iam, okta]
```

**Step 3 — At run time, the planner produces:**

```
Policy:  soc2.cc6.1.admin_mfa_enforced  (evidence_mode: automated)
  Slot user_directory binds to: [aws.iam, okta]
  Evaluation: pass_when (all user_directory records mfa_enabled == true)
  Parameters: {}
```

**Step 4 — The collector executes:**

```
- aws.iam.Collect() → 30 directory_user envelopes
- okta.Collect()    → 17 directory_user envelopes
- Each envelope signed with its own ephemeral Ed25519 keypair
- All envelopes written to:
    soc2/2026-Q1/run_.../policies/soc2.cc6.1.admin_mfa_enforced/envelopes/
```

**Step 5 — The evaluator runs the `pass_when:` clause in-process:**

```
quantifier=all over user_directory: payload.mfa_enabled == true
  evaluated against [<47 directory_user records>]
→ status: fail
  violations: [
    { resource_id: "AIDAEXAMPLE01", reason: "MFA disabled for alice@acme.com" },
    { resource_id: "AIDAEXAMPLE02", reason: "MFA disabled for bob@acme.com" },
    { resource_id: "okta-user-99",  reason: "MFA disabled for carol@acme.com" }
  ]
```

**Step 6 — Persistence writes:**

```
policies/soc2.cc6.1.admin_mfa_enforced/result.json
  { status: fail, violations: [...] }   # full fidelity, stays in vault
```

**Step 7 — Aggregation produces:**

```
{
  policy_id:           "soc2.cc6.1.admin_mfa_enforced",
  controls:            [{ framework: "soc2", control_id: "CC6.1", relationship: "equal" }],
  status:              "fail",
  severity:            "high",
  resources_evaluated: 47,
  resources_failed:    3,
  message:             "3 of 47 admin users do not have MFA enabled"
}
```

The three users' identities never leave the vault. The auditor —
months later — can open the vault, find this policy's result.json,
verify each envelope's signature offline, and confirm exactly which
users failed.

---

## What's deliberately not here

- **No "data lake" abstraction.** Evidence flows directly from
  source plugins to policy evaluators; there is no shared evidence
  store that policies query.
- **No cross-run state propagation.** A run cannot read another run's
  results. Period state is derived by readers (dashboard, report
  command), never consumed by the CLI itself.
- **No mutable shared registry.** Plugins and policies register at
  process startup based on the in-binary and project-local sets;
  there is no dynamic re-registration mid-run.
- **No "scope" or "tenant" dimension.** Single-scope v1 (one CLI run =
  one organizational unit). Multi-scope is deferred to v2; when added,
  it will introduce a `scope_id` on evidence records and a
  scope-aware aggregation contract — additive, not breaking.

---

## See also

- [`03-policy-spec.md`](03-policy-spec.md) — how `cadence` and `on_push`
  are declared on a policy spec.
- [`08-project-config.md`](08-project-config.md) — the per-policy
  `cadence` override (under `policies:`) in `.sigcomply.yaml`.
- [`09-ci-execution-model.md`](09-ci-execution-model.md) — how CI
  workflow files schedule cadences and invoke the CLI (Axiom 4 in
  practice).
