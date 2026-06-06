# 08 — Project Config

The `.sigcomply.yaml` at the repo root is the customer's source of
truth. It declares the framework, the fiscal calendar, the source
plugins and their configuration, policy bindings, parameter overrides,
exceptions, and the vault location.

Everything in this file is versioned in git. Auditors read it.
Reviewers ask "why?" on changes. It is intentionally human-authored
and human-reviewed.

> **Scope of this document.** This is the *architectural rationale* for
> the project config — why it is one file, how precedence works, and the
> semantics of the period / `policies:` / `controls:` models. The **canonical, field-by-field schema and the complete
> `check` flag reference live in
> [`../configuration.md`](../configuration.md)** — that is the single
> source of truth for key names, defaults, and allowed values. This page
> deliberately does not restate them. When the two disagree,
> `configuration.md` wins.

---

## Why one file

The CLI resolves the project config from `--config <path>`, else
`./.sigcomply.yaml`. It is parsed with **strict** `yaml.KnownFields(true)`:
any unknown key — top-level or nested — is a configuration error (exit 3),
not a warning. This is deliberate: a silently-ignored typo'd key
(`framewrok:`) in a compliance config is a latent audit gap, so the parser
refuses it outright.

The shape is intentionally one file. A project that wants modularity
authors a single file with section comments; splitting into multiple files
is not supported in v1. One repo = one project = one framework (the
`framework:` key is **singular** — there is no `frameworks:` list), so the
config never needs to span frameworks; multi-framework customers use
multiple repos.

The top-level keys are `schema_version` (required, `project.v1`),
`framework`, `period`, `vault`, `sources`, `policies`, `controls`,
`cloud`, `output`, `ci`, `ci_environment`, `extensions`, and
`experimental`. Their fields and defaults
are documented in [`../configuration.md`](../configuration.md); the
sections below cover only the load-bearing *design* decisions.

---

## Precedence: values, not scheduling

For any single value the CLI resolves: **defaults → config file →
environment (`SIGCOMPLY_*`) → CLI flags** (later wins). The effective
values are what the run acts on.

The important architectural point is that **precedence applies to values,
not to scheduling.** A bare `sigcomply check` does not consult prior runs
to decide what to evaluate *now*: it takes its policy set from at most one
mutually-exclusive filter flag (`--cadence` / `--cadences` / `--on-push` /
`--pr` / `--scheduled`), applies effective per-policy `cadence` overrides
(from `policies:`) on top of framework defaults, runs that set, and exits. Deciding *which*
cadence to run when is the CI scheduler's job (the per-cadence cron
workflows), not the config file's. The `--scheduled` mode is the one place
the CLI itself reads prior state to gate by cadence. See
[`09-ci-execution-model.md`](09-ci-execution-model.md) for the run modes
and [`10-cadence-model.md`](10-cadence-model.md) for the decision rule.

The full flag list (and the fact that there is **no** `--framework`,
`--policies`, `--controls`, `--output`, `--period`, `--backfill`,
`--reopen-period`, or `--dry-run` flag — the real `check` flags are
`--config`, `--verbose`, `--cloud`/`--no-cloud`, `--cloud-url`,
`--capture-cloud-payload`, `--cadence`, `--cadences`, `--on-push`, `--pr`,
`--scheduled`) is in [`../configuration.md`](../configuration.md). The
framework is selected by config `framework:` or `SIGCOMPLY_FRAMEWORK`,
never a flag on `check`.

---

## The period model

`period` controls how each run is tagged with an audit window. Two design
choices matter:

- **`fiscal_calendar.type`** is one of `calendar_quarter` (default),
  `fiscal_year` (with an optional `starts:` month), or `custom` (which
  requires an explicit `periods:` list of `{id, start, end}` boundaries).
  The fiscal calendar tunes period *derivation*; the derivation algorithm
  itself is fixed and not customer-overridable.
- **`time_basis`** is `commit` (default) or `wall_clock`. `commit` ties
  the period to the evidence-bearing commit so re-running an old commit
  reproduces the same period — the audit-reproducibility choice.

The period is frozen per-run by the planner (`DerivePeriod`): every policy
in one run shares one `period_id`, with no mid-run rollover. This is the
"Period" axis of the two-axis cadence model — distinct from the mutable,
never-signed cadence state. See [`01-conceptual-model.md`](01-conceptual-model.md)
§Period and [`10-cadence-model.md`](10-cadence-model.md).

---

## The binding model

All per-policy configuration lives under one object per policy ID in the
`policies:` map — bindings, parameter overrides, cadence override,
evidence-mode override, and scoped exceptions, co-located:

```yaml
policies:
  soc2.cc6.1.mfa_enforced:
    bindings:
      user_directory: [okta, acme.internal_iam]
    parameters:
      exempt_service_accounts: false
    cadence: hourly
    exceptions:
      - scope: { resource_id: "okta_user:bot@acme.com" }
        state: waived
        reason: "Legacy deploy bot; retired by Q3."
        expires_at: 2026-09-30
```

This single-object shape is deliberate: a new per-policy dimension
(severity, scope, owner, enabled) is added as a new optional field here —
additive, never a new top-level section — so the config evolves without a
schema bump (see [Config evolution policy](#config-evolution-policy)).

`bindings` is the architectural keystone: `{ slot_name: [source_id, …] }`
is the **only** place a policy is connected to a concrete source. Policies
declare `slots.<name>.accepts: [<evidence_type>, …]`; sources declare
`Emits()`; the binding picks which emitting source feeds which slot. The
planner validates that every bound source is registered and that its
emitted types intersect the slot's `accepts:` — empty intersection is a
plan-time error (exit 3). This indirection is what makes sources
substitutable without touching policies (see
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)). Omitting
`bindings` for a policy auto-binds every configured source whose `Emits()`
intersects the slot — the substitutability default; a `policies:` entry is
only needed to *narrow* or otherwise tune a policy.

`manual.pdf` is a **project-level singleton** — exactly one
`sources.manual.pdf` entry, no bracket-suffix instance variants
(`manual.pdf[x]` is rejected). A manual policy names its catalog entry
with the structured `catalog_entry:` field (alongside `evidence_mode:
manual`), not a `manual.pdf:<entry>` colon-string. API plugins may have
bracketed instances (`"aws.iam[backup]"`) for multiple accounts.

---

## The exception model

Exceptions are declarative waivers and N/A declarations, listed under the
policy they apply to (`policies.<id>.exceptions`) — there is no `policy:`
field, the map key is the policy. Each entry carries an optional
`scope.resource_id` / `scope.resource_pattern`, a `state` (`waived` |
`na`), a required `reason`, and approval metadata (`approved_by`,
`approved_at`, `expires_at`). A policy may list several entries with
distinct scopes. They are config — not code — because a waiver is a
*governance* decision an auditor must read, date, and trace in git.

Semantics: a **scoped** `waived` runs the rule and reclassifies only the
matching resource's failure (every other resource still counts); a
**whole-policy** exception (no scope) sets the policy directly to its state
— `na` short-circuits without evaluating. Expired exceptions
(`expires_at` in the past) are ignored, so a stale waiver can never
silently keep masking a failure.

To evolve a control's evidence source over time, override its
`evidence_mode` on the policy object: a customer who satisfies a control
by PDF today (`evidence_mode: manual` + `catalog_entry`) can later flip
that **single policy** to `automated` (and supply its bindings) — same
policy ID, same control mapping, the audit trail records which path ran.
This is the supported migration between the two evidence flows without
renumbering policies or forking the framework.

---

## The controls section

`controls:` holds the coarse, governance-level decisions that are
naturally authored **per control**, not per check — the unit auditors and
the ISO Statement of Applicability think in:

```yaml
controls:
  CC6.4:
    applicability: not_applicable
    reason: "Cloud-only; physical security inherited from AWS."
    approved_by: ciso@acme.com
```

A control marked `not_applicable` **cascades**: every policy that maps to
it is set to `na` in the run, with the control's reason. This is the
clean, first-class replacement for waiving each policy under a control
individually. Control-level applicability takes precedence over a
policy-level exception (the planner resolves the control cascade first).
`approved_by` and `reason` form the audit trail; `owner` / `inherited_from`
are reserved for later — additive fields under the same key.

The two axes compose: `controls:` for coarse "this whole requirement is
out of scope / inherited," `policies.<id>.exceptions` for the fine,
resource-scoped waiver.

---

## Vault config is flat and open

`vault` is a **flat, open** mapping — `backend` plus whatever keys that
backend reads, directly under `vault:`:

```yaml
vault:
  backend: s3
  bucket: acme-evidence
  region: us-east-1
  prefix: sigcomply/
```

This is deliberately **symmetric with `sources:`**: only `backend` is
interpreted by the loader; every other key flows through as an open
config bag to the backend's factory (`VaultConfig.Config`). There are
**no** nested `local:` / `s3:` / `gcs:` / `azure_blob:` sub-blocks and
**no** `auth:` apparatus — storage authentication is ambient SDK
credentials only (`AWS_*`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_*`),
never declared in the config.

**Adding a destination backend touches no file in `internal/spec`.** The
loader does not enumerate backends or their required fields — that would
be a second source of truth that drifts from the vault registry. Each
backend validates its own required keys in its factory and surfaces a
clear error at `vault.FromConfig` (still at startup, before any work).
The current backends expect: `local`→`path`; `s3`→`bucket`+`region`
(plus optional `endpoint`+`force_path_style` for S3-compatible stores);
`gcs`→`bucket`; `azure_blob`→`account`+`container`. The full field list
is in [`../configuration.md`](../configuration.md). Because the bag is
open like `sources:`, a typo in a vault key is not caught by the loader's
`KnownFields` strictness — the planned cross-reference validation pass
(P1.1) is where unknown-key warnings for vault belong.

`output.format` validates to `text | json | junit` only — there is no
`sarif` value (the validator rejects it; no SARIF formatter exists). And
note that `check` itself emits one fixed text summary regardless of
`output.format`; only `report` renders alternate formats.

---

## Config evolution policy

`.sigcomply.yaml` lives in the customer's git repo and is the audit
trail of their compliance decisions. It must keep loading across CLI
upgrades. The shape therefore evolves under one rule:

**Additive-only within `project.v1`.** New keys are always optional and
carry a safe default; existing keys are never renamed or removed. An old
config keeps loading on a new CLI forever, and a config written for a new
CLI keeps loading on an older one — *provided* the new field landed under
the escape hatch first (below). `schema_version` only bumps to
`project.v2` for a genuinely breaking shape change, which ships with an
automatic `sigcomply migrate` and a deprecation window; that is the path
of last resort, not the normal way to add a feature.

**The `experimental:` escape hatch.** The loader runs with
`KnownFields(true)`, so a typo in a recognized key (`policys:`,
`vualt:`) is a loud load-time error — exactly what you want for a
hand-edited file. But that same strictness means any brand-new top-level
key would hard-fail every CLI released before it. To break the tension,
not-yet-stable fields are introduced under `experimental:` first:

```yaml
experimental:
  some_future_knob: true
```

Every CLI version that recognizes `experimental:` tolerates and ignores
subkeys it doesn't understand, so a newer config never breaks an older
pinned CLI. Once a field stabilizes it graduates from
`experimental.<name>` to a first-class top-level key in a later release
(the old `experimental.<name>` form is honored for one deprecation
window). The loader itself interprets nothing inside `experimental:`;
each feature opts in by reading its own key.

This is why the per-policy and per-control configuration is shaped as a
single object per ID (see [The binding model](#the-binding-model)) rather
than a family of parallel `policy_*` maps: a new per-policy dimension is
then a new optional field on that object — additive, never a new
top-level section — and the rule above holds without a `v2`.

---

## Worked example

A complete `.sigcomply.yaml` for AcmeCorp's SOC 2 pursuit lives at
[`examples/acmecorp.sigcomply.yaml`](examples/acmecorp.sigcomply.yaml).
A narrative walkthrough is in
[`examples/acmecorp-walkthrough.md`](examples/acmecorp-walkthrough.md).
