# 08: Project config

This page records why `.sigcomply.yaml` is shaped the way it is. Every key, type, default and
allowed value is owned by [`docs/configuration.md`](../configuration.md); per-source keys by
[`docs/reference/sources.md`](../reference/sources.md). Don't restate keys here. When this page
and the code disagree, the code wins; fix both docs.

## Why one file

- The CLI reads `--config <path>`, else `./.sigcomply.yaml`. One file, no `include:`,
  `extends:` or inheritance. An organization with ten projects keeps ten copies of its shared
  blocks in sync itself; nothing detects drift between them.
- One repo is one project is one framework. `framework:` is singular; there is no `frameworks:`
  list. A customer with two frameworks uses two repos.
- The loader parses with `yaml.KnownFields(true)`: any unknown key, top-level or nested, is a
  config error (exit 3). A silently ignored typo (`framewrok:`) in a compliance config is an
  audit gap. The exceptions are the open bags (`vault:`, `sources.<id>`) and `experimental:`
  (see [Config evolution policy](#config-evolution-policy)).
- Keys that were parsed but never read (`cloud.enabled`, `output.*`, `ci.fail_severity`,
  `ci_environment`, `extensions.path`) were removed before launch. `spec.checkRemovedKeys` runs
  before the strict decode so a file still setting one gets `"<key>" was removed and has no
  effect` (exit 3) instead of the decoder's `field ... not found in type ...`. A key that is
  accepted must do something; one that does nothing tells the operator a story the run does not
  honour (`ci.fail_severity: critical` never changed which failures exited 1).

## Precedence: values, not scheduling

Flags override the config file, and the config file overrides built-in defaults. No environment
variable sets a config value. `check` reads the framework only from `framework:` in the config; it
has no `--framework` flag and ignores `SIGCOMPLY_FRAMEWORK`, which only `init` and the `evidence`
subcommands read. A missing `framework:` is a config error, not a `soc2` default.

Precedence covers values, not which policies run. A run takes its policy set from at most one
filter flag and the per-policy cadence state; deciding when each cadence runs is the CI
scheduler's job. See [`09-ci-execution-model.md`](09-ci-execution-model.md) and
[`10-cadence-model.md`](10-cadence-model.md).

## The period model

- `fiscal_calendar.type` tunes how a period is derived (`calendar_quarter`, `fiscal_year`,
  `custom` with explicit boundaries). The derivation itself is fixed.
- `time_basis` is validated at load whether or not `fiscal_calendar.type` is set.
- `time_basis: commit` (default) measures the period on HEAD's commit time, so re-running an old
  commit reproduces its period. `wall_clock` uses the run's start, for projects whose runs are
  scheduled posture scans. `planner.PeriodTime` chooses; every period in the run is measured on
  its result.
- `planner.DerivePeriod` freezes the run's period at run start; every policy in a run shares one
  `period_id`. A manual entry's upload folder is the one exception: it is keyed by the entry's
  own cadence window (`planner.CadencePeriod`). See [`10-cadence-model.md`](10-cadence-model.md)
  §Manual evidence periods.

## The binding model

All per-policy settings sit under one object per policy ID in `policies:` (bindings,
parameters, cadence, evidence mode, exceptions). A new per-policy dimension is a new optional
field on that object, never a new top-level map, so the config grows without a schema bump.

`bindings: { <slot>: [<source_id>, ...] }` is the only place a policy meets a concrete source.
Policies declare what they accept, sources declare what they emit, and the binding chooses. The
planner checks it two ways:

- An explicit binding whose source emits nothing the slot accepts is a plan error (exit 3).
- With no explicit binding, every configured source that emits an accepted type is bound
  (auto-bind). A required slot that nothing can feed is not an error; the policy is skipped.
  A `policies:` entry is only needed to narrow or tune.

Roster slots. A slot with `role: roster` is never auto-bound: which source is the organization's
list of people is the operator's decision. It binds to its explicit `bindings:` entry, else
`experimental.roster.source`, else nothing, and is always exactly one source (a union of rosters
would let a person missing from the real one pass). A `role: roster_subject` slot auto-binds as
usual minus every source bound to the same policy's roster slot, because a directory cannot vouch
for its own accounts; naming such a source explicitly is a plan error. When a required roster
slot stays unbound, the policy's other bindings are dropped and it skips with "no roster source
designated". Customer guide: [`../guides/identity-roster.md`](../guides/identity-roster.md).

`manual.pdf` is a project-level singleton: one `sources.manual.pdf` entry, and `manual.pdf[x]`
is rejected. API sources may have bracketed instances (`aws.iam[staging]`) for a second account
or org. The instance key becomes part of a vault path, so it is limited to letters, digits, dot,
dash and underscore. See [`04-source-plugins.md`](04-source-plugins.md) §Multiple plugin
instances.

## The exception model

Exceptions live under the policy they apply to (`policies.<id>.exceptions`). They are config,
not code, because a waiver is a governance decision an auditor must read, date and trace in git.

- The planner keeps every entry that has not expired (`planner.resolveExceptions`), in declared
  order, and the evaluator applies each scoped entry to its own resources. A live entry with no
  scope decides the whole result, so the planner keeps the first such entry alone.
- A scoped `waived` exception runs the rule and reclassifies only the matching resource's
  failure. An exception with no scope sets the whole policy to its state; `na` skips evaluation.
- An exception past its `expires_at` is ignored, so a stale waiver never keeps masking a
  failure.

To move a control between evidence flows, override `evidence_mode` on the one policy: a control
satisfied by a document today (`manual` + `catalog_entry`) can later switch to `automated` with
bindings. The policy ID and control mapping stay; `result.json` and the cloud payload record the
override (`evidence_mode_overridden`).

## The controls section

`controls:` holds decisions made per control, the unit auditors and the ISO Statement of
Applicability use. Control IDs must belong to the project's one framework; any other ID is a
plan error (`validateProjectReferences`). An ISO 27001 example:

```yaml
controls:
  A.7.4:
    applicability: not_applicable
    reason: "Cloud-only; physical security monitoring inherited from the cloud provider."
    approved_by: ciso@example.com
  A.5.7:
    justification: "Threat intel consumed from the CISA KEV feed; triaged weekly."
    approved_by: ciso@example.com
```

- `not_applicable` cascades: every policy mapped to the control becomes `na` with the control's
  reason. The planner resolves this before policy exceptions, so it takes precedence.
- `reason` says why a control is excluded; `justification` says why an included one is needed
  (ISO/IEC 27001:2022 6.1.3 d)). Setting both is a config error. `sigcomply report --view soa`
  prints `justification`, or derives one marked `(derived)`.
- Management-system controls (`core.ControlKindManagementSystem`, ISO 27001's `C.` clauses 4-10)
  cannot be `not_applicable`. `validateApplicability` (`internal/planner/references.go`) rejects
  it, because the cascade would otherwise turn every policy under the clause into `na`, remove
  them from the score denominator and raise the score. Rationale:
  [`13-isms-clauses-and-soa.md`](13-isms-clauses-and-soa.md).

## Vault config is flat and open

`vault:` is `backend` plus whatever keys that backend reads, with no per-backend sub-blocks and no
auth block: storage credentials are the SDKs' ambient ones. Only `backend` is interpreted by the
loader; the rest is an open bag passed to the backend factory (`VaultConfig`), symmetric with
`sources:`. Adding a backend therefore touches nothing in `internal/spec`: each factory checks its
own required keys at `vault.FromConfig`, before any work. The cost is that a typo in a vault key
is not caught by the loader.

## Operator-declared sets under `experimental:`

### The scope model

The key is `experimental.scope`. `sources:` says what the project has wired, not what it should have wired. A required slot with
no configured emitter is skipped and leaves the score denominator, so forgetting a platform
raises the score. `experimental.scope.required_sources` is the outside baseline: the run is
checked against the operator's declaration of the estate, not against itself.

- A declared source counts as covered only if it is configured, bound by some policy slot, and
  returned at least one record. Stopping at "configured" would pass a source with missing
  credentials or one whose every collection failed.
- Opt-in. No declaration means no verdict, no new output and an unchanged `summary.json`.
- Per project. Rolling several projects into one estate is not the CLI's job.
- Vault-side only. Source IDs often embed account names and `declared_by` is an email, so the
  verdict goes to `summary.json` and never to the cloud payload.
- An incomplete estate fails the run like a failing policy (exit 1, subject to
  `ci.fail_on_violation`).

### `experimental.vendors`

A vendor requirement is one control over N third parties. One folder for all of them would make
eleven current reports and one two-year-old report indistinguishable. The register supplies the
set, and a catalog entry that declares `fanOut` scans one folder per member.

The fan-out multiplies folders, not policies: one policy ID, one binding, one envelope, one state
shard. One policy per vendor would make the vendor slug an identity that state shards,
`validateProjectReferences`, the `evidence due` catalog and the coverage and SoA views all key
off, and would put the vendor list on the wire through `policy_id`. With one policy, the evaluator
reduces N verdicts to `resources_evaluated` / `resources_failed`.

Every tier but `low` requires a folder; `low` requires a recorded rationale and approver instead.
A tier that simply removed the obligation would shrink the denominator by operator choice, the
failure `experimental.scope` exists to prevent. Manual-evidence mechanics:
[`14-manual-evidence.md`](14-manual-evidence.md). Customer guide:
[`../guides/vendor-risk.md`](../guides/vendor-risk.md).

### `experimental.risks`

A risk register has nothing the CLI can observe, so it does one thing: it carries the
risk-to-control edge into `report --view soa`, which ISO/IEC 27001 6.1.3 b) and d) need. It
copies the vendor register's shape (IDs under `experimental:`, shape-validated, unknown subkeys
warned) but not the fan-out: a risk mints no policy and owns no folder, for the same reasons as
above.

- A risk's `level` changes which artifact is owed, never whether one is owed. `retain` owes
  `accepted_by` and `acceptance_rationale` instead of a control.
- Descriptions and owners are identity-bearing. The SoA carries risk IDs only; nothing about a
  risk reaches the cloud payload.

### `experimental.roster`

Designates the roster source, plus per-source `aliases` and `non_human` lists. A roster the
operator named but the CLI cannot use (missing, bracketed, not configured, emits nothing a roster
slot accepts, or an `aliases`/`non_human` key that is not a configured source) fails the plan,
because it would otherwise silently skip every roster control. Unknown subkeys only warn. Aliases
are identity data and stay vault-side.

## Config evolution policy

`.sigcomply.yaml` is the audit trail of the customer's decisions and must keep loading across CLI
upgrades.

- Additive only within `project.v1`. New keys are optional with a safe default; existing keys are
  never renamed or removed. The one exception was the pre-launch removal of the no-op keys above,
  which fail loudly by name rather than load silently. A `project.v2` is the last resort for a breaking shape change, and
  none exists. Before shipping one, decide how configs migrate.
- New, not-yet-stable fields go under `experimental:` first. Strict parsing would make a new
  top-level key a load error on every older CLI; `experimental:` is the one place an older CLI
  tolerates subkeys it does not know. Each feature reads its own key. The loader also runs
  `spec.LoadScopeConfig` so a malformed `experimental.scope` is a config error (exit 3) before
  collection; read later, it could only be a warning after the evidence was already signed.
- Validation inside an `experimental.*` feature must warn on unknown subkeys, not reject them, or
  the forward-compatibility hazard comes back one level down. A malformed recognized key (a bad
  date, a duplicate ID) is still an error.
- Graduating a field from `experimental.<name>` to a top-level key has not happened yet. When it
  does, keep accepting the old form for at least one release.

## Worked example

[`examples/acmecorp.sigcomply.yaml`](examples/acmecorp.sigcomply.yaml) is a complete SOC 2
config. `project_config_test` loads it.
