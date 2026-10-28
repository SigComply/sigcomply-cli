# 10. Cadence model

How the CLI decides, per policy and per run, whether to evaluate a policy now or carry its prior
result forward, and which audit period a run and a manual upload belong to. This doc owns the
period clock (`planner.PeriodTime`), the run period (`planner.DerivePeriod`) and the manual
evidence cadence windows (`planner.CadencePeriod`). Other docs link here.

## Two axes: cadence and period

- **Cadence** is per policy: "is this policy due to re-check?" Under `--scheduled` the answer
  depends on a mutable state shard in the vault. State is never signed and is not an audit
  deliverable; it only gates the planner.
- **Period** is per run: "which audit window does this run's evidence belong to?" The planner
  derives it once at run start and every policy in the run shares it. A manual entry's upload
  folder is the one exception: it follows the entry's own cadence window (see
  [Manual evidence periods](#manual-evidence-periods)).

A daily policy evaluated 90 times in `2026-Q2` produces 90 signed envelopes, all stamped
`period_id: 2026-Q2`. A quarterly policy evaluated once produces one.

## Cadence DSL

A policy declares `cadence:` in its spec; a project overrides it under `policies.<id>.cadence`.

| Value | Minimum interval before due again (`planner.CadenceInterval`) |
|---|---|
| `continuous` | 0 (always due) |
| `hourly` | 0 (always due) |
| `daily` | 23h |
| `weekly` | 6d 23h |
| `monthly` | 27d 23h |
| `quarterly` | 89d 23h |
| `annual` | 364d 23h |
| `every:<duration>` | the Go duration (`every:6h`, `every:90m`); floor 5 minutes |

Rules:

- The 1-hour slack on named cadences absorbs CI cron dispatch delay. `every:24h` has no slack, so
  it is not the same as `daily`.
- Each named interval is no longer than the shortest calendar window of its cadence (28-day
  February, 90-day quarter, 365-day year), so a daily `--scheduled` run evaluates every policy at
  least once in every calendar window and reads each manual folder
  (`TestIsDue_DailyRunsEvaluateEveryCalendarWindow`).
- `every:` values below 5 minutes are rejected when the policy or config loads
  (`parseEveryCadence`, `minEveryDuration`, `spec.validateCadenceSpec`).
- Write `every:6h` with no space after the colon; `every: 6h` parses as a YAML mapping.
- A bare duration (`cadence: 24h`) is a load error with a hint to add `every:`
  (`internal/spec/policy.go`).
- Overrides match policy IDs exactly. An unknown ID fails with "no such policy … did you mean"
  (`planner.validateProjectReferences`). There are no glob overrides.
- An override changes how often a policy runs. It does not move a manual entry's upload folder
  (see [Manual evidence periods](#manual-evidence-periods)).

## Per-policy state shards

The CLI writes one state file per policy under the vault prefix, next to the run folders:

```
{vault prefix}/
   {framework}/{periodID}/run_{stamp}_{id8}/...   signed run output (buildRunRoot)
   state/{framework}/policies/{policy_id}.json    mutable state (PolicyStatePath)
```

State is mutable by design. If the operator puts the vault under Object Lock or a retention rule,
they must exclude `state/`. Losing state is safe: the next `--scheduled` run treats every policy as
a first run and evaluates it. Evidence integrity does not depend on state.

The shard type is `core.PolicyState` (`internal/core/policy_state.go`): `LastRunAt`,
`LastPassAt` (the gating key), `LastFailAt`, `LastRunStatus`, `LastPeriodID`, `LastRunID`,
`LastPolicyHash`, `LastEnvelopeRef`, `NextDueAt`, `ConfiguredCadence`.

Why one file per policy:

- Concurrent CI runs rarely touch the same policy, so per-policy files give write isolation without
  conditional puts.
- Removing a policy from the bundle leaves one orphan file instead of a map entry to edit.

`BulkReadPolicyStates` (`internal/orchestrator/state.go`) issues one GET per framework policy, 8 at
a time. It does not list the prefix.

### Monotonic write rule

`WritePolicyState` accepts a write only if:

```
new.LastRunAt > existing.LastRunAt
OR (new.LastRunAt == existing.LastRunAt AND new.LastRunID > existing.LastRunID)
```

A runner with a slow clock cannot overwrite a newer result. A rejected write returns nil: the vault
already holds equal or newer state.

Every mode except `--pr` advances state after evaluation (`advancePolicyStates`), so a passing
`--on-push` run on the default branch sets `LastPassAt` and a later `--scheduled` run can carry the
policy forward. A `--pr` run evaluates a pull request's branch and config, so it neither advances
state nor submits to Cloud. Any run in a pull-request or merge-request pipeline skips the state
advance too, whatever its flags (`inPullRequestPipeline`). A failed state write is
logged as a warning; the policy stays due and re-evaluates next time.

## The decision rule

`planner.decideEvaluation` (`internal/planner/planner.go`) gates each policy, and delegates the
cadence question to `planner.IsDue` (`internal/planner/cadence.go`):

```
decideEvaluation(filter, cadence, stateHash, prior, now):
  1. filter.IsExplicit() (--cadence, --cadences, --on-push)  -> evaluate
  2. prior == nil (state not loaded, or no shard yet)          -> evaluate
  3. stateHash == ""                                           -> evaluate (fail closed)
  4. prior.LastPolicyHash != stateHash (an empty prior too)    -> evaluate
  5. IsDue(cadence, prior, now)                                -> evaluate
  6. else -> carry forward; Status = carried_forward,
             SkipReason = DueReason(cadence, prior, now)

IsDue(cadence, state, now):
  state == nil or state.IsFirstRun()   -> due
  state.LastRunStatus != pass          -> due (failed policies retry every run)
  CadenceInterval(cadence) == 0        -> due (continuous, hourly)
  LastPassAt.IsZero()                  -> due
  now - LastPassAt >= interval         -> due
  else                                 -> not due
```

`DueReason` produces a deterministic string such as `only 4h12m since last pass; cadence interval
6h0m0s not yet elapsed (next due 2026-05-25T09:00:00Z)`. Intervals render with
`time.Duration.String()`, so a quarterly interval reads `2159h0m0s`.

### Content-hash invalidation

`PolicyContentHash` is the SHA-256 of a hand-built canonical projection (`canonicalizePolicy`,
`internal/core/policy_state.go`) of: `id`, primary control, `rule`, the whole `pass_when` tree,
`severity`, `cadence`, `on_push`, slots (sorted `accepts`, cardinality, required, role,
`fail_when_empty`), parameters (type + default), and the digests of every registered
evidence-type schema, not only the ones the policy accepts. A schema bump therefore re-evaluates
every policy under `--scheduled`; that errs on the safe side.

- `pass_when` must stay in the projection. Shipped policies are `pass_when`-driven; without it, an
  edited threshold or operator would leave the hash unchanged and the old signed result would be
  carried forward. The projection walks every clause in order (quantifier, slot,
  `violation_msg`, `identity_key`, `min_percentage`, `condition`, `filter`, nested
  `all_of`/`any_of`, `matches_in`). Clause order is semantic and never sorted; map-valued parts are
  flattened to sorted pairs.
- The projection is built by hand because the `pass_when` types have no `json:` tags; marshaling
  the structs would key on Go field names and a field rename would rotate every hash.
- A hash change makes the policy due regardless of cadence. The carried-forward skip reason names
  the mismatch; no run-level notice is printed.
- An empty hash (nil policy, or a `value:` JSON cannot represent) means "evaluate", never "no
  change" (branch 3). So does a prior shard with no hash (branch 4).

The gate compares `PlannedPolicy.StateHash`, not the content hash. `planner.policyStateHash`
folds the policy's effective project configuration into `PolicyContentHash`: resolved
parameters, the resolved cadence, evidence mode and catalog entry, the source IDs bound to each
slot, and the live exceptions (state, resource scope, expiry). Tightening a parameter, adding an
account, adding or expiring a waiver, or switching a policy to manual therefore re-evaluates it on
the next `--scheduled` run instead of carrying an old pass forward. `advancePolicyStates` writes
the state hash to `LastPolicyHash`. It stays in the vault; the wire's `policy_content_hash` is
still the spec-only content hash, so no source ID or exception scope reaches the payload, even
hashed. The first run after this was introduced re-evaluates every policy once.

## Carry-forward results

A carried-forward `result.json` has `Status: carried_forward` and a `CarryForward`
(`core.CarryForwardRef`) with `LastEvaluatedAt`, `LastEvaluatedRun`, `LastEnvelopeRef`,
`LastKnownStatus` and `SkipReason`. The CLI writes no new envelope and no new signature. An auditor
verifies the original envelope at `LastEnvelopeRef`; the carried-forward result inherits trust only
from that signature.

## Period freeze rule

The run's audit period (`2026-Q1`, `FY2026`, or a custom ID) is computed once at run start:

```
period = planner.DerivePeriod(&cfg.Period, planner.PeriodTime(&cfg.Period, commitTime, now))
```

- `planner.PeriodTime` returns the run's start clock when `period.time_basis` is unset or
  `wall_clock`, and the HEAD commit time only under an explicit `commit`. The run clock is the
  default because a dedicated compliance repository rarely gets commits: under `commit` its daily
  run would keep evaluating, and `evidence due` would keep pointing uploads at, a period that
  closed months ago.
- `commitTime` comes from `gitContext` (`cmd/sigcomply/check.go`):
  `GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP`, else `git show -s --format=%cI HEAD`, else `time.Now()`.
- `period.fiscal_calendar.type` is `calendar_quarter` (default), `fiscal_year` (with `starts:
  <month>`, any month; IDs are `FY<year>`), or `custom` (named windows).
- Every policy in the run shares the period. A run that starts at `2026-03-31T23:55:00Z` and ends
  in April still stamps `2026-Q1`.
- Period boundaries are UTC (`DerivePeriod` and `CadencePeriod` convert to UTC first).
- Under an explicit `commit` basis, a run cannot read evidence for a period its HEAD commit has
  not reached, and a quiet repository stays in a closed period until the next commit. Nothing
  warns about it; that is the trade for reproducible replays.

The CLI writes one `summary.json` per run, in the run folder. It keeps no per-period roll-up; any
cross-run view is built by `report` from run folders or by SigComply Cloud.

## Manual evidence periods

A manual entry's upload folder is keyed by the entry's own cadence window, not by the run period:

```
{bucket}/{prefix}{evidence_catalog_id}/{period_id}/
              daily 2026-01-15 · weekly 2026-W03 · monthly 2026-01
              quarterly 2026-Q1 · annual 2026
```

`planner.CadencePeriod(cfg, t, cadence)` is the single derivation. The planner
(`resolveManualBinding`) and `sigcomply evidence due` (`internal/manualdue`) both call it with the
same `PeriodTime` clock and the entry's declared cadence, so the folder `evidence due` reports is
the folder `check` reads.

| cadence | `calendar_quarter` | `fiscal_year` | `custom` |
|---|---|---|---|
| daily | `2026-01-15` | `2026-01-15` | run period |
| weekly | `2026-W03` | `2026-W03` | run period |
| monthly | `2026-01` | `2026-01` | run period |
| quarterly | `2026-Q1` | `2026-Q1` | run period |
| annual | `2026` | `FY2026` | run period |

`continuous`, `hourly` and `every:<duration>` have no calendar window and use the run period.

Why: the temporal-window check (`isInTemporalWindow`) is closed at both ends, so a file satisfies
only a run whose window contains its upload time. If an annual attestation's folder followed the
run's quarter, a January upload would be invisible to the April, July and October runs, and
an annual policy evaluated in those runs would fail.

What follows the cadence window: the folder path, the temporal window, and the `period_id` in the
signed evidence record. The collector stamps `period_id`, `period_start`, `period_end` and
`prior_period_id` on the slot request from one `planner.Period` (`collector.buildSlotRequest`).
What stays on the run period: the run folder, `manifest.json`, `summary.json`, the cloud payload's
`period_id` and `PolicyState.LastPeriodID`.

The resolver uses the declared cadence of the manual policy that owns the entry, not a project
override, so an override never relocates the folder. A policy switched to manual with
`catalog_entry` takes that entry's cadence too (`resolveManualBinding` doc comment).

Customer-facing folder rules: [`../configuration.md`](../configuration.md) §Manual evidence. The
manual-evidence contract: [`14-manual-evidence.md`](14-manual-evidence.md).

## Sub-period aggregation

`PolicyResult.PeriodAggregate` (evaluations, pass/fail counts, longest failure streak, longest gap)
is reserved. No command populates it: one run cannot see its period history without scanning the
vault, and the CLI keeps no cross-run state beyond the gating shards.

## Modes and state

| Mode | Set by | Loads state? | Gates by cadence? | Advances state? |
|---|---|---|---|---|
| `ModeManual` | default, `--cadence`, `--cadences`, `--on-push` | No | No | Yes |
| `ModePR` | `--pr` | No | No (on-push set) | No |
| `ModeScheduled` | `--scheduled` | Yes | Yes | Yes |

`resolveMode` (`internal/orchestrator/orchestrator.go`) loads state only in `ModeScheduled`.
`ModeScheduled` with an explicit filter would skip the state load, but `check` makes `--scheduled`
mutually exclusive with every filter flag, so that path is unreachable from the CLI.

## Day-1 warnings

`emitPlanWarnings` (`internal/orchestrator/orchestrator.go`) prints these after planning:

- Under `--scheduled` only (other modes load no state, so "first time" would be false on every
  run), at info level: `first-run: N policies will evaluate for the first time this run` for
  policies with no shard; or, when the vault holds no state at all, `first-run: no cadence state
  found in the vault, …` plus a hint that a vault which does not outlive the CI job (a local
  folder) makes every run a first run.
- `gap-detected: N policies have no evaluation in the last 30d; today's run does not backfill`,
  at warning level. It needs prior state, so it fires only under `--scheduled`. The threshold is
  the larger of 30 days and 1.5 × the cadence interval, although the message says 30d. The CLI
  never back-fills missed evaluations.
- `coverage-skew` and `coverage-gap` warnings, for slots that no configured source can bind (see
  [04a](04a-evidence-type-registry.md)).

### Manual evidence due (`sigcomply evidence due`)

A separate, advisory command. The scaffolded scheduled workflow runs it as a non-failing step.

```
manual evidence: 3 of 52 entries have an empty folder (run period 2026-Q3)
  ENTRY                        CADENCE    PERIOD   DUE IN  UPLOAD TO
  access_review_quarterly      quarterly  2026-Q3  14d     s3://acme-evidence/manual/access_review_quarterly/2026-Q3/
  security_awareness_training  annual     2026     105d    s3://acme-evidence/manual/security_awareness_training/2026/
```

Rules it follows (`internal/manualdue`):

- It lists only entries whose current folder is empty; an entry disappears once a file lands.
  Fan-out entries are checked once per member.
- Empty folders outside `--within-days` are counted (`Report.Suppressed`) and named in the
  summary line ("N of M entries have no upload for the current period; none closes within D
  days"). The all-clear line appears only when every folder has a file.
- `window_closes` (period end plus grace) is the temporal-window bound, not a late-upload
  deadline: under the default run-clock basis no run reads a folder after its period ends.
- It exits 0 whatever it finds and 3 on a config error
  ([commands](../reference/commands.md#sigcomply-evidence-due)). A storage failure is reported
  as "could not verify", not as a deadline, and still exits 0.
- `PERIOD` is per entry (its cadence window). The run period is printed once as context.
- `DUE IN` counts down to the entry's period end on the `PeriodTime` clock (the run clock by
  default), so it matches the folder the next run reads. There is no "overdue" state.
- It does not use `PolicyState.NextDueAt`: `AdvancePolicyState` sets that only after a pass, so a
  policy that never passed has none.
- It is not part of `check`: a `--scheduled` run carries passing manual policies forward without
  listing their folders, and a filtered run may not select them, so `check` cannot replace it.

## Cloud payload cadence fields

Each `AggregatedPolicy` (`internal/core/cloud.go`) carries five scalars so the dashboard can show
staleness without recomputing: `configured_cadence`, `last_evaluated_at`, `next_due_at`,
`is_carried_forward`, `policy_content_hash`. They are scalars, not maps, and the reflection test in
`internal/core/cloud_test.go` fails the build if a freeform field is added. Schema versioning is
owned by [06](06-aggregation.md).

## Out of scope by design

| Item | Reason |
|---|---|
| Cron strings as the cadence DSL | Named cadences plus `every:<duration>` cover the catalog. |
| Drift detection between runs | Cross-run history is Rails work; the CLI is snapshot-based. |
| Cadences under 5 minutes | API rate limits and cost. |
| Glob overrides (`soc2.cc6.*`) | Not needed yet. |
| Skip-when-evidence-unchanged, `pause_until` | Cadence plus retry-on-fail covers the need. |
| Calling cadence-gated checks "continuous monitoring" | Auditors flag the mismatch; say "scheduled evaluation". |
| Sending more than the five cadence scalars to Cloud | The wire type stays counts-only. |

## Code map

- `internal/planner/cadence.go`: `CadenceInterval`, `IsDue`, `DueReason`, `NextDueAt`.
- `internal/planner/planner.go`: `decideEvaluation`, `filterAccepts`, `resolveManualBinding`.
- `internal/planner/period.go`: `PeriodTime`, `DerivePeriod`, `CadencePeriod`.
- `internal/core/policy_state.go`: `PolicyState`, `PolicyContentHash`, `canonicalizePolicy`.
- `internal/orchestrator/state.go`: shard paths, bulk read, monotonic write, `AdvancePolicyState`.
- `internal/orchestrator/orchestrator.go`: `resolveMode`, `loadPolicyStates`,
  `advancePolicyStates`, `emitPlanWarnings`.
- `internal/manualdue/due.go`: `evidence due` scan and output.
