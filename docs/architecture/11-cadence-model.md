# 11 — Cadence Model

This document specifies how the CLI decides, for each policy in each
run, whether to **re-evaluate** it now or **carry forward** its prior
result. It is the answer to the foundational question every
compliance-as-code customer asks:

> "MFA needs to be checked every day; the board-meeting review needs
> to be checked every quarter. A single CI run triggers everything.
> How do you reconcile that?"

This file is the canonical reference for the cadence design. Every
other document in this tree refers back here for the decision rule,
the state shape, the day-1 warnings, and the auditor-visible
artifacts.

---

## The two axes

Cadence design lives on two orthogonal axes that must never be
conflated. Mixing them is dbt's most-imitated lesson.

```
                  POLICY EVALUATION DECISION
                  =========================
                              │
                ┌─────────────┴──────────────┐
                ▼                            ▼
         CADENCE axis                  PERIOD axis
   "should we re-evaluate now?"   "what audit window does
                                   the result belong to?"
                │                            │
   per-policy gating, mutable        per-run, immutable,
   state in vault/state/             stamped at run start,
                                     shared across all policies
```

- **Cadence** is a per-policy scheduling concern. It answers "is this
  policy due to re-check?" The decision depends on a mutable state
  shard kept in the customer vault. State is never signed, never an
  audit deliverable, never trusted by an auditor — it exists only
  to gate the planner.
- **Period** is a per-run compliance concern. It answers "what audit
  window does this run's evidence belong to?" The period is frozen
  at run-start by the planner and shared by every policy in the run.
  No mid-run rollover — see §Period freeze rule.

A daily-cadence policy evaluated 124 times across `2026-Q2` produces
124 signed envelopes, all stamped `period_id: 2026-Q2`. A quarterly-
cadence policy evaluated once in `2026-Q2` produces one envelope.
Both axes are visible to auditors; the framework summary makes the
distinction explicit (see §Sub-period aggregation).

---

## Cadence DSL

A policy's cadence is declared in its YAML spec:

```yaml
cadence: daily               # named cadence
cadence: every:6h            # interval-since-last-pass
```

### Named cadences

The seven canonical values, in ascending interval:

| Value        | Minimum interval before due again |
|--------------|-----------------------------------|
| `continuous` | 0 (always due in any run)         |
| `hourly`     | 0 (always due in any scheduled run) |
| `daily`      | 23 hours                           |
| `weekly`     | 6 days 23 hours                    |
| `monthly`    | 29 days 23 hours                   |
| `quarterly`  | 89 days 23 hours                   |
| `annual`     | 364 days 23 hours                  |

The 1-hour slack on every cadence absorbs CI cron drift. GitHub
Actions and GitLab CI commonly dispatch scheduled jobs 5–15 minutes
late under load; a strict 24h gate would silently skip days when
drift crosses midnight.

### Custom intervals: `every:<duration>`

The escape hatch for power users. The value after `every:` is a
Go-style duration (`time.ParseDuration` grammar): `6h`, `30m`,
`2h30m`, `90s`. Examples:

```yaml
cadence: every:6h          # every six hours since last pass
cadence: every:90m         # every ninety minutes
cadence: every:48h         # every two days (slightly stricter than `daily`)
```

Floor: 5 minutes. Anything tighter is rejected at plan time — CI
runners cannot meaningfully dispatch faster, and tighter intervals
just hammer API quotas.

YAML note: the colon must be followed by a non-space character
(`every:6h`, not `every: 6h`). YAML's mapping syntax requires
`colon-space` to parse as a mapping; `colon-letter` parses as a
single scalar.

### Customer overrides

Customers override the framework default in `.sigcomply.yaml`:

```yaml
policy_cadences:
  soc2.cc6.1.mfa_enforced_admin: every:6h
  soc2.cc7.2.annual_pentest: annual
```

Overrides are exact-match by policy ID. Unknown IDs are caught at
plan time. (Globs and severity-baseline overrides are intentionally
absent in v1 — see §What we do not do.)

### `every:24h` ≠ `daily`

The two are NOT equivalent. `daily` has the cron-drift slack baked in
(23h); `every:24h` is exactly 24 hours from last pass. Over a year,
`every:24h` will drift its time-of-day; `daily` stays anchored. A
plain `cadence: 24h` (no `every:` prefix) is a configuration error
with a hint to add the prefix.

---

## Per-policy state shards

State lives in the customer vault, OUTSIDE the immutable evidence
prefix:

```
{vault}/
   evidence/                                          ← signed, append-only
      {framework}/{periodID}/run_*/...
   state/                                             ← mutable, NOT under Object Lock
      {framework}/policies/{policy_id}.json
```

One file per policy. The single most important architectural
property: **the state file is mutable by design**, so it cannot live
under the same Object-Lock retention policy customers use for
evidence. State loss is recoverable (worst case: the next run re-
evaluates everything as first-run). Evidence integrity is
unaffected — the signing scheme does not depend on state.

### Shard schema

```go
type PolicyState struct {
    SchemaVersion     string       // "policy-state.v1"
    PolicyID          string
    Framework         string

    LastRunAt         time.Time    // any evaluation (pass/fail/skip/error)
    LastPassAt        time.Time    // gating key — separate from LastRunAt
    LastFailAt        time.Time
    LastRunStatus     PolicyStatus
    LastPeriodID      string
    LastRunID         string       // tiebreaker in monotonic write

    LastPolicyHash    string       // detects bundle/schema bumps
    LastEnvelopeRef   string       // points carry-forward results at the original signed envelope
    NextDueAt         time.Time    // pre-computed; planner is O(1) lookup
    ConfiguredCadence string
}
```

### Why per-policy shards, not one consolidated file

- **Concurrent CI runs** rarely collide on the same policy; sharded
  files give us per-policy write isolation without conditional-put
  preconditions.
- **`sigcomply why <policy>`** wants one file, not all 400.
- **State garbage collection** (a policy removed from the bundle)
  becomes a file delete, not a map mutation.

Trade-off: bulk reads need List + parallel GET. We use a worker pool
of 8 concurrent reads (`BulkReadPolicyStates`) — for 400 policies on
S3 that's ~2 seconds.

### Monotonic write rule

Two parallel CI runs against the same vault could race. The write
guard:

```
Accept the write iff:
   new.LastRunAt > existing.LastRunAt
OR (new.LastRunAt == existing.LastRunAt AND new.LastRunID > existing.LastRunID)
```

Last-writer-wins ordered by run-start time, with run-ID as the
lexicographic tiebreaker for true ties. Defends against clock skew
on individual runners (a slow-clock runner cannot overwrite a more-
recent successor).

A rejected write returns nil from `WritePolicyState` — the caller
sees no error because the vault already has equivalent-or-newer
state, which is the correct outcome.

---

## The decision rule

For each policy in the plan, the planner answers ShouldEvaluate using
a strictly-layered rule:

```
1. Filter explicit (--policies, --cadences, --on-push, etc.):
   → ShouldEvaluate = true
   (Operator forced; cadence-gate is bypassed.)

2. PolicyStates is nil (Manual or PR mode):
   → ShouldEvaluate = true
   (No gating; modes that don't load state always evaluate.)

3. Prior state is nil (never run before):
   → ShouldEvaluate = true
   (First-run warning surfaces in the run log.)

4. Prior policy content-hash differs from current:
   → ShouldEvaluate = true
   (Bundle update or schema bump invalidated prior evaluation.)

5. Prior terminal status was NOT pass:
   → ShouldEvaluate = true
   (on_fail_retry: failed policies retry every run until they pass.)

6. Now - LastPassAt ≥ CadenceInterval:
   → ShouldEvaluate = true
   (Cadence elapsed.)

7. Else:
   → ShouldEvaluate = false
   → Status becomes StatusCarriedForward.
```

The rule is encoded in `planner.decideEvaluation`. The reason string
attached to a carried-forward result is human-readable and
deterministic: `"only 4h12m since last pass; cadence interval 6h0m
not yet elapsed (next due 2026-05-25T09:00:00Z)"`.

### Content-hash invalidation

`PolicyContentHash` is the SHA-256 of canonicalized
(policy spec + referenced evidence-type schemas). When a bundle
update or schema bump changes the hash, every affected policy
becomes due regardless of cadence. The planner emits an info-level
notice naming the count of newly-due policies so the customer is not
surprised by a longer run.

This is the structural guard against silently re-certifying old
evidence with new rules.

---

## Carry-forward result format

When ShouldEvaluate is false, the evaluator emits a carry-forward
result.json that references the prior signed envelope:

```json
{
  "PolicyID": "soc2.cc1.board_review_quarterly",
  "ControlID": "SOC2.CC1.1",
  "Status": "carried_forward",
  "ConfiguredCadence": "quarterly",
  "PolicyContentHash": "sha256:...",
  "CarryForward": {
    "LastEvaluatedAt": "2026-04-01T10:23:14Z",
    "LastEnvelopeRef": "soc2/2026-Q2/run_20260401T102314Z_a3f9/policies/.../envelopes/manual_pdf__manual.json",
    "LastKnownStatus": "pass",
    "SkipReason": "only 1h42m since last pass; cadence interval 89d23h not yet elapsed"
  }
}
```

The carry-forward result is a tiny pointer, not a re-statement. No
new envelope is written; no new signature is generated. The auditor
verifies the original envelope at `LastEnvelopeRef` independently —
the carry-forward result inherits trust from the original signature,
not from anything the CLI claims about it.

---

## Period freeze rule

The audit period (`2026-Q1`, `FY2026`, custom) is computed once at
run-start by `planner.DerivePeriod`. Every policy in the run shares
the same `period_id`. A run that begins at `2026-03-31T23:55:00Z`
and takes twenty minutes still stamps every result with `2026-Q1`,
even though the wall clock crosses into Q2 mid-run. There is no
mid-run rollover.

The framework's per-period summary at `{framework}/{periodID}/
summary.json` is rebuilt on every run whose `startedAt` falls inside
that period. The first run whose `startedAt` lands in a new period
writes a fresh summary in the new period and never touches the
previous period's summary again.

---

## Sub-period aggregation

For policies whose cadence is **shorter** than the period (e.g.,
daily MFA check inside a quarterly period), "latest status" alone
doesn't answer the auditor's real question: *did this control hold
continuously throughout the period?*

The `PeriodAggregate` field on `PolicyResult` is reserved for this
purpose:

```go
type PeriodAggregate struct {
    EvaluationsInPeriod          int
    PassCount                    int
    FailCount                    int
    LongestFailureStreak         time.Duration
    FirstEvaluationAt            time.Time
    LastEvaluationAt             time.Time
    LongestGapBetweenEvaluations time.Duration
}
```

`PeriodAggregate` is populated by `sigcomply audit-ledger`, not the
single-run path. A single run cannot know its period history without
scanning the vault. The field is reserved on `PolicyResult` so the
ledger command can populate it later without a schema bump.

`PeriodAggregate` is omitted entirely for period-aligned cadences
(quarterly-in-quarterly): there is only one data point to display.

---

## Modes and state interaction

| Mode | Loads state? | Gates by cadence? | Advances state? |
|------|--------------|-------------------|-----------------|
| `ModeManual` (default) | No | No | Yes (per-policy after eval) |
| `ModePR` (`--pr`) | No | No (filtered to `on_push` only) | Yes |
| `ModeScheduled` (`--scheduled`) | Yes (unless filter explicit) | Yes (unless filter explicit) | Yes |

Manual and PR modes always evaluate every in-scope policy. Only
Scheduled mode applies cadence gating. All three modes advance the
per-policy state after evaluation — so a PR-triggered run that
passes a daily policy correctly sets `LastPassAt`, and the next
Scheduled run skips it as expected.

When `--scheduled` is combined with an explicit filter
(`--policies foo,bar`), the operator's intent wins: every matching
policy evaluates regardless of cadence state. State load is skipped
entirely in that case.

---

## Day-1 warnings

Three warnings are non-negotiable from V1 because they prevent the
most-regretted UX failures from being silently shipped:

### First-run

```
first-run: 47 policies will evaluate for the first time this run
first-run: configure a recurring CI schedule before depending on these results
```

Surfaces on the first run after a fresh install OR after a bundle
update that adds policies. Annual policies will pass on day 1 and
not re-evaluate for 364+ days — the warning prevents customers from
mistaking "all-green on day one" for "compliant."

### Gap-detected

```
gap-detected: 12 policies have no evaluation in the last 30d; today's
run does not backfill
```

Surfaces when CI was broken for an extended window. The CLI does NOT
fabricate retroactive evaluations — auditors will see the gap in the
period history, which is the correct posture (compare Airflow's
`catchup=false`).

### State-write-failed (warning-level in v1)

A `WritePolicyState` failure is logged at warning level. The next
run treats the un-advanced policy as still-due and re-evaluates —
over-run is safe; under-run is not. A future revision may upgrade
this to a hard error in CI mode.

---

## Cloud payload v2

The submission schema is `sigcomply.cloud.v2`. Five non-identifying
scalars per policy were added so the dashboard can render staleness
and next-due badges without recomputing locally:

- `ConfiguredCadence` (string)
- `LastEvaluatedAt` (RFC3339)
- `NextDueAt` (RFC3339)
- `IsCarriedForward` (bool)
- `PolicyContentHash` (string)

The aggregation boundary is preserved: every new field is a scalar,
not a map or interface. The structural counts-only test in
`core/cloud_test.go` enforces this — adding a freeform field fails
the build.

The Cloud-side staleness alarm fires when `NextDueAt < now - grace`.
The same query covers both per-policy staleness (one policy overdue)
and org-level absence (every policy stale because nothing has
submitted). One query, two surfaces — see the Rails app's
`Api::V1::RunsController`.

---

## What we explicitly do NOT do

The greenfield design is deliberately small. The following live in
the design space but are intentionally absent in v1:

| Item | Why not in v1 |
|------|---------------|
| Cron strings as the cadence DSL | Universally regretted at scale. Named cadences + `every:<duration>` cover 99% of catalog needs. |
| Drift detection between runs | Paid Rails feature, not free CLI. Keep the CLI snapshot-based. |
| Sub-5-minute cadences | API rate-limit cliff. Trapdoor for cost surprise. |
| Glob overrides (`soc2.cc6.*: weekly`) | YAGNI. First customer with ≥10 same-prefix overrides earns this feature. |
| `on_change_evaluate` (skip when evidence stable) | YAGNI. Cadence + on_fail_retry covers 99% of cases. |
| `pause_until: <date>` | YAGNI. We control the policy bundle and can remove policies; pause becomes useful only with customer-owned policy lifecycles. |
| Fiscal-calendar with non-January start (per-framework) | First customer with the need. |
| Calling cadence-gated checks "continuous monitoring" | SOC 2 wording trap — auditors flag the mismatch. Internal: "scheduled evaluation." |
| Sending anything more than the five new scalars to Cloud | Slippery slope into identifier leakage. The wire type stays counts-only. |

---

## See also

- `internal/core/policy_state.go` — the type
- `internal/orchestrator/state.go` — shard reads/writes + monotonic guard
- `internal/planner/cadence.go` — cadence parsing, NextDueAt, IsDue, DueReason
- `internal/planner/plan.go` — `PlannedPolicy.ShouldEvaluate`
- `internal/orchestrator/orchestrator.go` — `loadPolicyStates`, `advancePolicyStates`, `emitPlanWarnings`
- `internal/core/cloud.go` — `AggregatedPolicy` v2 fields
- `docs/architecture/06-aggregation.md` — Cloud schema versioning
- `docs/architecture/10-ci-execution-model.md` — pipeline ↔ mode mapping
