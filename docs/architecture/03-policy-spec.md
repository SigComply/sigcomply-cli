# 03 — Policy Spec

A policy declares: what it asserts, what evidence shapes it needs, which
parameters can be tuned, and which rule implements its logic. Policies
are framework-shipped (curated, in-binary) or project-local (custom,
under `.sigcomply/policies/`). The spec format is identical for both.

This document specifies the spec, the slot and parameter models, and
the three rule implementation flavors.

---

## File layout

A single policy is one directory containing the spec and its rule
implementation:

```
soc2/policies/cc6.1.mfa_enforced/
   policy.yaml                       # the spec
   rule.rego          (one of)       # Rego implementation
   rule.go            (or)           # Go implementation
   rule.dsl.yaml      (or)           # YAML DSL implementation
   tests/                            # rule unit tests
      passes_when_all_mfa_on.yaml
      fails_when_any_mfa_off.yaml
   README.md                         # human-facing description
```

Exactly one rule file must exist per policy. The spec's `rule:` field
names the rule reference (`rules.mfa_enforced.v1`); the registry
resolves it to whichever rule file is present.

---

## The spec — `policy.yaml`

```yaml
schema_version: policy.v1

id: soc2.cc6.1.mfa_enforced

control: SOC2.CC6.1
severity: high               # info | low | medium | high | critical
category: access_control

cadence: daily               # continuous | hourly | daily | weekly | monthly | quarterly | annual
on_push: true                # run on every PR/push for fast feedback

description: |
  All users in the configured user directory must have multi-factor
  authentication enabled.

remediation: |
  For affected users, enable MFA via the relevant identity provider:
    - AWS IAM: aws iam enable-mfa-device ...
    - Okta:    require MFA factor enrollment in the user's group
  Re-run the check after remediation.

slots:
  user_directory:
    type: user_record
    cardinality: one-or-more
    required: true
    description: "Source(s) of users to evaluate for MFA."

parameters:
  exempt_service_accounts:
    type: bool
    default: true
    description: |
      If true, records where payload.is_service_account == true are
      skipped. Use false to require MFA on machine identities as well.

rule: rules.mfa_enforced.v1

tags:
  - aws-soc2
  - identity
```

### Field reference

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | Always `policy.v1` for v1 of the spec format. |
| `id` | yes | Globally unique policy ID. Must match the directory name's last segment. Convention: `<framework>.<control_lowercase>.<short_name>`. |
| `control` | yes | The control this policy contributes to. Must exist in the framework's control catalog. |
| `severity` | yes | Display severity. The rule cannot override this; if a single policy needs variable severity, split into multiple policies. |
| `category` | no | Free-form grouping label (e.g. `access_control`, `encryption`, `monitoring`). Used in summaries. |
| `cadence` | yes | How often the policy must be evaluated. One of `continuous`, `hourly`, `daily`, `weekly`, `monthly`, `quarterly`, `annual`. Drives CI workflow scheduling; the CLI itself does not enforce it. |
| `on_push` | no | Whether this policy is suitable for fast PR/push feedback. Defaults to `true` for automated rules, `false` for manual rules. CI workflows for on-push gates filter by this tag. |
| `description` | yes | Plain-English statement of what the policy asserts. |
| `remediation` | no | Plain-English remediation guidance, displayed alongside failures. |
| `slots` | yes (≥1) | Named typed inputs. See §Slots below. |
| `parameters` | no | Tunable per-project values. See §Parameters below. |
| `rule` | yes | Rule reference (must resolve in `RuleRegistry`). |
| `tags` | no | Free-form labels for filtering and reporting. |

---

## Slots

A slot is a named, typed input on a policy. It is the interface between
the policy and the source plugins that fulfill it.

### Cardinality

| Value | Meaning | Project may bind |
|---|---|---|
| `exactly-one` | Slot must be fulfilled by exactly one source. | 1 source |
| `at-most-one` | Slot may be fulfilled by zero or one source. | 0 or 1 source |
| `one-or-more` | Slot must be fulfilled by at least one source. | 1+ sources |
| `optional` | Slot may be fulfilled by zero or more sources. | 0+ sources |

If `required: true` and the slot has no records at run time, the policy
result is `skip` with diagnostic `"no records for required slot
<name>"`.

If `required: false` and the slot has no records, the rule sees an
empty `input.slots.<name>` array; it is the rule's responsibility to
handle the absence.

### Type matching

A slot's `type` field names an evidence type ID registered in
`EvidenceTypeRegistry`. The planner verifies that every source bound
to this slot declares the same type in its `emits` list. Mismatches
fail at plan time with exit code 3.

### Multiple bound sources

When `cardinality: one-or-more` or `optional` allows multiple sources,
the rule receives the **union** of all bound sources' records under
`input.slots.<slot_name>`. The records remain tagged with their
`SourceID`, so a rule that wants to know the origin (rarely needed)
can inspect it. Most rules ignore `SourceID` and treat the union as a
flat set.

### Cross-source dedup (read this if your slot has cardinality `one-or-more`)

The union is a **bag**, not a set. If Alice has an account in both AWS
IAM and Okta and a project's `user_directory` slot binds to
`[aws.iam, okta]`, Alice's two records arrive as two entries. A naive
rule that iterates and counts produces `resources_evaluated: <total>`
that double-counts every human with accounts in multiple sources.

This matters because the count crosses the privacy boundary as the
customer's compliance score input. A 47-record union of 30 AWS + 17
Okta where 5 humans appear in both should report 42 unique humans
evaluated, not 47.

**The dedup mechanism** is `identity_key`. Source plugins may set
`identity_key` on an `EvidenceRecord` to a stable cross-source
identifier — typically email, employee_id, or another value that
represents the same real-world entity across systems:

```go
// Inside aws.iam.Collect(...)
records = append(records, evidence.Record{
    Type:        "user_record",
    ID:          "AIDAEXAMPLE01",        // AWS-local ARN
    IdentityKey: "alice@acme.com",        // cross-source
    Payload:     payload,
    SourceID:    "aws.iam",
})

// Inside okta.Collect(...)
records = append(records, evidence.Record{
    Type:        "user_record",
    ID:          "okta-user-99",          // Okta-local ID
    IdentityKey: "alice@acme.com",        // same key — dedup possible
    Payload:     payload,
    SourceID:    "okta",
})
```

When a rule processes records with `IdentityKey` set, it should
**dedupe by identity_key first** before counting. The framework's Go
rule helpers expose `rule.DedupeByIdentity(records []Record) []Record`
which returns one record per identity_key (first-seen wins; rules
needing different semantics — e.g., "merge fields from both records"
— must implement that themselves).

Rego rules apply the same pattern via a `dedupe_by_identity` helper in
`data.sigcomply.lib`:

```rego
package rules.mfa_enforced.v1

import data.sigcomply.lib.dedupe_by_identity

violation contains v if {
    unique_users := dedupe_by_identity(input.slots.user_directory)
    record := unique_users[_]
    not record.payload.mfa_enabled
    v := {"resource_id": record.id, "reason": ...}
}
```

YAML DSL rules dedupe automatically when the evidence type schema
declares `identity_key` as a known field — the transpiler emits the
dedupe step.

**When `identity_key` is not set**, no dedup happens. This is correct
for evidence types where there is no cross-source identity (e.g.,
`firewall_rule` — a rule in AWS is not the same rule as a rule in
GCP). Plugin authors should set `identity_key` only when it
genuinely represents a shared real-world entity across sources.

**Effect on counts**: when dedup occurs, `resources_evaluated` and
`resources_failed` in the `PolicyResult` reflect the deduplicated
count. The vault's full violation list may still include all records
(for forensic visibility into which source reported which failure);
the cloud submission carries the deduplicated count only.

Shipped rules that consume types where `identity_key` is meaningful
(`user_record`, etc.) dedupe by default. Custom rule authors must
explicitly choose: dedupe (set-of-entities semantics) or no-dedupe
(bag-of-records semantics).

---

## Parameters

Parameters let projects tune policy behavior without forking. Each
parameter has a type, a default, and optional bounds.

```yaml
parameters:
  max_age_days:
    type: int
    default: 90
    min: 1
    max: 365
    description: "Maximum credential age in days before rotation is required."

  approved_kms_keys:
    type: list_of_string
    default: []
    description: "KMS key ARNs that are approved for encryption."

  enforce_in_grace_period:
    type: bool
    default: false
```

### Supported types

| Type | Project value form | Notes |
|---|---|---|
| `bool` | `true` / `false` | |
| `int` | integer | Optional `min` / `max` |
| `float` | number | Optional `min` / `max` |
| `string` | string | Optional `enum: [...]` or `pattern: <regex>` |
| `duration` | `"30d"`, `"24h"`, `"15m"` | Parsed via Go `time.ParseDuration` extended for days |
| `date` | `"2026-01-15"` | ISO 8601 date |
| `list_of_string` | `["a", "b"]` | Optional `item_pattern: <regex>` |
| `list_of_int` | `[1, 2, 3]` | |

### Effective values

The planner computes effective values as:

```
effective = policy.parameters.<name>.default
          ⊕ project_config.policy_parameters[policy_id].<name>
```

Validation runs against `min/max/enum/pattern`. Out-of-bounds values
cause a planning error (exit 3). The effective values are stamped into
the run's `manifest.json` so auditors see the exact thresholds used.

### Rule input

The rule receives `input.params.<name>` for every declared parameter,
always populated (default if not overridden).

---

## Rule references

The `rule:` field is a string in dotted-with-version notation:

```
rules.<name>.v<n>
```

Examples:

- `rules.mfa_enforced.v1`
- `rules.access_key_rotation.v2`
- `rules.encryption_at_rest.v1`

The `RuleRegistry` resolves a reference to a `Rule` interface
implementation regardless of which language the rule is authored in.

**Versioning.** Bumping a rule's logic in a breaking way (changing the
meaning of pass/fail) requires a new version (`.v2`). Existing
policies pin to the older version until intentionally migrated. The
rule version is stamped into every `PolicyResult` so old runs in the
vault remain interpretable.

---

## Cadence and on-push tagging

`cadence` and `on_push` together describe **when** a policy should be
evaluated. Both live on the policy spec. Neither is enforced by the
CLI — they are the contract between the framework author and the CI
workflow files that schedule runs.

### Why cadence matters

A SOC 2 program does not benefit from re-checking every quarterly
access review on every commit, and a public-bucket drift check does
not want to wait a day to fire. Different policies need different
schedules. By tagging each policy with a cadence, the framework author
expresses what's reasonable; the CI scheduler turns that into actual
cron entries.

The flow:

```
policy.yaml declares cadence ──→ project .sigcomply.yaml may override
                              ──→ CI workflow files filter on cadence
                              ──→ scheduled workflow invokes
                                  `sigcomply check --cadence <value>`
                              ──→ CLI runs every policy whose effective
                                  cadence matches the flag
```

### The seven cadence values

| Cadence | Typical policy examples |
|---|---|
| `continuous` | Branch protection on the default branch, encryption-at-rest defaults, IaC drift checks that read static config. |
| `hourly` | Public S3 buckets, root-account MFA, IMDSv1 detection — high-blast-radius drift. |
| `daily` | Most automated SOC 2 / ISO 27001 checks: IAM password policy, CloudTrail enabled, RDS encryption, GitHub default-branch protection. |
| `weekly` | Inactive-user reviews, access-key rotation reminders, dependency vulnerability summaries. |
| `monthly` | Backup verification, log retention sweep, vulnerability scan summary. |
| `quarterly` | Manual access reviews, risk acceptance declarations, signed acknowledgments — almost all manual evidence. |
| `annual` | Annual policy acknowledgment, security awareness training completion, business continuity test results. |

### The `on_push` tag

`on_push` is orthogonal to `cadence`. It answers a different question:
"Is this policy fast enough and stable enough to gate every PR on?"

- `on_push: true` (default for automated policies) — the policy fetches
  quickly, fails deterministically, and produces a result that a PR
  author can act on. The on-push CI workflow runs all policies with
  this tag, regardless of their cadence.
- `on_push: false` (default for manual policies) — the policy either
  takes too long, depends on out-of-band evidence (a PDF the human
  hasn't uploaded yet), or doesn't have an actionable failure mode at
  PR time. The on-push workflow skips it.

A manual quarterly access review has `cadence: quarterly, on_push:
false`: the quarterly workflow checks for the PDF's presence; the
on-push workflow ignores it entirely. A daily IAM MFA check has
`cadence: daily, on_push: true`: the daily workflow runs the full
sweep, and PRs touching IAM also get the policy as fast feedback.

### Cadence is metadata, not enforcement

The CLI does not refuse to run a quarterly policy on demand. If a
human types `sigcomply check --policies soc2.cc1.1.board_review`
directly, the policy runs — its `cadence: quarterly` is documentation
of the recommended schedule, not a lock. This preserves Axiom 4 (CI is
the orchestrator, not the CLI) and matches how the rest of the CLI's
filtering flags behave: the CLI is a deterministic function of its
inputs, never a stateful gatekeeper.

The CLI **does** filter by cadence when asked: `--cadence daily`
selects every policy whose effective cadence is `daily`. Effective
cadence = `project_config.policy_cadences[id]` if set, else
`policy.cadence`.

### Project override pattern

A project can override a shipped policy's cadence in its
`.sigcomply.yaml`:

```yaml
policy_cadences:
  soc2.cc6.1.mfa_enforced: hourly       # tighten — we care about drift
  soc2.cc6.6.public_access_blocked: continuous
  soc2.cc1.2.code_of_conduct_attested: annual   # loosen — we attest yearly
```

The full reference (precedence, validation, interaction with `--policies`
filtering) lives in [`08-project-config.md`](08-project-config.md).

### A manual policy's cadence in practice

```yaml
schema_version: policy.v1

id: soc2.cc1.4.quarterly_access_review
control: SOC2.CC1.4
severity: medium
category: governance

cadence: quarterly
on_push: false

description: |
  An access review of all privileged users must be completed and
  signed off each quarter. The reviewer uploads the signed review
  document to the manual-evidence vault.

slots:
  access_review_document:
    type: signed_document
    cardinality: exactly-one
    required: true

parameters:
  grace_period_days:
    type: int
    default: 30

rule: rules.manual_presence_in_period.v1
```

The quarterly CI workflow (`.github/workflows/sigcomply-quarterly.yml`)
runs `sigcomply check --cadence quarterly` once per quarter on the
calendar boundary plus grace. The on-push workflow never sees this
policy because `on_push: false`. The CLI itself, given
`--policies soc2.cc1.4.quarterly_access_review`, will still evaluate
it on demand — the cadence value is guidance for the scheduler, not a
runtime gate.

---

## Rule implementations

The same policy logic can be authored in any of three flavors. All
three implement the same `Rule` Go interface.

### Flavor 1 — Rego (default for framework-shipped policies)

```rego
# rule.rego
package rules.mfa_enforced.v1

# input shape (provided by the evaluator):
# {
#   "policy_id": "soc2.cc6.1.mfa_enforced",
#   "slots": {
#     "user_directory": [
#       { "type": "user_record", "id": "...", "source_id": "...",
#         "collected_at": "...", "payload": {...} },
#       ...
#     ]
#   },
#   "params": { "exempt_service_accounts": true },
#   "now":    "2026-05-23T14:00:00Z"
# }

violation contains v if {
    record := input.slots.user_directory[_]

    # respect exemption parameter
    not (input.params.exempt_service_accounts == true
         and record.payload.is_service_account == true)

    not record.payload.mfa_enabled

    v := {
        "resource_id": record.id,
        "reason": sprintf("MFA disabled for %s", [record.payload.email]),
    }
}

# status defaults to pass; the evaluator computes:
#   fail if violation set non-empty
#   pass otherwise
```

**Strengths.** Declarative, side-effect-free, sandboxed at runtime.
Auditors can read the rule without understanding Go.

**Conventions for shipped rules:**

- Package name matches the rule reference: `package rules.<name>.v<n>`
- Single rule per file
- Rules emit `violation` and optionally `diag` (a free-form
  diagnostics map)
- No imports beyond `data.<framework>.lib.*` shared helpers

### Flavor 2 — Go (for rules where Rego is awkward)

```go
// rule.go
package mfa_enforced_v1

import (
    "context"
    "fmt"

    "github.com/sigcomply/sigcomply-cli/internal/core/rule"
)

type Rule struct{}

func (Rule) ID() string { return "rules.mfa_enforced.v1" }

func (Rule) Evaluate(ctx context.Context, in rule.Input) (rule.Result, error) {
    exemptServiceAccounts := in.ParamBool("exempt_service_accounts", true)
    var violations []rule.Violation
    var evaluated int

    for _, rec := range in.Records("user_directory") {
        if exemptServiceAccounts && rec.PayloadBool("is_service_account") {
            continue
        }
        evaluated++
        if !rec.PayloadBool("mfa_enabled") {
            violations = append(violations, rule.Violation{
                ResourceID: rec.ID,
                Reason:     fmt.Sprintf("MFA disabled for %s", rec.PayloadString("email")),
            })
        }
    }

    return rule.Result{
        Status:             rule.StatusFromViolations(violations),
        Violations:         violations,
        ResourcesEvaluated: evaluated,
    }, nil
}

// init registers the rule with the global registry on import.
func init() { rule.Register(Rule{}) }
```

**Strengths.** Full Go expressiveness. Easier to express joins, time
math, complex aggregations. Easier to unit-test with Go's testing
package.

**Conventions for shipped rules:**

- Package name `<rule_name>_v<n>` (Go-friendly identifier)
- Implements the `rule.Rule` interface
- `init()` registers the rule
- Must be deterministic, must not perform I/O
- Reviewed at PR time for side-effect-freedom

### Flavor 3 — YAML DSL (for the common "for each X assert Y" case)

```yaml
# rule.dsl.yaml
schema_version: rule_dsl.v1
id: rules.mfa_enforced.v1

for_each:
  slot: user_directory
  bind: record
  where:
    - condition: "not (params.exempt_service_accounts and record.payload.is_service_account)"

assert:
  - condition: "record.payload.mfa_enabled == true"
    on_fail:
      reason: "MFA disabled for {{record.payload.email}}"
      resource_id: "{{record.id}}"
```

**Strengths.** Very readable. Non-programmers can write and review.
The CLI transpiles to Rego at build time; the compiled rule registers
the same way as a hand-written Rego rule.

**Constraints.** Only handles patterns expressible as
`for_each → where filter → assert condition → on_fail`. Anything more
complex (multi-slot joins, time math, aggregations across records)
must drop to Rego or Go.

---

## Testing rules

Every policy directory carries a `tests/` subdirectory with YAML
test cases. Each test specifies inputs and expected outputs:

```yaml
# tests/passes_when_all_mfa_on.yaml
name: passes when all users have MFA on
inputs:
  slots:
    user_directory:
      - id: alice
        payload: { email: alice@acme.com, mfa_enabled: true,  is_service_account: false }
      - id: bob
        payload: { email: bob@acme.com,   mfa_enabled: true,  is_service_account: false }
  params:
    exempt_service_accounts: true
  now: "2026-05-23T14:00:00Z"
expected:
  status: pass
  violations: []
```

```yaml
# tests/fails_when_any_mfa_off.yaml
name: fails when any non-service-account user lacks MFA
inputs:
  slots:
    user_directory:
      - id: alice
        payload: { email: alice@acme.com, mfa_enabled: false, is_service_account: false }
      - id: bob
        payload: { email: bob@acme.com,   mfa_enabled: true,  is_service_account: false }
      - id: deploy_bot
        payload: { email: deploy-bot@acme.com, mfa_enabled: false, is_service_account: true }
  params:
    exempt_service_accounts: true
expected:
  status: fail
  violations:
    - resource_id: alice
      reason: "MFA disabled for alice@acme.com"
```

A repo-wide test runner (`sigcomply test policies`) loads every
policy's tests and runs them against the registered rule, regardless
of language flavor.

---

## Policy versioning and lifecycle

- Policies are versionless from the project's perspective: there is one
  current spec per policy ID.
- Substantive logic changes happen in the *rule*, which is versioned.
  When a rule's `.v2` ships, the policy spec is updated to point at it.
  Old runs in the vault retain `rule_version: rules.X.v1` in their
  result.json, so prior results stay interpretable.
- Policies can be deprecated by marking `status: deprecated` (a
  forthcoming optional field). Deprecated policies still run; the
  output formatter surfaces a warning.
- A policy can be removed entirely from a framework only at a major
  framework version bump.

---

## Project-local custom policies

A customer can author policies under
`.sigcomply/policies/<id>/policy.yaml` using the identical schema. The
loader merges them into the registry alongside framework-shipped
policies. Conventions for custom policy IDs:

- Use a customer-specific prefix: `acme.custom.cc6.1.contractor_review`
- Reference framework controls if applicable (`control: SOC2.CC6.1`)
- Rules can reference framework-shipped rules (`rule: rules.mfa_enforced.v1`)
  if the slots align — encouraged when the same logic applies with
  different bindings.

Custom policies declare `cadence` and `on_push` the same way
framework-shipped policies do. If either field is omitted, the loader
applies defaults based on the rule's evidence shape:

- Automated rule (all slot types are structured records) → `cadence:
  daily`, `on_push: true`.
- Manual rule (any slot type is `signed_document` or similar) → `cadence:
  quarterly`, `on_push: false`.

Explicitly setting the fields is encouraged — defaults exist to keep
small custom policies low-friction, not to hide scheduling decisions.

Custom policies appear in run output and submission payloads just like
framework-shipped policies. They do not affect framework version pins.

See [`07-extensibility.md`](07-extensibility.md) for the full
extension workflow.
