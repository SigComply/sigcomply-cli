# 06 — Aggregation Contract (the Privacy Boundary)

This document specifies the single most load-bearing component of the
non-custodial architecture: the contract that determines what crosses
from the customer's environment to the SigComply cloud (or any
self-hosted dashboard). Get this wrong and the entire product
positioning collapses.

The contract is enforced **structurally**, not procedurally. There is
no lint rule, no PR template, no documentation check that prevents
leakage. There is a Go type. Adding any field to that type that could
carry resource identity requires editing the type — a code-review
gate.

---

## The non-custodial promise

In SigComply's words: *"Evidence without access."* Operationally:

1. The customer's vault holds full-fidelity evidence: signed
   envelopes, raw API responses, PDF bytes, violation lists with
   resource identifiers.
2. The SigComply cloud (or any other dashboard the customer points
   the CLI at) holds *only counts, statuses, and metadata that the
   customer has already published* (commit SHA, repo name, branch).
3. No identifier (ARN, email, IAM user ID, file hash, resource name,
   account number) crosses the boundary.

The boundary is between L6 (Aggregator) and L8 (Submitter) in the
layer stack. L6 produces a `SubmissionPayload`; L8 transmits it.
Everything else in the system is on the customer's side.

---

## The submission payload

```go
// internal/core/cloud.go

package core

// SubmissionPayload is the wire format. Every field is concretely
// typed and represents either a count, an enum status, or
// already-public metadata. There is no map[string]any, no
// json.RawMessage, no string field that could carry an identifier.
//
// AUDIT NOTE: any change to this type must be reviewed by ≥ 2
// maintainers including the security owner. Adding a freeform field
// is a non-custodial regression and must be explicitly justified.
type SubmissionPayload struct {
    Schema      string         `json:"schema"`        // "sigcomply.cloud.v3"

    RunID       string         `json:"run_id"`        // UUID
    Framework   string         `json:"framework"`     // "soc2"
    PeriodID    string         `json:"period_id"`     // "2026-Q1"

    CommitSHA   string         `json:"commit_sha"`    // already public via git
    CommitTime  time.Time      `json:"commit_time"`
    Branch      string         `json:"branch"`        // already public via git

    Repository  Repository     `json:"repository"`    // already public
    Environment CIEnvironment  `json:"environment"`   // CI metadata only

    CLIVersion  string         `json:"cli_version"`
    StartedAt   time.Time      `json:"started_at"`
    CompletedAt time.Time      `json:"completed_at"`

    Summary     RunSummary     `json:"summary"`
    Policies    []PolicyResult `json:"policies"`
}

type Repository struct {
    Provider string `json:"provider"` // "github" | "gitlab" | "bitbucket" | "self_hosted"
    NameSlug string `json:"name_slug"` // e.g. "acme/infrastructure"
    URL      string `json:"url,omitempty"`
}

type CIEnvironment struct {
    Provider     string `json:"provider"`        // "github_actions" | "gitlab_ci" | "local"
    Workflow     string `json:"workflow,omitempty"`
    RunURL       string `json:"run_url,omitempty"`
    WorkerImage  string `json:"worker_image,omitempty"`
}

type RunSummary struct {
    PoliciesTotal          int     `json:"policies_total"`
    PoliciesPassed         int     `json:"policies_passed"`
    PoliciesFailed         int     `json:"policies_failed"`
    PoliciesSkipped        int     `json:"policies_skipped"`
    PoliciesError          int     `json:"policies_error"`
    PoliciesNA             int     `json:"policies_na"`
    PoliciesWaived         int     `json:"policies_waived"`
    PoliciesCarriedForward int     `json:"policies_carried_forward"`
    ComplianceScore        float64 `json:"compliance_score"`
}

// ComplianceScore = (PoliciesPassed + PoliciesWaived + PoliciesCarriedForward)
//                 / (PoliciesTotal - PoliciesSkipped - PoliciesNA)
// Carried-forward policies inherit a prior PASS (carry-forward never
// follows a non-pass terminal status), so they count toward the
// numerator; otherwise the steady state of sub-period cadences would
// systematically understate the score.

// AggregatedPolicy: per-policy. No identifiers permitted.
// (Named PolicyResult in earlier docs; the wire type is
// core.AggregatedPolicy.)
type AggregatedPolicy struct {
    PolicyID           string       `json:"policy_id"`         // "soc2.cc6.1.mfa_enforced"
    Controls           []ControlRef `json:"controls"`          // v3: one check ↦ many frameworks
    Status             PolicyStatus `json:"status"`            // pass|fail|skip|error|na|waived|carried_forward
    Severity           Severity     `json:"severity"`          // info|low|medium|high|critical
    Category           string       `json:"category,omitempty"`
    ResourcesEvaluated int          `json:"resources_evaluated"`
    ResourcesFailed    int          `json:"resources_failed"`
    Message            string       `json:"message"`           // generated from counts
    RuleVersion        string       `json:"rule_version,omitempty"`

    // Cadence fields (added in v2, retained in v3) — non-identifying
    // scalars for the cadence model. The dashboard uses these to render
    // staleness / next-due badges without recomputing locally. See
    // docs/architecture/10-cadence-model.md.
    ConfiguredCadence  string    `json:"configured_cadence,omitempty"`     // "daily" | "every:6h" | …
    LastEvaluatedAt    time.Time `json:"last_evaluated_at,omitempty"`      // most recent ACTUAL eval
    NextDueAt          time.Time `json:"next_due_at,omitempty"`            // when cadence next elapses
    IsCarriedForward   bool      `json:"is_carried_forward,omitempty"`
    PolicyContentHash  string    `json:"policy_content_hash,omitempty"`    // SHA-256(policy + schemas)
}

// ControlRef maps one policy to one control in one framework. A single
// policy commonly satisfies controls across SOC 2, ISO 27001, etc., so
// v3 carries a list. All four fields are public framework taxonomy —
// no customer identity. Earlier schemas (v1/v2) had a single scalar
// `control_id` instead; v2 clients still send it and the receiver
// synthesizes a one-element list (see Rails RunSubmissionService).
type ControlRef struct {
    Framework        string `json:"framework,omitempty"`         // "soc2" | "iso27001" | …
    FrameworkVersion string `json:"framework_version,omitempty"` // "soc2-2017@1.0.0"
    ControlID        string `json:"control_id"`                  // "SOC2.CC6.1"
    Relationship     string `json:"relationship,omitempty"`      // equal|subset_of|superset_of|intersects
}
```

The cadence fields are deliberately scalars — never maps, slices, or
interfaces — and `Controls` is a slice of a fixed, fully-typed struct
(no freeform keys). The reflection test in `internal/core/cloud_test.go`
walks the type graph and fails the build if a freeform-shape field
(`interface{}`, `json.RawMessage`, `map[string]any`) is added. Adding a
new field follows the same rules as adding any other (see §How to extend
the type below).

### What this type physically cannot express

- `Violations []Violation` — there is no such field. The full
  violation list lives only in the vault.
- `FailedResources []string` — there is no such field. The cloud sees
  the *count* of failed resources, never their IDs.
- `Details map[string]any` — there is no such field. No freeform
  extensibility hook.
- `EvidencePreview string` — there is no such field.
- `Diag json.RawMessage` — there is no such field.

If a maintainer believes a new field is needed, they must:

1. Argue the case in writing on the PR.
2. Demonstrate that the field cannot carry a resource identifier in
   any deployment.
3. Get review from ≥ 2 maintainers including the security owner.
4. Bump the schema version (current is `sigcomply.cloud.v3`; next would
   be `sigcomply.cloud.v4`) so existing deployments are aware of the
   change.

This is friction, by design. Every loosening of the contract erodes
the non-custodial promise.

---

## How L6 actually builds the payload

The real entry point is `aggregator.Build` — it takes the evaluated
`PolicyResult` slice plus a `*Environment`, and computes the run summary
internally (no `plan`/`summary` parameters are threaded in). The
following is illustrative pseudocode of its shape, not a line-for-line
transcription:

```go
// internal/aggregator/aggregator.go (illustrative)

func Build(results []core.PolicyResult, env *Environment) core.SubmissionPayload {

    out := core.SubmissionPayload{
        Schema:      SchemaVersion,        // "sigcomply.cloud.v3"
        RunID:       env.RunID,
        Framework:   env.Framework,
        PeriodID:    env.PeriodID,
        CommitSHA:   env.CommitSHA,
        CommitTime:  env.CommitTime,
        Branch:      env.Branch,
        Repository:  toRepository(env),
        Environment: toCIEnvironment(env),
        CLIVersion:  env.CLIVersion,
        StartedAt:   env.StartedAt,
        CompletedAt: time.Now(),
        Summary:     buildSummary(results),  // counts computed here
        Policies:    make([]core.AggregatedPolicy, 0, len(results)),
    }

    for _, r := range results {
        out.Policies = append(out.Policies, core.AggregatedPolicy{
            PolicyID:           r.PolicyID,
            Controls:           r.Controls,  // []ControlRef — multi-framework mapping
            Status:             r.Status,    // PolicyStatus
            Severity:           r.Severity,  // Severity
            Category:           r.Category,
            ResourcesEvaluated: r.ResourcesEvaluated,
            ResourcesFailed:    r.ResourcesFailed,
            Message:            generateMessage(r),  // <-- key step
            RuleVersion:        r.RuleVersion,

            // The five non-identifying cadence scalars (see
            // 10-cadence-model.md §Cloud payload cadence fields).
            ConfiguredCadence: r.ConfiguredCadence,
            LastEvaluatedAt:   lastEvaluatedAt(r, env),
            NextDueAt:         r.NextDueAt,
            IsCarriedForward:  r.Status == core.StatusCarriedForward,
            PolicyContentHash: r.PolicyContentHash,
        })
    }

    return out
}

// generateMessage produces a count-only summary from a PolicyResult.
// It never copies the violation text, which may contain identities.
func generateMessage(r core.PolicyResult) string {
    switch r.Status {
    case core.StatusPass:
        return fmt.Sprintf("All %d resources passed.", r.ResourcesEvaluated)
    case core.StatusFail:
        return fmt.Sprintf("%d of %d resources failed.", r.ResourcesFailed, r.ResourcesEvaluated)
    case core.StatusSkip:
        return "No matching resources to evaluate."
    case core.StatusError:
        return "Evaluation error; see customer vault for diagnostics."
    case core.StatusNA:
        return "Not applicable to this project."
    case core.StatusWaived:
        return fmt.Sprintf("Waived by exception (%d of %d resources affected).",
            r.ResourcesFailed, r.ResourcesEvaluated)
    case core.StatusCarriedForward:
        return "Carried forward from a prior passing evaluation (cadence not yet due)."
    }
    return ""
}
```

The critical design choice: `Message` is **regenerated** from counts.
The rule's violation text (which may say "MFA disabled for
alice@acme.com") is *never* propagated to the cloud payload.

---

## Wire format

The payload is transmitted as JSON over HTTPS to the configured cloud
base URL. The default is `https://api.sigcomply.com`; self-hosted
deployments override via `cloud.base_url` in project config or the
`SIGCOMPLY_CLOUD_URL` env var.

```
POST {cloud_base_url}/api/v1/runs
Content-Type: application/json
Authorization: Bearer <oidc_jwt>
X-OIDC-Provider: github | gitlab
X-Sigcomply-CLI-Version: 1.0.0

{ /* SubmissionPayload */ }
```

### Authentication

OIDC only. No API keys, no secrets stored, no long-lived credentials.

- In GitHub Actions: the CLI fetches a workload-identity token from
  `ACTIONS_ID_TOKEN_REQUEST_URL` with audience
  `https://api.sigcomply.com` (or the configured base URL).
- In GitLab CI: the CLI reads the JWT from `ID_TOKEN` (configured in
  the pipeline) with the same audience.
- Locally: no OIDC token available → cloud submission silently
  skipped. The vault still receives all evidence.

The receiving Rails app validates:

- Token signature against the CI provider's public JWKS.
- Audience matches the configured cloud URL.
- Subject claim (`repository`, `namespace_path`, `project_path`)
  matches a customer's registered repository.

If validation fails, the cloud returns 401 and the CLI logs but does
not block the run.

### Response

```json
{
  "accepted": true,
  "run_id":   "a3f8b2c1-...",
  "received_at": "2026-02-15T14:01:43Z",
  "dashboard_url": "https://app.sigcomply.com/runs/a3f8b2c1"
}
```

The CLI prints `dashboard_url` for the operator's convenience.

---

## Submission lifecycle

| Step | Layer | Action |
|---|---|---|
| 1 | L6 | Build `SubmissionPayload` from `PolicyResult[]`. |
| 2 | L9 | Decide whether to submit (see §Decision matrix). |
| 3 | L8 | Acquire OIDC token from CI provider (if available). |
| 4 | L8 | POST payload. |
| 5 | L8 | Log response, return success/failure to L9. |
| 6 | L9 | Print summary to operator; exit code reflects evaluation, not submission. |

### Decision matrix

| Flag | CI? | OIDC? | Cloud URL set? | Submit? |
|---|---|---|---|---|
| `--no-cloud` | any | any | any | **No** |
| `--cloud` | any | yes | yes | **Yes** |
| `--cloud` | any | no | yes | **Error** (exit 2 with explanation) |
| (default) | yes | yes | yes | **Yes** (auto) |
| (default) | yes | no | yes | **No** (silently) |
| (default) | no | n/a | any | **No** |

A run that does not submit is not a failure. The vault is the
permanent record; submission is for the optional dashboard view.

### Failure handling

| Failure | CLI response |
|---|---|
| Network error | Retry once after backoff; if still failing, log and continue. Exit code unaffected. |
| 401/403 | Log explanation; continue. Exit code unaffected. |
| 4xx (validation) | Log payload, log response, continue. Exit code unaffected. The vault has the same data. |
| 5xx | Retry up to 3 times with exponential backoff; if still failing, log and continue. |

The principle: a cloud outage must never block a customer's CI
pipeline. The customer has their own evidence in their own vault; the
cloud is a convenience layer.

---

## What the paid Rails app does with the submitted data

The SigComply CLI is open source and free. The SigComply Cloud /
Rails app is a separate, **paid** product. The two are intentionally
decoupled: the CLI works fully without the cloud (the vault is
self-sufficient), and the cloud provides analytical value on top of
the per-run submissions it receives.

### What the Rails app stores

Every `SubmissionPayload` the cloud receives is persisted in the
Rails app's database. The schema mirrors the wire format described
above — counts, statuses, controls, severities, run identity,
environment metadata — and nothing else. No raw evidence, no resource
identifiers, no violation lists, no envelopes, no PDFs. The privacy
boundary is structural; the Rails app cannot store what the CLI
cannot send.

Submissions accumulate over time. After many runs across many
periods, the Rails DB holds a longitudinal record of every aggregated
policy outcome the project has produced.

### What the Rails app does with that data (paid features)

The free CLI handles per-run evaluation and snapshot views. The paid
Rails app adds the **longitudinal analytical layer**:

| Feature | Description |
|---|---|
| **Deviation timeline** | For each policy in each period: the sequence of pass/fail windows and time-in-violation. Required to substantiate SOC 2 Type II "operated effectively *throughout* the period" claims. |
| **Drift detection** | Cross-period comparison ("Q1 2026 vs Q1 2025"); flagging of newly failing policies, newly waived policies, and trend lines for compliance score. |
| **Continuous monitoring alerts** | Real-time notifications (email, Slack, webhook) when a previously-passing policy transitions to fail, or when an exception is about to expire, or when a scheduled workflow has missed its expected run. |
| **Auditor-ready reports** | Composite Type II reports combining latest state, deviation timelines, exception register, and run-level evidence pointers into one paginated deliverable. |
| **Multi-project rollup** | An organization with multiple repos (e.g. SOC 2 + ISO 27001 in separate projects) sees a unified compliance posture in one dashboard. |
| **Auditor seats** | Read-only access for external auditors with scoped permissions to specific periods. |

These are the paid product's value-add. They are not duplicated in
the free CLI. The data the Rails app needs lives in two places: the
aggregated per-run submissions the cloud receives (counts, statuses,
metadata — what powers all of the above), and the customer's vault
(raw evidence — only consulted when an auditor drills down to specific
envelopes, via signed read-only links the Rails app can generate).

The Rails app **never** stores raw evidence in its own database. When
deeper detail is needed (an auditor opens a specific failing policy
to see the violation list), the dashboard renders the per-policy
`result.json` directly from the customer's vault — the customer's
infrastructure is the source of truth, the cloud is the index and
analytics layer.

### Privacy boundary, restated for the paid context

Even with the paid product, the customer's data sovereignty does not
weaken:

- Resource identifiers stay in the customer's vault.
- Raw evidence stays in the customer's vault.
- PDF attachments stay in the customer's vault.
- The Rails DB contains only what the `SubmissionPayload` carries —
  counts, statuses, policy IDs, control IDs, severities, and metadata
  that's already public (commit SHA, repo name, branch).
- The Rails app's deviation timelines, drift analyses, and reports
  operate **on aggregated counts over time**, not on identities.

A breach of the SigComply Cloud / Rails DB would expose: a customer's
compliance score history and which policy IDs have been failing.
Never: who is failing, what their email is, what their AWS account
ID is, what their evidence PDFs say.

---

## Self-hosted dashboards

The `CloudClient` interface (L1) abstracts the transport. The shipped
implementation talks to SigComply Cloud; a customer running a
self-hosted Rails app (if offered) or an alternative dashboard can
configure:

```yaml
# .sigcomply.yaml
cloud:
  base_url: "https://compliance.acme-internal.com"
  client:   "default"             # uses the same OIDC + payload shape
```

Self-hosted backends are responsible for their own auth scheme; if
they don't validate OIDC, the CLI still sends the token (let the
receiver decide). Self-hosted backends MUST honor the same
`SubmissionPayload` schema — the contract is identical regardless of
who receives it.

Customers who don't want any dashboard at all (free CLI only, no
cloud submissions) simply omit `cloud.base_url`. The vault remains
fully self-sufficient for snapshot reporting and integrity
verification; only the longitudinal analytics layer (drift,
deviations, alerts) is unavailable without a Rails-app-equivalent
consumer of the submissions.

---

## Auditing the boundary

Two checks any reviewer (internal or external) should be able to
perform.

### 1. Static check: type inspection

Read `internal/core/cloud.go`. Verify:

- No `interface{}` or `any` types in `SubmissionPayload` (transitively).
- No `json.RawMessage` types.
- No `map[string]X` types unless `X` is a primitive (int, float, bool,
  string-enum, time.Time).
- No `[]X` where `X` could carry identity (e.g. `[]string` named
  "failed_resources" is forbidden; `[]string` named "categories" is
  OK because category names are policy metadata, not identities).

A unit test enforces this with `go/types` reflection on the package:

```go
// internal/core/cloud_test.go
func TestSubmissionPayload_StructurallyCountsOnly(t *testing.T) {
    walkType(t, reflect.TypeOf(SubmissionPayload{}), "SubmissionPayload")
}
```

### 2. Dynamic check: payload capture

Run any check with `--capture-cloud-payload /tmp/payload.json`:

```bash
sigcomply check --capture-cloud-payload /tmp/payload.json
```

This dumps the exact bytes that would be sent to the cloud, without
sending them. A reviewer or auditor can:

- Diff `payload.json` against the vault's `summary.json`. The
  difference should be: violations are omitted, message is regenerated.
- Grep for known customer identifiers (employee emails, ARNs). Should
  return zero matches.

The `--capture-cloud-payload` flag is permanent; it's the auditor's
escape hatch for verifying the boundary on demand.

---

## Things that DO cross the boundary, justified

| Field | Why it's OK |
|---|---|
| `policy_id`, `controls[]` (`framework`, `framework_version`, `control_id`, `relationship`) | Public framework taxonomy; identical across all customers. |
| `status`, `severity` | Enum; carries no identity. |
| `category` | Policy metadata, not customer data. |
| `resources_evaluated`, `resources_failed` | Counts, by definition non-identifying. |
| `message` (generated) | Regenerated from counts; never copied from rule output. |
| `commit_sha`, `commit_time`, `branch` | Already published to git; the cloud knowing them is the same as the cloud's host knowing them. |
| `repository.name_slug` | Already public in the repo URL. |
| `cli_version`, `framework`, `framework_version` | CLI/framework metadata, no customer specifics. |
| `period_id` | Date label; non-identifying. |
| OIDC subject claims (during auth, not in payload) | Standardized; the cloud sees them only to authenticate. |

### Things that do *not* cross

| Field | Stays in |
|---|---|
| Violation lists (resource_id, reason text) | Vault `result.json` only |
| Evidence record payloads (emails, ARNs, etc.) | Vault envelopes only |
| Source plugin diagnostics | Vault `diagnostics.json` only |
| Manual PDF bytes | Vault `attachments/` only |
| File hashes (`sha256` of PDFs) | Vault envelopes only |
| Effective parameter values | Vault `manifest.json` only |
| Envelope signatures and public keys | Vault envelopes only |
| Exceptions detail (resource scopes, approver names) | Vault `manifest.json` only |
| `RecordScope` / `Scope` (per-record scope on a `PolicyResult`) | Vault only — deliberately never lifted onto the wire type |

A field on the "stays in" side that ever drifts to the "crosses"
side is a privacy regression. The structural enforcement (type system)
makes that drift visible.

---

## Versioning the contract

`Schema: "sigcomply.cloud.v3"` is stamped into every payload (the
constant `aggregator.SchemaVersion`). The receiver (cloud or self-hosted
dashboard) keys behavior off it. v3 replaced the per-policy scalar
`control_id` with a `controls []ControlRef` list so one check can map to
controls across many frameworks; the cadence scalars added in v2 are
unchanged.

Breaking changes (renames, semantic shifts in existing fields) bump the
version. The CLI emits one version per release; the receiver typically
accepts a range. Coexistence rules:

- The Rails receiver is **shape-driven, not version-gated**: it stores
  the `schema` string verbatim and accepts `v1`/`v2`/`v3` payloads
  simultaneously. A policy carrying a non-empty `controls[]` is treated
  as v3; one carrying only a scalar `control_id` is read as v2 and
  synthesized into a single-element `controls` list. See the Rails app's
  `Cli::RunSubmissionService#normalize_controls`.
- An old CLI (v2) talking to a new cloud sends a scalar `control_id`; the
  receiver up-converts it to a one-element list.
- A new CLI (v3) talking to an old cloud that predates the `controls`
  field would have that field dropped by strong-params; deploy the Rails
  side first.

The transition cost of bumping is intentional. The privacy boundary
is not a place for casual evolution.
