package core

import (
	"context"
	"time"
)

// CloudClient transmits SubmissionPayload to a configured dashboard
// endpoint (SigComply Cloud or a self-hosted backend). It is the only
// consumer of SubmissionPayload outside the aggregator.
type CloudClient interface {
	Submit(ctx context.Context, payload SubmissionPayload) error
}

// SubmissionPayload is the wire format crossing the aggregation
// boundary from the customer environment to the cloud. Every field is
// concretely typed and represents either a count, an enum status, or
// already-public metadata.
//
// SECURITY: This type is the structural privacy guarantee of the
// non-custodial architecture. Adding any field that could carry
// resource identity (ARNs, emails, IDs, file hashes, hostnames) is a
// non-custodial regression. Required for any such change:
//  1. Written justification on the PR.
//  2. Demonstration that the field cannot carry identity in any
//     deployment.
//  3. Review by >=2 maintainers including the security owner.
//  4. Schema-version bump (current: sigcomply.cloud.v3).
//
// The reflection test in cloud_test.go enforces "no freeform fields"
// structurally — adding interface{}, json.RawMessage, or
// map[string]any (transitively) will fail the build.
type SubmissionPayload struct {
	Schema string `json:"schema"`

	RunID     string `json:"run_id"`
	Framework string `json:"framework"`
	PeriodID  string `json:"period_id"`

	CommitSHA  string    `json:"commit_sha"`
	CommitTime time.Time `json:"commit_time"`
	Branch     string    `json:"branch"`

	Repository  Repository    `json:"repository"`
	Environment CIEnvironment `json:"environment"`

	CLIVersion  string    `json:"cli_version"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`

	Summary  RunSummary         `json:"summary"`
	Policies []AggregatedPolicy `json:"policies"`
}

// Repository is git-repo identity. Every field listed here is already
// public via the git remote URL.
type Repository struct {
	Provider string `json:"provider"`
	NameSlug string `json:"name_slug"`
	URL      string `json:"url,omitempty"`
}

// CIEnvironment captures CI-runner metadata. Workflow names and run
// URLs are CI-system artifacts, not customer evidence.
type CIEnvironment struct {
	Provider    string `json:"provider"`
	Workflow    string `json:"workflow,omitempty"`
	RunURL      string `json:"run_url,omitempty"`
	WorkerImage string `json:"worker_image,omitempty"`
}

// RunSummary is the counts-only run-level summary. ComplianceScore is
// the applicable-pass ratio computed in the aggregator:
// (policies_passed + policies_waived + policies_carried_forward) /
// (policies_total - policies_skipped - policies_na). Skipped and N/A
// policies are removed from the denominator so they don't drag the
// score down; waived policies count toward the numerator on the basis
// that an accepted exception is operationally equivalent to a pass.
// Carried-forward policies also count toward the numerator: a
// carry-forward only happens when the prior terminal status was pass
// (the cadence decision rule re-evaluates any non-pass), so the policy
// is still passing — it simply wasn't re-evaluated this run. Carried-
// forward policies are the normal steady state for sub-period cadences,
// so omitting them from the numerator would systematically understate
// the score on most real runs.
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

// AggregatedPolicy is the per-policy projection that crosses the
// boundary. Counts only — no violation lists, no resource IDs. The
// Message string is regenerated from counts by the aggregator, never
// copied from the rule's violation text.
//
// Cadence-related fields (ConfiguredCadence, LastEvaluatedAt,
// NextDueAt, IsCarriedForward, PolicyContentHash) are non-identifying
// scalars: they describe schedule/staleness, not who or what. The
// dashboard uses them to render staleness badges and "next due in N"
// without recomputing locally. The reflection test in cloud_test.go
// ensures no identity-carrying field can be added accidentally.
type AggregatedPolicy struct {
	PolicyID           string       `json:"policy_id"`
	Controls           []ControlRef `json:"controls"`
	Status             PolicyStatus `json:"status"`
	Severity           Severity     `json:"severity"`
	Category           string       `json:"category,omitempty"`
	ResourcesEvaluated int          `json:"resources_evaluated"`
	ResourcesFailed    int          `json:"resources_failed"`
	Message            string       `json:"message"`
	RuleVersion        string       `json:"rule_version,omitempty"`

	// ConfiguredCadence is the cadence string in effect at this run
	// (e.g., "daily", "every:6h"). Non-identifying.
	ConfiguredCadence string `json:"configured_cadence,omitempty"`

	// LastEvaluatedAt is the start time of the most recent run that
	// actually evaluated this policy. For freshly-evaluated rows it
	// equals StartedAt; for carry-forward rows it points to the
	// earlier run. Non-identifying. Pointer so a zero value is omitted
	// from the wire rather than serialized as "0001-01-01T00:00:00Z"
	// (encoding/json's omitempty does not omit a zero time.Time struct).
	LastEvaluatedAt *time.Time `json:"last_evaluated_at,omitempty"`

	// NextDueAt is the wall-clock time after which the policy is due
	// to be re-evaluated. Nil when the policy is always due (cadence
	// "continuous" / "every:0s") or when the most recent terminal
	// status was not pass (on_fail_retry → due on next run). Pointer
	// for the same omit-zero reason as LastEvaluatedAt.
	NextDueAt *time.Time `json:"next_due_at,omitempty"`

	// IsCarriedForward is true when this row references a prior
	// evaluation rather than a fresh one in this run.
	IsCarriedForward bool `json:"is_carried_forward,omitempty"`

	// PolicyContentHash is the SHA-256 hash of the policy spec +
	// referenced evidence-type schemas at this run. The cloud uses
	// it to detect a bundle bump that may invalidate prior
	// evaluations.
	PolicyContentHash string `json:"policy_content_hash,omitempty"`
}
