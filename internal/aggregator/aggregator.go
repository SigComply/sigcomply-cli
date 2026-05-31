// Package aggregator is L6 of the SigComply CLI and the privacy
// boundary: projects []core.PolicyResult into the structurally
// counts-only core.SubmissionPayload that the cloud submitter
// consumes. No resource identifier crosses this boundary. The wire
// type has no Violations slice, no map[string]any, no interface{}
// fields — widening it requires a code change reviewed at this seam.
//
// The structural enforcement lives in
// internal/core/cloud_test.go::TestSubmissionPayload_StructurallyCountsOnly,
// which walks SubmissionPayload's type graph and fails the build if
// an identity-carrying field is added.
//
// See docs/architecture/02-layers.md and 06-aggregation.md.
package aggregator

import (
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// SchemaVersion is the wire-format identifier stamped on every
// SubmissionPayload. Bumping requires a code change to the contract
// (see 06-aggregation.md §Versioning the contract).
//
// v2: adds per-policy cadence metadata (ConfiguredCadence,
// LastEvaluatedAt, NextDueAt, IsCarriedForward, PolicyContentHash) so
// the dashboard can render staleness and next-due badges without
// recomputing locally.
//
// v3 (current): replaces the per-policy scalar ControlID with a
// Controls []ControlRef list so one check can map to controls across
// multiple frameworks, each ControlRef carrying framework,
// framework_version, control_id, and a relationship type. All fields
// are non-identifying scalars and pass the structural counts-only test
// in core/cloud_test.go.
const SchemaVersion = "sigcomply.cloud.v3"

// Environment captures the CI-runtime metadata stamped on the payload.
// The CLI's orchestrator (L9) populates it from environment variables
// and git context before calling Build.
type Environment struct {
	Repository  core.Repository
	CI          core.CIEnvironment
	Branch      string
	CommitSHA   string
	CommitTime  time.Time
	CLIVersion  string
	RunID       string
	Framework   string
	PeriodID    string
	StartedAt   time.Time
	CompletedAt time.Time
}

// Build produces the SubmissionPayload from a run's per-policy results.
// The "Message" field on each AggregatedPolicy is regenerated from
// counts here; the rule's violation text is never copied across.
func Build(results []core.PolicyResult, env *Environment) core.SubmissionPayload {
	if env == nil {
		env = &Environment{}
	}
	out := core.SubmissionPayload{
		Schema:      SchemaVersion,
		RunID:       env.RunID,
		Framework:   env.Framework,
		PeriodID:    env.PeriodID,
		CommitSHA:   env.CommitSHA,
		CommitTime:  env.CommitTime,
		Branch:      env.Branch,
		Repository:  env.Repository,
		Environment: env.CI,
		CLIVersion:  env.CLIVersion,
		StartedAt:   env.StartedAt,
		CompletedAt: env.CompletedAt,
		Summary:     buildSummary(results),
		Policies:    make([]core.AggregatedPolicy, 0, len(results)),
	}
	for i := range results {
		r := &results[i]
		out.Policies = append(out.Policies, core.AggregatedPolicy{
			PolicyID:           r.PolicyID,
			Controls:           r.Controls,
			Status:             r.Status,
			Severity:           r.Severity,
			Category:           r.Category,
			ResourcesEvaluated: r.ResourcesEvaluated,
			ResourcesFailed:    r.ResourcesFailed,
			Message:            generateMessage(r),
			RuleVersion:        r.RuleVersion,
			ConfiguredCadence:  r.ConfiguredCadence,
			LastEvaluatedAt:    lastEvaluatedAt(r, env),
			NextDueAt:          r.NextDueAt,
			IsCarriedForward:   r.Status == core.StatusCarriedForward,
			PolicyContentHash:  r.PolicyContentHash,
		})
	}
	return out
}

// lastEvaluatedAt returns the timestamp of the most recent actual
// evaluation for a policy. For freshly-evaluated policies it is the
// run's start time. For carry-forward results it is the carry-
// forward ref's LastEvaluatedAt — the earlier run that this row
// inherits from. Used by the cloud dashboard to render staleness
// badges without recomputing locally.
func lastEvaluatedAt(r *core.PolicyResult, env *Environment) time.Time {
	if r.Status == core.StatusCarriedForward && r.CarryForward != nil {
		return r.CarryForward.LastEvaluatedAt
	}
	if env == nil {
		return time.Time{}
	}
	return env.StartedAt
}

func buildSummary(results []core.PolicyResult) core.RunSummary {
	var s core.RunSummary
	s.PoliciesTotal = len(results)
	for i := range results {
		r := &results[i]
		switch r.Status {
		case core.StatusPass:
			s.PoliciesPassed++
		case core.StatusFail:
			s.PoliciesFailed++
		case core.StatusSkip:
			s.PoliciesSkipped++
		case core.StatusError:
			s.PoliciesError++
		case core.StatusNA:
			s.PoliciesNA++
		case core.StatusWaived:
			s.PoliciesWaived++
		}
	}
	denominator := s.PoliciesTotal - s.PoliciesSkipped - s.PoliciesNA
	if denominator > 0 {
		s.ComplianceScore = float64(s.PoliciesPassed+s.PoliciesWaived) / float64(denominator)
	}
	return s
}

// generateMessage produces a count-only summary string. It NEVER
// receives the rule's violation text — the rule's text may name
// resources, and resource identifiers do not cross the privacy
// boundary.
func generateMessage(r *core.PolicyResult) string {
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
	}
	return ""
}
