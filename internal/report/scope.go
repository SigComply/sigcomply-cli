package report

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// scopeSummary is the slice of summary.json the scope view needs. It is
// decoded structurally rather than by importing internal/scope so the
// report layer stays a pure reader of vault bytes and can still parse a
// summary written by a different CLI version.
type scopeSummary struct {
	Scope *struct {
		Status     string `json:"status"`
		DeclaredBy string `json:"declared_by"`
		DeclaredAt string `json:"declared_at"`
		Sources    []struct {
			SourceID string `json:"source_id"`
			State    string `json:"state"`
		} `json:"sources"`
	} `json:"scope"`
}

// buildScope answers "what was this run supposed to cover, and did it?"
//
// It reads two things from the latest run in the period: the estate
// verdict persisted in summary.json (absent for projects that never
// declared one, and for runs written before scope existed), and the set
// of controls that were not evaluated, derived from the per-policy
// result.json files the latest view already reads.
//
// The skip half is deliberately independent of the declaration. A
// skipped control drops out of the compliance-score denominator, so it
// is exactly the thing a green run can hide — and that is worth showing
// whether or not anyone opted into declaring an estate.
func buildScope(ctx context.Context, v core.Vault, runs []runRecord) (*ScopeView, error) {
	out := &ScopeView{}
	if len(runs) == 0 {
		return out, nil
	}
	latest := runs[len(runs)-1]
	out.RunID = latest.Manifest.RunID

	// A run predating scope, or one from a project that never opted in,
	// simply has no block. That is not an error — the skip half below
	// still renders.
	if body, err := v.GetBinary(ctx, latest.Path+"/summary.json"); err == nil {
		var s scopeSummary
		if err := json.Unmarshal(body, &s); err == nil && s.Scope != nil {
			out.Declared = true
			out.Status = s.Scope.Status
			out.DeclaredBy = s.Scope.DeclaredBy
			out.DeclaredAt = s.Scope.DeclaredAt
			for _, src := range s.Scope.Sources {
				out.Sources = append(out.Sources, ScopeSource{SourceID: src.SourceID, State: src.State})
			}
			sort.Slice(out.Sources, func(i, j int) bool { return out.Sources[i].SourceID < out.Sources[j].SourceID })
		}
	}

	raw, err := listPolicyResults(ctx, v, latest.Path)
	if err != nil {
		return nil, err
	}
	for policyID, body := range raw {
		var r core.PolicyResult
		if err := json.Unmarshal(body, &r); err != nil {
			// An unreadable result.json is skipped rather than fatal,
			// matching how the other views degrade.
			continue
		}
		// Skips and errors both mean the control was not evaluated.
		// An errored policy is arguably the more urgent of the two: a
		// skip at least leaves the compliance-score denominator, while
		// an error stays in it and counts against the score, so it is
		// an unevaluated control wearing a failure's clothes.
		if r.Status != core.StatusSkip && r.Status != core.StatusError {
			continue
		}
		id := r.PolicyID
		if id == "" {
			id = policyID
		}
		out.Skipped = append(out.Skipped, SkippedPolicy{
			PolicyID: id,
			Status:   string(r.Status),
			Reason:   skipReasonOf(&r),
		})
	}
	sort.Slice(out.Skipped, func(i, j int) bool { return out.Skipped[i].PolicyID < out.Skipped[j].PolicyID })
	return out, nil
}

// skipReasonOf pulls the evaluator's diagnostic off an unevaluated
// result, falling back to a plain statement rather than an empty cell.
//
// The planner's own "reason" wins for a skip; an error carries its
// explanation elsewhere in Diag, so core.ResultReason — the same
// projection `check` prints — handles that half.
func skipReasonOf(r *core.PolicyResult) string {
	if r.Diag != nil {
		if v, ok := r.Diag["reason"].(string); ok && v != "" {
			return v
		}
	}
	if reason := core.ResultReason(r); reason != "" {
		return reason
	}
	return "not evaluated"
}
