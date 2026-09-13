// Package scope answers the question every other layer assumes away:
// did this run actually look at everything it was supposed to?
//
// The rest of the pipeline is self-referential. A policy whose required
// slot has no configured source binds nothing, plans cleanly (the
// deferred-source model deliberately permits it), is skipped at
// evaluation, and is then removed from the compliance-score denominator.
// Forget to wire a platform and its controls do not fail — they
// disappear, and the run reports a perfect score for an estate it never
// examined. Nothing in the collected evidence can reveal this, because
// the evidence that would have revealed it is exactly what is missing.
//
// The fix is an external baseline: the operator declares the estate this
// project asserts coverage over (spec.ScopeConfig), and this package
// checks the run against that declaration. Declaring is opt-in; when no
// declaration is present the report is Undeclared and nothing anywhere
// changes behavior.
//
// Everything here is vault-side. Source IDs are operator-chosen and
// routinely embed account or environment names, so the report is written
// to the run summary and rendered locally, and never crosses the
// aggregation boundary. See ARCHITECTURE.md Core Principle #1.
package scope

import (
	"sort"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// Status is the run-level verdict.
type Status string

const (
	// StatusUndeclared means the operator declared no estate. The run is
	// unchanged and unjudged — we cannot call a run incomplete against a
	// baseline that does not exist.
	StatusUndeclared Status = "undeclared"
	// StatusComplete means every declared source was configured, bound to
	// at least one policy slot, and returned at least one record.
	StatusComplete Status = "complete"
	// StatusIncomplete means at least one declared source did not make it
	// all the way through. The run has not covered what it claims to.
	StatusIncomplete Status = "incomplete"
)

// SourceState is why one declared source did or did not count as covered.
type SourceState string

const (
	// SourceOK means configured, bound, and it produced evidence.
	SourceOK SourceState = "ok"
	// SourceNotConfigured means declared in scope but absent from `sources:`.
	// The commonest real failure — a platform nobody wired up.
	SourceNotConfigured SourceState = "not_configured"
	// SourceNotBound means configured, but no policy slot accepts anything it
	// emits, so it was never consulted. Usually an evidence-type version
	// mismatch or a source wired for a framework that does not use it.
	SourceNotBound SourceState = "not_bound"
	// SourceNoRecords means bound but returned zero records — credentials that
	// resolve to an empty account, a failed collection, or a permission
	// that silently returns nothing.
	SourceNoRecords SourceState = "no_records"
)

// SourceReport is the per-source verdict.
type SourceReport struct {
	SourceID string      `json:"source_id"`
	State    SourceState `json:"state"`
}

// Report is the run-level scope object: the auditor-legible answer to
// "what was in scope, and did we actually look at it?"
//
// Written to summary.json, so it is covered by the run manifest's
// signature and is diffable across runs (Core Principle #7). All slices
// are sorted.
type Report struct {
	Status Status `json:"status"`

	// DeclaredBy/DeclaredAt carry the operator's audit trail for the
	// assertion. DeclaredBy is an email address: vault-side only, never
	// on the wire.
	DeclaredBy string `json:"declared_by,omitempty"`
	DeclaredAt string `json:"declared_at,omitempty"`

	// Sources is one entry per declared source, sorted by ID.
	Sources []SourceReport `json:"sources,omitempty"`

	// Missing lists the declared sources whose state is not ok, sorted.
	// Redundant with Sources but kept because it is what the renderers
	// and the exit-code decision actually consume.
	Missing []string `json:"missing,omitempty"`

	// PoliciesUnbound counts policies with at least one required slot
	// that bound no source. These are the controls that will be skipped
	// and silently leave the compliance score. Reported even when the
	// estate is undeclared, because the number is informative on its own.
	PoliciesUnbound int `json:"policies_unbound"`
}

// Complete reports whether the run covered its declared estate. An
// undeclared estate is not a failure — there is nothing to fall short of.
func (r *Report) Complete() bool {
	return r == nil || r.Status != StatusIncomplete
}

// Input is everything needed to judge a run against its declaration.
type Input struct {
	// Declared is the operator's estate, from
	// experimental.scope.required_sources. Empty means undeclared.
	Declared []string
	// DeclaredBy/DeclaredAt are the audit trail, passed through.
	DeclaredBy string
	DeclaredAt string
	// Configured is the key set of `sources:` in the project config.
	Configured map[string]map[string]any
	// Plan is the resolved run plan, read for bindings and for required
	// slots that bound nothing.
	Plan *planner.RunPlan
	// RecordsByPolicy is the collector's output. Records carry the
	// SourceID that produced them, which is how a source that was bound
	// but returned nothing is told apart from one that worked.
	RecordsByPolicy map[string]map[string][]core.EvidenceRecord
}

// Evaluate judges one run against its declared estate.
//
// A declared source must clear three bars to count as covered: it is
// configured, some policy slot actually bound it, and it returned at
// least one record. Stopping at the first bar would make this a lint on
// a single YAML file — it would report success for a source whose
// credentials are absent, whose plugin emits nothing any policy accepts,
// or whose every collection failed.
func Evaluate(in *Input) *Report {
	unbound := 0
	if in.Plan != nil {
		for i := range in.Plan.Policies {
			if len(in.Plan.Policies[i].UnboundRequiredSlots) > 0 {
				unbound++
			}
		}
	}

	if len(in.Declared) == 0 {
		return &Report{Status: StatusUndeclared, PoliciesUnbound: unbound}
	}

	bound := boundSources(in.Plan)
	producing := producingSources(in.RecordsByPolicy)

	rep := &Report{
		DeclaredBy:      in.DeclaredBy,
		DeclaredAt:      in.DeclaredAt,
		PoliciesUnbound: unbound,
	}
	for _, id := range in.Declared {
		state := classify(id, in.Configured, bound, producing)
		rep.Sources = append(rep.Sources, SourceReport{SourceID: id, State: state})
		if state != SourceOK {
			rep.Missing = append(rep.Missing, id)
		}
	}
	sort.Slice(rep.Sources, func(i, j int) bool { return rep.Sources[i].SourceID < rep.Sources[j].SourceID })
	sort.Strings(rep.Missing)

	rep.Status = StatusComplete
	if len(rep.Missing) > 0 {
		rep.Status = StatusIncomplete
	}
	return rep
}

func classify(id string, configured map[string]map[string]any, bound, producing map[string]struct{}) SourceState {
	if _, ok := configured[id]; !ok {
		return SourceNotConfigured
	}
	if _, ok := bound[id]; !ok {
		return SourceNotBound
	}
	if _, ok := producing[id]; !ok {
		return SourceNoRecords
	}
	return SourceOK
}

// boundSources is the set of source IDs the planner actually bound to at
// least one slot.
func boundSources(plan *planner.RunPlan) map[string]struct{} {
	out := map[string]struct{}{}
	if plan == nil {
		return out
	}
	for i := range plan.Policies {
		for _, bs := range plan.Policies[i].Bindings {
			for j := range bs {
				out[bs[j].SourceID] = struct{}{}
			}
		}
	}
	return out
}

// producingSources is the set of source IDs that actually returned at
// least one evidence record this run.
func producingSources(byPolicy map[string]map[string][]core.EvidenceRecord) map[string]struct{} {
	out := map[string]struct{}{}
	for _, slots := range byPolicy {
		for _, recs := range slots {
			for i := range recs {
				out[recs[i].SourceID] = struct{}{}
			}
		}
	}
	return out
}
