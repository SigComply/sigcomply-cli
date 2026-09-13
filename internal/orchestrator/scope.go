package orchestrator

import (
	"fmt"
	"io"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/scope"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// evaluateScope judges the run against the operator's declared estate.
//
// Returns nil only when the declaration cannot be read at all; an absent
// declaration still yields a report (status undeclared), because the
// unbound-policy count it carries is worth surfacing either way.
func evaluateScope(opts *Options, plan *planner.RunPlan, records map[string]map[string][]core.EvidenceRecord) *scope.Report {
	sc, err := spec.LoadScopeConfig(opts.Config)
	if err != nil {
		// A malformed declaration must not take the run down after the
		// evidence has already been collected and signed. Warn and treat
		// the estate as undeclared; the config error surfaces on the next
		// `check` at load time anyway.
		opts.Logger.Warnf("scope: ignoring experimental.scope: %s", err.Error())
		sc = nil
	}
	in := &scope.Input{
		Configured:      opts.Config.Sources,
		Plan:            plan,
		RecordsByPolicy: records,
	}
	if sc != nil {
		in.Declared = sc.RequiredSources
		in.DeclaredBy = sc.DeclaredBy
		in.DeclaredAt = sc.DeclaredAt
		for _, k := range sc.UnknownKeys {
			// Tolerated, never fatal — that tolerance is the point of the
			// experimental: hatch — but a typo should still be loud.
			opts.Logger.Warnf("scope: ignoring unrecognized key experimental.scope.%s", k)
		}
	}
	return scope.Evaluate(in)
}

// scopeStateExplanation turns a per-source verdict into the sentence an
// operator can act on.
func scopeStateExplanation(s scope.SourceState) string {
	switch s {
	case scope.SourceNotConfigured:
		return "declared in scope but absent from sources: — nothing collected it"
	case scope.SourceNotBound:
		return "configured, but no policy slot accepts what it emits — never consulted"
	case scope.SourceNoRecords:
		return "bound but returned zero records — check credentials and permissions"
	default:
		return "covered"
	}
}

// renderScope prints the estate verdict. Silent when the estate is
// declared and fully covered: a passing check does not need a paragraph.
// When the estate is undeclared it prints nothing here either — the
// existing skip explanations already cover that ground, and a nag on
// every run of every project that has not opted in would be noise.
func renderScope(stdout io.Writer, rep *scope.Report) {
	if rep == nil || rep.Status != scope.StatusIncomplete {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\nSCOPE INCOMPLETE — %d of %d declared source(s) were not covered by this run:\n",
		len(rep.Missing), len(rep.Sources))
	for _, s := range rep.Sources {
		if s.State == scope.SourceOK {
			continue
		}
		fmt.Fprintf(&b, "  %s — %s\n", s.SourceID, scopeStateExplanation(s.State))
	}
	b.WriteString("This run did not look at everything the project declares it covers,\n")
	b.WriteString("so its compliance score describes a smaller estate than you claimed.\n")
	b.WriteString("Fix the sources above, or amend experimental.scope.required_sources\n")
	b.WriteString("in .sigcomply.yaml if the estate genuinely changed.\n")
	_, _ = io.WriteString(stdout, b.String()) //nolint:errcheck // status output
}
