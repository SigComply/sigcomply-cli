package orchestrator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

func caveatPlan(policyIDs, alternatives []string) *planner.RunPlan {
	plan := &planner.RunPlan{}
	for _, id := range policyIDs {
		plan.Policies = append(plan.Policies, planner.PlannedPolicy{
			Spec: core.Policy{ID: id},
			SourceCaveats: []planner.SourceCaveatWarning{{
				Slot: "evidence", SourceID: "aws.identity_center",
				EvidenceType: "directory_user", Field: "mfa_enabled",
				Detail:       "AWS publishes no per-user MFA API",
				Alternatives: alternatives,
			}},
		})
	}
	return plan
}

// The remediable case: another source on the same slot holds the real answer,
// so the warning must name it and print the pin.
func TestEmitSourceCaveatWarnings_NamesThePin(t *testing.T) {
	var buf bytes.Buffer
	emitSourceCaveatWarnings(log.New(&buf, false), caveatPlan(
		[]string{"soc2.cc6.1.mfa_enforced_all_users", "soc2.cc6.1.mfa_enforced_admins"},
		[]string{"okta"},
	))
	got := buf.String()

	for _, want := range []string{
		"source-caveat: aws.identity_center cannot verify directory_user.mfa_enabled",
		"AWS publishes no per-user MFA API",
		"2 policy/policies read that field",
		"soc2.cc6.1.mfa_enforced_admins, soc2.cc6.1.mfa_enforced_all_users",
		"okta also bound to slot \"evidence\"",
		"bindings:",
		"evidence: [okta]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log missing %q; got:\n%s", want, got)
		}
	}
}

// One misbound identity source trips every MFA policy at once. Six
// near-identical blocks would bury the single fact that matters, so the
// source/field pair is reported once with the policies listed.
func TestEmitSourceCaveatWarnings_GroupsBySourceAndField(t *testing.T) {
	var buf bytes.Buffer
	emitSourceCaveatWarnings(log.New(&buf, false), caveatPlan(
		[]string{"p1", "p2", "p3"}, []string{"okta"},
	))
	if n := strings.Count(buf.String(), "cannot verify directory_user.mfa_enabled"); n != 1 {
		t.Errorf("headline appeared %d times; want 1 grouped line:\n%s", n, buf.String())
	}
}

// With nothing else on the slot, suggesting a pin would be advice to pin the
// slot to the only source already on it. Say it is a real finding instead.
func TestEmitSourceCaveatWarnings_SoleSourceIsARealFinding(t *testing.T) {
	var buf bytes.Buffer
	emitSourceCaveatWarnings(log.New(&buf, false), caveatPlan([]string{"p1"}, nil))
	got := buf.String()

	if !strings.Contains(got, "real finding rather than a binding mistake") {
		t.Errorf("log = %q; want the honest-residue wording", got)
	}
	if strings.Contains(got, "bindings:") {
		t.Errorf("log = %q; must not suggest pinning when there is nothing to pin to", got)
	}
}

// Silence when nothing is caveated — otherwise this is noise on every run.
func TestEmitSourceCaveatWarnings_SilentWhenClean(t *testing.T) {
	var buf bytes.Buffer
	emitSourceCaveatWarnings(log.New(&buf, false), &planner.RunPlan{
		Policies: []planner.PlannedPolicy{{Spec: core.Policy{ID: "p1"}}},
	})
	if buf.String() != "" {
		t.Errorf("log = %q; want silence", buf.String())
	}
	emitSourceCaveatWarnings(log.New(&buf, false), nil)
	if buf.String() != "" {
		t.Errorf("nil plan produced output: %q", buf.String())
	}
}
