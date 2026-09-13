package planner

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func TestUnboundRequiredSlots(t *testing.T) {
	twoSlots := &core.Policy{
		ID: "p1",
		Slots: map[string]core.Slot{
			"users": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
			"repos": {Accepts: []string{"repository"}, Cardinality: core.SlotOneOrMore, Required: true},
			"extra": {Accepts: []string{"whatever"}, Cardinality: core.SlotOptional, Required: false},
		},
	}

	cases := []struct {
		name     string
		bindings map[string][]Binding
		want     []string
	}{
		{
			name:     "no bindings at all",
			bindings: map[string][]Binding{},
			want:     []string{"repos", "users"},
		},
		{
			name: "one required slot bound",
			bindings: map[string][]Binding{
				"users": {{SourceID: "aws.iam"}},
			},
			want: []string{"repos"},
		},
		{
			name: "all required slots bound",
			bindings: map[string][]Binding{
				"users": {{SourceID: "aws.iam"}},
				"repos": {{SourceID: "github"}},
			},
			want: nil,
		},
		{
			// A non-required slot with no binding is not a scope gap —
			// the policy is designed to run without it.
			name: "optional slot unbound is not a gap",
			bindings: map[string][]Binding{
				"users": {{SourceID: "aws.iam"}},
				"repos": {{SourceID: "github"}},
				"extra": nil,
			},
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := unboundRequiredSlots(twoSlots, c.bindings)
			if len(got) != len(c.want) {
				t.Fatalf("unboundRequiredSlots = %v; want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("unboundRequiredSlots = %v; want %v (sorted)", got, c.want)
				}
			}
		})
	}
}

// Manual policies bind a synthetic "_manual" slot and declare no Slots
// map, so they can never report a scope gap.
func TestUnboundRequiredSlots_ManualPolicyHasNoSlots(t *testing.T) {
	manual := &core.Policy{ID: "m1", EvidenceMode: core.EvidenceModeManual}
	if got := unboundRequiredSlots(manual, map[string][]Binding{}); got != nil {
		t.Fatalf("unboundRequiredSlots = %v; want nil for a manual policy", got)
	}
}
