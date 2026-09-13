package iso27001

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// rosterShape is the part of a roster policy that decides what it checks.
type rosterShape struct {
	control, cadence, category string
	severity                   core.Severity
	mode                       core.EvidenceMode
	quantifier                 core.PassWhenQuantifier
	slot, identityKey, op, in  string
	roster, accounts           string // role|cardinality|required|accepts
}

func slotShape(s *core.Slot) string {
	req := "optional"
	if s.Required {
		req = "required"
	}
	return strings.Join([]string{string(s.Role), string(s.Cardinality), req, strings.Join(s.Accepts, ",")}, "|")
}

// The roster lifecycle policies join accounts in every other system to
// the designated roster: a roster slot that is never auto-bound and an
// accounts slot the planner keeps disjoint from it.
func TestRosterPolicies_ShapeAndControls(t *testing.T) {
	base := rosterShape{
		cadence: "daily", category: "access", mode: core.EvidenceModeAutomated,
		slot: "accounts", identityKey: "account.ref", op: core.OpMatchesIn, in: "roster",
		roster:   "roster|exactly-one|required|roster_entry",
		accounts: "roster_subject|one-or-more|required|directory_user,directory_user.v2",
	}
	linked, inactive := base, base
	linked.control, linked.severity, linked.quantifier = "A.5.16", core.SeverityHigh, core.QuantifierAll
	inactive.control, inactive.severity, inactive.quantifier = "A.5.18", core.SeverityCritical, core.QuantifierNone
	want := map[string]rosterShape{
		"iso27001.5.16.accounts_linked_to_roster":                 linked,
		"iso27001.5.18.no_active_accounts_for_inactive_personnel": inactive,
	}

	found := 0
	for _, p := range Policies() {
		w, ok := want[p.ID]
		if !ok {
			continue
		}
		found++
		if err := spec.ValidatePassWhen(p); err != nil {
			t.Errorf("%s: %v", p.ID, err)
		}
		c := p.PassWhen.Clauses[0]
		roster, accounts := p.Slots["roster"], p.Slots["accounts"]
		got := rosterShape{
			control: core.PrimaryControlID(p.Controls), cadence: p.Cadence, category: p.Category,
			severity: p.Severity, mode: p.EvidenceMode, quantifier: c.Quantifier,
			slot: c.Slot, identityKey: c.IdentityKey, op: c.Condition.Op, in: c.Condition.InSlot,
			roster: slotShape(&roster), accounts: slotShape(&accounts),
		}
		if got != w {
			t.Errorf("%s:\n got  %+v\n want %+v", p.ID, got, w)
		}
	}
	if found != len(want) {
		t.Errorf("found %d of %d roster policies", found, len(want))
	}
}
