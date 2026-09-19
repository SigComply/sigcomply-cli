package orchestrator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// An unbound roster slot is explained as a missing designation, and the
// accounts slot the planner emptied alongside it is not blamed.
func TestSkipDetail_UnboundRosterSlot(t *testing.T) {
	pp := &planner.PlannedPolicy{
		Spec: core.Policy{Slots: map[string]core.Slot{
			slotRoster:   {Accepts: []string{"roster_entry"}, Required: true, Role: core.SlotRoleRoster},
			slotAccounts: {Accepts: []string{evidenceTypeDirectoryUser}, Required: true, Role: core.SlotRoleRosterSubject},
		}},
		Bindings: map[string][]planner.Binding{slotRoster: nil, slotAccounts: nil},
	}
	got := skipDetail(pp)
	if !strings.Contains(got, "no roster source designated") || !strings.Contains(got, "experimental.roster.source") {
		t.Errorf("skipDetail = %q; want it to name experimental.roster.source", got)
	}
	if strings.Contains(got, "no configured source emits") || strings.Contains(got, slotAccounts) {
		t.Errorf("skipDetail = %q; must not blame the emptied accounts slot", got)
	}
}

func TestEmitRosterWarnings_UnknownKey(t *testing.T) {
	var buf bytes.Buffer
	cfg := &spec.ProjectConfig{
		Framework:    testFramework,
		Sources:      map[string]map[string]any{sourceOkta: {}},
		Experimental: map[string]any{slotRoster: map[string]any{"source": sourceOkta, "nonhuman": []any{"bot"}}},
	}
	emitRosterWarnings(log.New(&buf, false), cfg, registry.NewSet())
	if !strings.Contains(buf.String(), "roster: ignoring unrecognized key experimental.roster.nonhuman") {
		t.Errorf("log = %q; want the unrecognized-key warning", buf.String())
	}
}
