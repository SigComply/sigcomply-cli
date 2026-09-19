package manualcatalog_test

import (
	"sort"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
)

// TestEveryControlHasAPolicy keeps a declared control from shipping with
// nothing behind it.
//
// Why this exists: both frameworks already assert the reverse direction
// (every policy references a registered control), so an orphaned control
// — declared in controls.go, implemented by no policy — was structurally
// invisible. An audit found 33 of them (SOC 2 7, ISO 27001 26). That gap
// is not cosmetic: a customer reads a published control count — "all 93
// Annex A controls", "16 management-system requirements" — as coverage,
// and an auditor who asks about an orphaned control finds the tool never
// once prompted for its evidence. This runs over every declared control,
// management-system requirements included: a clause 4-10 requirement with
// no policy behind it is the same silent hole.
//
// Adding a control without a policy now fails the build. Closing a gap
// does not require automation — a manual-evidence policy that prompts for
// the right document is legitimate coverage, and is the honest answer
// wherever no evidence type can observe the control.
func TestEveryControlHasAPolicy(t *testing.T) {
	for _, fw := range []struct {
		id       string
		controls func() []core.Control
		policies func() []core.Policy
	}{
		{"soc2", soc2.Controls, soc2.Policies},
		{"iso27001", iso27001.Controls, iso27001.Policies},
	} {
		t.Run(fw.id, func(t *testing.T) {
			covered := make(map[string]bool)
			for _, p := range fw.policies() {
				covered[core.PrimaryControlID(p.Controls)] = true
			}
			var orphaned []string
			for _, c := range fw.controls() {
				if !covered[c.ID] {
					orphaned = append(orphaned, c.ID)
				}
			}
			sort.Strings(orphaned)
			if len(orphaned) > 0 {
				t.Errorf("%s: %d control(s) declared with no implementing policy: %v\n"+
					"every declared control needs at least one policy — an automated pass_when "+
					"check where an evidence type supports it, otherwise a manual-evidence entry",
					fw.id, len(orphaned), orphaned)
			}
		})
	}
}
