package manualcatalog_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
)

// coverage is the derived truth about one framework: what the compiled
// registries actually contain, not what a document claims they contain.
type coverage struct {
	controls, policies   int
	automated, manual    int // policies, by evidence mode
	ctrlAuto, ctrlManual int // controls, by the strongest check behind them
	catalogEntries       int
	// mgmtSystem counts the controls that are management-system
	// requirements rather than selectable catalog controls. Split out
	// because a claim about "Annex A controls" that silently counts ISO
	// 27001's clause 4-10 requirements too is the same category of
	// overclaim this file exists to catch — one that gets *more*
	// flattering as the honest gap is closed.
	mgmtSystem int
}

// measure derives the published figures from the compiled framework.
//
// The per-control half delegates to core.ClassifyControls — the same
// function `sigcomply report --view coverage` renders. That shared call
// is the point: when the doc figures and the product view were computed
// by two separate pieces of code, nothing stopped them disagreeing, and
// a coverage claim drifting from the coverage screen is precisely the
// failure this test exists to prevent.
func measure(controls []core.Control, policies []core.Policy, entries int) coverage {
	c := coverage{policies: len(policies), catalogEntries: entries}
	catalog := make([]core.Control, 0, len(controls))
	for i := range controls {
		if controls[i].IsManagementSystem() {
			c.mgmtSystem++
			continue
		}
		catalog = append(catalog, controls[i])
	}
	c.controls = len(catalog)
	for i := range policies {
		if policies[i].EvidenceMode == core.EvidenceModeAutomated {
			c.automated++
		} else {
			c.manual++
		}
	}
	totals := core.CoverageTotals(core.ClassifyControls(catalog, policies))
	c.ctrlAuto, c.ctrlManual = totals.Automated, totals.Manual
	return c
}

// TestDocFiguresMatchCode pins every published count and coverage claim
// to the compiled frameworks.
//
// Why this exists: a 2026 audit found `docs/reference/frameworks.md`
// advertising "100+ automated policies" when there were 82 — a claim
// that was false in customer-facing material, in a product whose whole
// pitch is not overclaiming. The counts had been recomputed by hand
// twice; nothing stopped them drifting again. Now adding a policy that
// changes a published figure fails the build, and the failure message
// names the number to write.
//
// If a doc is reworded, update the expected substring here rather than
// deleting the assertion.
func TestDocFiguresMatchCode(t *testing.T) {
	s := measure(soc2.Controls(), soc2.Policies(), len(soc2.ManualCatalogExport().Entries))
	i := measure(iso27001.Controls(), iso27001.Policies(), len(iso27001.ManualCatalogExport().Entries))

	for _, tc := range []struct {
		doc  string
		want []string
	}{
		{"docs/reference/frameworks.md", []string{
			fmt.Sprintf("%d / %d criteria have a check — %d automated, %d manual-only", s.controls, s.controls, s.ctrlAuto, s.ctrlManual),
			fmt.Sprintf("%d policies: %d automated + %d manual catalog entries", s.policies, s.automated, s.catalogEntries),
			fmt.Sprintf("%d / %d Annex A controls have a check — %d automated, %d manual-only", i.controls, i.controls, i.ctrlAuto, i.ctrlManual),
			fmt.Sprintf("%d policies: %d automated + %d manual catalog entries", i.policies, i.automated, i.catalogEntries),
			fmt.Sprintf("%d management-system requirements (clauses 4-10), all manual", i.mgmtSystem),
		}},
		{"README.md", []string{
			fmt.Sprintf("all %d Annex A controls,", i.controls),
			fmt.Sprintf("%d of them with an automated check", i.ctrlAuto),
			fmt.Sprintf("the %d management-system requirements of clauses 4-10", i.mgmtSystem),
		}},
		{"CLAUDE.md", []string{
			fmt.Sprintf("all %d Annex A controls, %d automated", i.controls, i.ctrlAuto),
			fmt.Sprintf("%d clause 4-10 management-system requirements", i.mgmtSystem),
		}},
		{"docs/guides/manual-evidence.md", []string{
			fmt.Sprintf("The SOC 2 catalog has **%d entries**", s.catalogEntries),
			fmt.Sprintf("Manual Evidence Catalog: soc2 (v1.0) — %d entries", s.catalogEntries),
		}},
		{"docs/quickstart.md", []string{
			fmt.Sprintf("SOC 2 ships %d catalog entries", s.catalogEntries),
		}},
		// The four below were drifting unguarded — every one of them
		// was stale or about to be. A published figure with no test is
		// a claim nobody re-derives (Theme C: none of the live
		// discrepancies was caught by review; they were caught by
		// deriving the truth mechanically and diffing it against the
		// prose).
		{"docs/guides/isms-clauses.md", []string{
			fmt.Sprintf("%d Annex A controls** — the selectable catalog. %d have an automated check; %d are manual-only.", i.controls, i.ctrlAuto, i.ctrlManual),
			fmt.Sprintf("To see the whole ISO catalog (%d entries", i.catalogEntries),
			fmt.Sprintf("%d of %d catalog controls have a check", i.controls, i.controls),
			fmt.Sprintf("%d automated  — verified by inspecting your infrastructure", i.ctrlAuto),
			fmt.Sprintf("%d manual     — satisfied by a document being on file", i.ctrlManual),
		}},
		{"docs/reference/commands.md", []string{
			fmt.Sprintf("For SOC 2, %d of %d criteria are the first kind", s.ctrlManual, s.controls),
			// The sample coverage output in this file is a SOC 2 run.
			fmt.Sprintf("%d of %d catalog controls have a check", s.controls, s.controls),
		}},
		{"docs/guides/verify-evidence.md", []string{
			fmt.Sprintf("For SOC 2, %d of %d criteria are", s.ctrlManual, s.controls),
		}},
		{"docs/architecture/10-cadence-model.md", []string{
			fmt.Sprintf("of %d entries have no file for period", s.catalogEntries),
		}},
	} {
		t.Run(tc.doc, func(t *testing.T) {
			path := filepath.Join("..", "..", tc.doc)
			data, err := os.ReadFile(path) //nolint:gosec // fixed in-repo doc paths
			if err != nil {
				t.Fatalf("read %s: %v", tc.doc, err)
			}
			body := string(data)
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("%s is out of date with the code.\n  expected to find: %q\n"+
						"  the compiled frameworks are the source of truth — update the doc to match, "+
						"then update the expected string here if you reworded it.", tc.doc, want)
				}
			}
		})
	}
}

// TestNoOverclaimedCoverage guards the specific phrasings that made the
// old docs misleading: a bare "all N controls" reads as "all N are
// checked", and "100+ automated policies" was simply false.
func TestNoOverclaimedCoverage(t *testing.T) {
	for _, doc := range []string{"README.md", "CLAUDE.md", "docs/reference/frameworks.md", "docs/quickstart.md", "docs/guides/manual-evidence.md"} {
		data, err := os.ReadFile(filepath.Join("..", "..", doc)) //nolint:gosec // fixed in-repo doc paths
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		for _, banned := range []string{"100+ automated"} {
			if strings.Contains(string(data), banned) {
				t.Errorf("%s contains the overclaiming phrase %q; state the real count instead", doc, banned)
			}
		}
	}
}
