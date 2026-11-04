package orchestrator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

const (
	formDeclEntry = "decl_entry"
	formDeclURL   = "https://forms.example/evidence/soc2/decl_entry"
	formCheckURL  = "https://forms.example/evidence/soc2/check_entry"
)

// formLinkPlan plans one manual policy per catalog entry, so a test can
// give any of them a status.
func formLinkPlan(catalogByPolicy map[string]string) *planner.RunPlan {
	plan := &planner.RunPlan{Framework: testFramework, Period: planner.Period{ID: testPeriodID}}
	for id, entry := range catalogByPolicy {
		plan.Policies = append(plan.Policies, planner.PlannedPolicy{Spec: core.Policy{
			ID: id, EvidenceMode: core.EvidenceModeManual, CatalogEntry: entry,
		}})
	}
	return plan
}

func manualFail(id string) core.PolicyResult {
	return core.PolicyResult{
		PolicyID: id, Status: core.StatusFail, EvidenceMode: core.EvidenceModeManual,
		Violations: []core.Violation{{ResourceID: "folder", Reason: "no file uploaded for " + id}},
	}
}

var formLinks = map[string]string{formDeclEntry: formDeclURL, "check_entry": formCheckURL}

func TestRenderAndExitCode_FormLinkForMissingManualEvidence(t *testing.T) {
	plan := formLinkPlan(map[string]string{"p.decl": formDeclEntry, "p.check": "check_entry"})
	results := []core.PolicyResult{manualFail("p.decl"), manualFail("p.check")}
	var buf bytes.Buffer
	renderAndExitCode(&buf, plan, results, formLinks, spec.CIConfig{}, nil)
	out := buf.String()
	for _, want := range []string{
		"      ↳ no file uploaded for p.decl\n      ↳ fill in the form: " + formDeclURL + "\n",
		"      ↳ no file uploaded for p.check\n      ↳ fill in the form: " + formCheckURL + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// No link where the SPA has no form (document_upload, or a
// catalog_entry overridden to an ID outside the catalog), and none where
// nothing is missing or the failure is not about a missing file.
func TestRenderAndExitCode_NoFormLink(t *testing.T) {
	plan := formLinkPlan(map[string]string{
		"p.doc": "doc_entry", "p.override": "custom_entry",
		"p.pass": formDeclEntry, "p.carried": formDeclEntry, "p.error": formDeclEntry,
	})
	results := []core.PolicyResult{
		manualFail("p.doc"),
		manualFail("p.override"),
		{PolicyID: "p.pass", Status: core.StatusPass, EvidenceMode: core.EvidenceModeManual},
		{PolicyID: "p.carried", Status: core.StatusCarriedForward, EvidenceMode: core.EvidenceModeManual},
		{PolicyID: "p.error", Status: core.StatusError, EvidenceMode: core.EvidenceModeManual,
			Diag: map[string]any{"collect_error": "storage unreachable"}},
		// An automated failure whose policy shares an entry ID never
		// points at a form.
		{PolicyID: "p.auto", Status: core.StatusFail, Violations: []core.Violation{{ResourceID: "r", Reason: "bad"}}},
	}
	plan.Policies = append(plan.Policies, planner.PlannedPolicy{Spec: core.Policy{ID: "p.auto", CatalogEntry: formDeclEntry}})
	var buf bytes.Buffer
	renderAndExitCode(&buf, plan, results, formLinks, spec.CIConfig{}, nil)
	if strings.Contains(buf.String(), "fill in the form") {
		t.Errorf("unexpected form link:\n%s", buf.String())
	}
}

func TestRenderAndExitCode_FormLinkIsSanitized(t *testing.T) {
	plan := formLinkPlan(map[string]string{"p.decl": formDeclEntry})
	var buf bytes.Buffer
	renderAndExitCode(&buf, plan, []core.PolicyResult{manualFail("p.decl")},
		map[string]string{formDeclEntry: hostileText}, spec.CIConfig{}, nil)
	assertSafeOutput(t, buf.String())
}
