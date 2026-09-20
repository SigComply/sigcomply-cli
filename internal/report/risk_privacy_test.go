package report_test

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/report"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// The register holds the two most sensitive strings a compliance tool
// can hold: a description of where an organization believes it is
// weakest, and the address of the person accountable for it. Both stay
// vault-side.
//
// The Statement of Applicability is the only surface that reads the
// register at all, and it carries risk IDs — never descriptions, owners,
// acceptance rationales or approver addresses. An ID is an opaque slug
// the operator chose; the rest is the map. This pins the distinction
// directly, because it is a behavior no type-level guard can express:
// every one of these is an ordinary string field.
func TestSoA_CarriesRiskIDsAndNothingElseAboutARisk(t *testing.T) {
	const (
		description = "Offshore payroll processor retains unencrypted salary data"
		owner       = "cfo@example.com"
		rationale   = "Residual exposure is inside the board's stated appetite"
		approver    = "ceo@example.com"
	)
	cfg, err := spec.LoadProjectConfig([]byte(`schema_version: project.v1
framework: iso27001
sources:
  aws.iam: {}
experimental:
  risks:
    register:
      - id: r-payroll
        description: ` + description + `
        owner: ` + owner + `
        level: high
        treatment: retain
        accepted_by: ` + approver + `
        acceptance_rationale: ` + rationale + `
        residual_level: high
        assessed_at: "2026-01-15"
      - id: r-crypto
        description: Weak key rotation on the signing service
        owner: ` + owner + `
        level: moderate
        treatment: modify
        controls: [` + ctrlA51 + `]
        residual_level: low
        assessed_at: "2026-01-15"
`))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	reg, err := spec.LoadRiskRegister(&cfg)
	if err != nil {
		t.Fatalf("LoadRiskRegister: %v", err)
	}

	snap := buildSoASnapshotWithRisks(t, nil, reg.ControlRisks())

	var text, csvOut, jsonOut strings.Builder
	if err := report.FormatText(&text, snap); err != nil {
		t.Fatal(err)
	}
	if err := report.FormatCSV(&csvOut, snap); err != nil {
		t.Fatal(err)
	}
	if err := report.FormatJSON(&jsonOut, snap); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string]string{
		"text": text.String(), "csv": csvOut.String(), "json": jsonOut.String(),
	} {
		for _, forbidden := range []string{description, owner, rationale, approver} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s output leaked %q:\n%s", name, forbidden, body)
			}
		}
		// The ID must survive, or the traceability edge is gone.
		if !strings.Contains(body, "r-crypto") {
			t.Errorf("%s output dropped the risk id:\n%s", name, body)
		}
		// A retained risk names no control, so it must not appear at all.
		if strings.Contains(body, "r-payroll") {
			t.Errorf("%s output cited a risk that treats no control:\n%s", name, body)
		}
	}
}
