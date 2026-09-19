package aggregator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// A fan-out manual policy is the first check whose vault-side result
// carries third-party identifiers — the vendor slugs and names from the
// project's register. Invariant #1 says the wire learns how many
// vendors fell short and never which ones.
//
// The structural guard in core/cloud_test.go cannot catch a leak here:
// it is a *kind* guard, and a vendor name smuggled into the message
// string would be a perfectly ordinary string field. So this pins the
// behavior directly — marshal the real payload and search the bytes.
func TestBuild_FanOutVendorIdentifiersNeverReachTheWire(t *testing.T) {
	const (
		slug = "initech_pay"
		name = "Initech Payments"
	)

	results := []core.PolicyResult{{
		PolicyID: "soc2.cc9.2.vendor_assurance",
		Controls: []core.ControlRef{{
			Framework: testFrameworkSOC2, FrameworkVersion: testFrameworkVersionSOC2,
			ControlID: "CC9.2", Relationship: core.RelationshipEqual,
		}},
		Status:             core.StatusFail,
		Severity:           core.SeverityMedium,
		Category:           "governance",
		EvidenceMode:       core.EvidenceModeManual,
		ResourcesEvaluated: 3,
		ResourcesFailed:    1,
		Violations: []core.Violation{{
			ResourceID: slug,
			Reason:     name + " (" + slug + "): no evidence found; expected files in: s3://b/manual/vendor_assurance." + slug + "/2026-Q3/",
		}},
		Diag: map[string]any{"instances_total": 3, "instances_satisfied": 2},
	}}

	payload := Build(results, &Environment{
		RunID:     "run_1",
		Framework: testFrameworkSOC2,
		PeriodID:  "2026-Q3",
	})

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := string(raw)

	for _, forbidden := range []string{slug, name, "Initech", "manual/vendor_assurance", "s3://"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("submission payload leaked %q:\n%s", forbidden, body)
		}
	}

	// The counts must survive, or the collapse would have thrown away
	// the only thing the dashboard can legitimately show.
	if len(payload.Policies) != 1 {
		t.Fatalf("len(Policies) = %d; want 1", len(payload.Policies))
	}
	p := payload.Policies[0]
	if p.ResourcesEvaluated != 3 || p.ResourcesFailed != 1 {
		t.Fatalf("counts = %d/%d; want 3 evaluated, 1 failed", p.ResourcesEvaluated, p.ResourcesFailed)
	}
	if p.EvidenceMode != core.EvidenceModeManual {
		t.Fatalf("EvidenceMode = %q; want manual — the dashboard must be able to tell a folder of PDFs from a verified estate", p.EvidenceMode)
	}
	if !strings.Contains(p.Message, "1 of 3") {
		t.Fatalf("Message = %q; want a count-shaped summary", p.Message)
	}
}
