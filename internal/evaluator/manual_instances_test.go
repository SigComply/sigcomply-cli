package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// The fan-out payload keys read by the manual instances path, plus a
// fixture member id.
const (
	keyInstances = "instances"
	keyRequired  = "required"
	keySatisfied = "satisfied"

	testVendorInitech = "initech"
)

// manualInstanceSlots wraps a fan-out payload in the synthetic slot the
// manual path reads.
func manualInstanceSlots(t *testing.T, payload map[string]any) map[string][]core.EvidenceRecord {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return map[string][]core.EvidenceRecord{
		spec.ManualSlotName: {{
			Type:    "signed_document",
			ID:      "vendor_assurance/2026-Q1",
			Payload: b,
		}},
	}
}

func TestEvaluateManual_Instances_AllSatisfiedPasses(t *testing.T) {
	slots := manualInstanceSlots(t, map[string]any{
		keyInstances: []map[string]any{
			{"id": "acme", keyName: "Acme", keyRequired: true, keySatisfied: true},
			{"id": "zeta", keyName: "Zeta", keyRequired: false, keySatisfied: true},
		},
	})
	got := evaluateManual(slots)
	if got.Status != core.StatusPass {
		t.Fatalf("Status = %v; want pass", got.Status)
	}
	if got.Counts == nil || got.Counts.Evaluated != 2 || got.Counts.Failed != 0 {
		t.Fatalf("Counts = %+v; want 2 evaluated, 0 failed", got.Counts)
	}
}

// One unsatisfied vendor fails the control. That is the whole reason to
// fan out: a single consolidated folder could not express it.
func TestEvaluateManual_Instances_OneMissingFails(t *testing.T) {
	slots := manualInstanceSlots(t, map[string]any{
		keyInstances: []map[string]any{
			{"id": "acme", keyName: "Acme", keyRequired: true, keySatisfied: true, keyFilePresent: true, keyInTemporalWindow: true},
			{"id": testVendorInitech, keyName: "Initech", keyRequired: true, keySatisfied: false,
				keyFilePresent: false, keyExpectedURI: "s3://b/manual/vendor_assurance.initech/2026-Q1/"},
			{"id": "zeta", keyRequired: false, keySatisfied: true},
		},
	})
	got := evaluateManual(slots)
	if got.Status != core.StatusFail {
		t.Fatalf("Status = %v; want fail", got.Status)
	}
	if got.Counts.Evaluated != 3 || got.Counts.Failed != 1 {
		t.Fatalf("Counts = %+v; want 3 evaluated, 1 failed", got.Counts)
	}
	if len(got.Violations) != 1 || got.Violations[0].ResourceID != testVendorInitech {
		t.Fatalf("Violations = %+v", got.Violations)
	}
	if !strings.Contains(got.Violations[0].Reason, "vendor_assurance.initech") {
		t.Fatalf("violation should name the folder: %q", got.Violations[0].Reason)
	}
}

func TestEvaluateManual_Instances_ReasonsMatchFailureKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		inst map[string]any
		want string
	}{
		{
			name: "absent",
			inst: map[string]any{"id": "a", keyRequired: true, keySatisfied: false, keyFilePresent: false},
			want: "no evidence found",
		},
		{
			name: "outside window",
			inst: map[string]any{"id": "a", keyRequired: true, keySatisfied: false,
				keyFilePresent: true, keyInTemporalWindow: false},
			want: "outside the configured temporal window",
		},
		{
			name: "validation failure",
			inst: map[string]any{"id": "a", keyRequired: true, keySatisfied: false,
				keyFilePresent: true, keyInTemporalWindow: true,
				"validation_failures": []string{"assurance_out_of_date (declared coverage ended 2020-01-01)"}},
			want: "assurance_out_of_date",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateManual(manualInstanceSlots(t, map[string]any{
				keyInstances: []map[string]any{tc.inst},
			}))
			if got.Status != core.StatusFail {
				t.Fatalf("Status = %v; want fail", got.Status)
			}
			if !strings.Contains(got.Violations[0].Reason, tc.want) {
				t.Fatalf("Reason = %q; want it to mention %q", got.Violations[0].Reason, tc.want)
			}
		})
	}
}

// Invariant #1. Vendor names are third-party identifiers; the wire may
// learn how many vendors fell short, never which ones. The evaluator is
// where that reduction happens, so it is where it must be pinned.
func TestEvaluateManual_Instances_NamesStayOutOfTheCounts(t *testing.T) {
	slots := manualInstanceSlots(t, map[string]any{
		keyInstances: []map[string]any{
			{"id": "acme_cloud", keyName: "Acme Cloud", keyRequired: true, keySatisfied: false, keyFilePresent: false},
			{"id": testVendorInitech, keyName: "Initech", keyRequired: true, keySatisfied: true},
		},
	})
	got := evaluateManual(slots)

	// The counts are the only thing the aggregator promotes to the
	// payload; they are pure integers by construction.
	if got.Counts.Evaluated != 2 || got.Counts.Failed != 1 {
		t.Fatalf("Counts = %+v", got.Counts)
	}
	// Diag is vault-side but let's keep it count-shaped too, so a
	// future change that starts persisting it cannot leak a name.
	for k, v := range got.Diag {
		if s, ok := v.(string); ok && (strings.Contains(s, "Acme") || strings.Contains(s, "acme_cloud")) {
			t.Fatalf("Diag[%q] leaked a vendor identifier: %q", k, s)
		}
	}
}

// A fan-out payload with an empty instances list must fall through to
// the single-folder checks rather than vacuously passing.
func TestEvaluateManual_EmptyInstancesUsesSingleFolderPath(t *testing.T) {
	slots := manualInstanceSlots(t, map[string]any{
		keyInstances:   []map[string]any{},
		keyFilePresent: false,
		keyExpectedURI: "s3://b/manual/vendor_assurance/2026-Q1/",
	})
	got := evaluateManual(slots)
	if got.Status != core.StatusFail {
		t.Fatalf("Status = %v; want fail via the single-folder path", got.Status)
	}
	if got.Counts != nil {
		t.Fatalf("Counts = %+v; want nil so the record arithmetic applies", got.Counts)
	}
}
