package evaluator

import (
	"encoding/json"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// manualPayload mirrors the JSON shape emitted by the manual.pdf plugin.
// Only the fields the evaluator inspects are declared here; others are
// ignored via json.Unmarshal's normal behavior.
type manualPayload struct {
	FilePresent      bool     `json:"file_present"`
	InTemporalWindow bool     `json:"in_temporal_window"`
	FileValid        bool     `json:"file_valid"`
	ExpectedURI      string   `json:"expected_uri"`
	ValidationFails  []string `json:"validation_failures"`
}

// evaluateManual implements Path A: the universal PDF presence check for
// evidence_mode: manual policies. It reads the record from the synthetic
// "_manual" slot and checks file_present, in_temporal_window, file_valid.
//
// The check logic:
//  1. No record at all → status=error (collector failed to run or
//     source not configured).
//  2. file_present=false → status=fail with a structured message that
//     includes the expected URI.
//  3. file_present=true, in_temporal_window=false → status=fail.
//  4. file_present=true, file_valid=false → status=fail with the
//     specific validation_failures listed.
//  5. All checks pass → status=pass.
func evaluateManual(slots map[string][]core.EvidenceRecord) core.RuleResult {
	records := slots[spec.ManualSlotName]
	if len(records) == 0 {
		return core.RuleResult{
			Status: core.StatusError,
			Diag:   map[string]any{"reason": "manual evidence: no record collected (source not configured or collection failed)"},
		}
	}
	rec := records[0]
	var p manualPayload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return core.RuleResult{
			Status: core.StatusError,
			Diag:   map[string]any{"reason": fmt.Sprintf("manual evidence: failed to parse collector record: %v", err)},
		}
	}

	if !p.FilePresent {
		msg := "manual evidence PDF not found"
		if p.ExpectedURI != "" {
			msg = fmt.Sprintf("manual evidence PDF not found; expected at: %s", p.ExpectedURI)
		}
		return core.RuleResult{
			Status: core.StatusFail,
			Violations: []core.Violation{
				{ResourceID: rec.ID, Reason: msg},
			},
		}
	}
	if !p.InTemporalWindow {
		return core.RuleResult{
			Status: core.StatusFail,
			Violations: []core.Violation{
				{ResourceID: rec.ID, Reason: fmt.Sprintf("manual evidence PDF at %s was uploaded outside the configured temporal window", p.ExpectedURI)},
			},
		}
	}
	if !p.FileValid {
		msg := "manual evidence PDF failed validation checks"
		if len(p.ValidationFails) > 0 {
			msg = fmt.Sprintf("manual evidence PDF failed validation: %v", p.ValidationFails)
		}
		return core.RuleResult{
			Status: core.StatusFail,
			Violations: []core.Violation{
				{ResourceID: rec.ID, Reason: msg},
			},
		}
	}
	return core.RuleResult{Status: core.StatusPass}
}
