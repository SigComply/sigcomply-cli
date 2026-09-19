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

	// Instances is non-empty only for a fan-out entry (one catalog
	// entry, N folders — today, one per vendor in the project register).
	Instances []manualInstance `json:"instances"`
}

// manualInstance is one fan-out member's verdict. The plugin has
// already decided Satisfied; the evaluator's job is to turn N verdicts
// into one policy status plus the two counts that cross the aggregation
// boundary.
type manualInstance struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Required         bool     `json:"required"`
	Satisfied        bool     `json:"satisfied"`
	FilePresent      bool     `json:"file_present"`
	InTemporalWindow bool     `json:"in_temporal_window"`
	ExpectedURI      string   `json:"expected_uri"`
	ValidationFails  []string `json:"validation_failures"`
}

// evaluateManual implements Path A: the universal evidence presence check
// for evidence_mode: manual policies. It reads the record from the
// synthetic "_manual" slot and checks file_present, in_temporal_window,
// file_valid.
//
// The check logic:
//  1. No record at all → status=error (collector failed to run or
//     source not configured).
//  2. file_present=false → status=fail with a structured message that
//     includes the expected folder URI.
//  3. file_present=true, in_temporal_window=false → status=fail.
//  4. file_present=true, file_valid=false → status=fail with the
//     specific validation_failures listed. Unsupported file types,
//     conversion failures, and structural PDF errors all surface here.
//  5. All checks pass → status=pass.
func evaluateManual(slots map[string][]core.EvidenceRecord) core.RuleResult {
	records := slots[spec.ManualSlotName]
	if len(records) == 0 {
		return core.RuleResult{
			Status: core.StatusError,
			Diag:   map[string]any{diagReason: "manual evidence: no record collected (source not configured or collection failed)"},
		}
	}
	rec := records[0]
	var p manualPayload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return core.RuleResult{
			Status: core.StatusError,
			Diag:   map[string]any{diagReason: fmt.Sprintf("manual evidence: failed to parse collector record: %v", err)},
		}
	}

	if len(p.Instances) > 0 {
		return evaluateManualInstances(p.Instances)
	}

	if !p.FilePresent {
		msg := "manual evidence not found"
		if p.ExpectedURI != "" {
			msg = fmt.Sprintf("manual evidence not found; expected files in: %s", p.ExpectedURI)
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
				{ResourceID: rec.ID, Reason: fmt.Sprintf("manual evidence at %s was uploaded outside the configured temporal window", p.ExpectedURI)},
			},
		}
	}
	if !p.FileValid {
		msg := "manual evidence failed validation checks"
		if len(p.ValidationFails) > 0 {
			msg = fmt.Sprintf("manual evidence failed validation: %v", p.ValidationFails)
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

// evaluateManualInstances reduces a fan-out entry's per-instance
// verdicts to one policy result.
//
// The policy passes only when every *required* instance is satisfied —
// one missing vendor fails the control, which is the point of fanning
// out at all. Non-required instances are approved exemptions and count
// as satisfied; they are still listed in the signed record so the
// decision is auditable.
//
// Violations name the instance and stay vault-side. What crosses the
// aggregation boundary is Counts: how many instances were examined and
// how many came up short — never which ones. A vendor list is a set of
// third-party identifiers, and the non-custodial model does not put
// those on the wire.
func evaluateManualInstances(instances []manualInstance) core.RuleResult {
	var violations []core.Violation
	failed := 0

	for i := range instances {
		in := &instances[i]
		if in.Satisfied {
			continue
		}
		failed++
		violations = append(violations, core.Violation{
			ResourceID: in.ID,
			Reason:     manualInstanceReason(in),
		})
	}

	counts := &core.ResourceCounts{Evaluated: len(instances), Failed: failed}
	if failed == 0 {
		return core.RuleResult{Status: core.StatusPass, Counts: counts}
	}
	return core.RuleResult{
		Status:     core.StatusFail,
		Violations: violations,
		Counts:     counts,
		Diag: map[string]any{
			"instances_total":     len(instances),
			"instances_satisfied": len(instances) - failed,
		},
	}
}

// manualInstanceReason explains one unsatisfied instance, mirroring the
// single-folder check's ordering so the two read alike.
func manualInstanceReason(in *manualInstance) string {
	label := in.ID
	if in.Name != "" {
		label = fmt.Sprintf("%s (%s)", in.Name, in.ID)
	}
	switch {
	case !in.FilePresent:
		if in.ExpectedURI != "" {
			return fmt.Sprintf("%s: no evidence found; expected files in: %s", label, in.ExpectedURI)
		}
		return fmt.Sprintf("%s: no evidence found", label)
	case !in.InTemporalWindow:
		return fmt.Sprintf("%s: evidence at %s was uploaded outside the configured temporal window", label, in.ExpectedURI)
	case len(in.ValidationFails) > 0:
		return fmt.Sprintf("%s: evidence failed validation: %v", label, in.ValidationFails)
	default:
		return fmt.Sprintf("%s: evidence did not satisfy the requirement", label)
	}
}
