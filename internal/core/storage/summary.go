package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

const (
	summaryFilename      = "summary.json"
	summarySchemaVersion = "1.0"
)

// Summary is the framework-level snapshot persisted at {framework}/summary.json.
// It is per-policy by design so an auditor can see, in one file, which policies
// passed and what evidence backed each result — without crawling per-run folders.
//
// Policies executed in this run overwrite their entries; policies not in this
// run are preserved from the previous summary so a filtered re-run does not
// erase known state.
type Summary struct {
	SchemaVersion string            `json:"schema_version"`
	Framework     string            `json:"framework"`
	LastRun       time.Time         `json:"last_run"`
	LastRunID     string            `json:"last_run_id"`
	LastUpdated   time.Time         `json:"last_updated"`
	Totals        SummaryTotals     `json:"totals"`
	Automated     []AutomatedPolicy `json:"automated"`
	Manual        []ManualPolicy    `json:"manual"`
}

// SummaryTotals aggregates policy outcomes across both automated and manual.
type SummaryTotals struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

// AutomatedPolicy is a per-policy entry whose evidence comes from API collectors.
type AutomatedPolicy struct {
	PolicyID           string                 `json:"policy_id"`
	ControlID          string                 `json:"control_id"`
	Name               string                 `json:"name"`
	Severity           string                 `json:"severity"`
	Status             string                 `json:"status"`
	ResourcesEvaluated int                    `json:"resources_evaluated"`
	ResourcesFailed    int                    `json:"resources_failed"`
	LastRun            time.Time              `json:"last_run"`
	Evidence           AutomatedEvidenceState `json:"evidence"`
}

// AutomatedEvidenceState describes what API-collected evidence backed the policy.
type AutomatedEvidenceState struct {
	Status        string   `json:"status"` // "collected" | "missing"
	ResourceTypes []string `json:"resource_types"`
	Count         int      `json:"count"`
}

// ManualPolicy is a per-policy entry backed by user-uploaded evidence.
type ManualPolicy struct {
	PolicyID  string              `json:"policy_id"`
	ControlID string              `json:"control_id"`
	Name      string              `json:"name"`
	Severity  string              `json:"severity"`
	Status    string              `json:"status"`
	LastRun   time.Time           `json:"last_run"`
	Evidence  ManualEvidenceState `json:"evidence"`
}

// ManualEvidenceState describes the user-uploaded evidence backing a manual policy.
type ManualEvidenceState struct {
	Status      string    `json:"status"` // "uploaded" | "not_uploaded"
	EvidenceID  string    `json:"evidence_id,omitempty"`
	Period      string    `json:"period,omitempty"`
	CompletedBy string    `json:"completed_by,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// BuildSummary computes a Summary from the just-completed run. It does not
// read prior state — call MergeSummary or WriteSummary to preserve history.
func BuildSummary(result *evidence.CheckResult, evidenceList []evidence.Evidence,
	sidecars []ManualSidecar) *Summary {
	manualMeta := indexManualMetadata(evidenceList, sidecars)

	s := &Summary{
		SchemaVersion: summarySchemaVersion,
		Framework:     result.Framework,
		LastRun:       result.Timestamp,
		LastRunID:     result.RunID,
		LastUpdated:   result.Timestamp,
		Totals: SummaryTotals{
			Total:   result.Summary.TotalPolicies,
			Passed:  result.Summary.PassedPolicies,
			Failed:  result.Summary.FailedPolicies,
			Skipped: result.Summary.SkippedPolicies,
		},
	}

	for i := range result.PolicyResults {
		pr := &result.PolicyResults[i]
		if isManualPolicy(pr.ResourceTypes) {
			s.Manual = append(s.Manual, buildManualPolicy(pr, manualMeta, result.Timestamp))
		} else {
			s.Automated = append(s.Automated, buildAutomatedPolicy(pr, evidenceList, result.Timestamp))
		}
	}

	return s
}

// MergeSummary returns a new Summary that takes top-level fields and totals
// from current, but preserves entries from existing for any policy_id not
// present in current. This keeps last-known state for filtered-out policies.
func MergeSummary(existing, current *Summary) *Summary {
	if existing == nil {
		return current
	}

	merged := *current

	currentManual := make(map[string]bool, len(current.Manual))
	for i := range current.Manual {
		currentManual[current.Manual[i].PolicyID] = true
	}
	for i := range existing.Manual {
		if !currentManual[existing.Manual[i].PolicyID] {
			merged.Manual = append(merged.Manual, existing.Manual[i])
		}
	}

	currentAuto := make(map[string]bool, len(current.Automated))
	for i := range current.Automated {
		currentAuto[current.Automated[i].PolicyID] = true
	}
	for i := range existing.Automated {
		if !currentAuto[existing.Automated[i].PolicyID] {
			merged.Automated = append(merged.Automated, existing.Automated[i])
		}
	}

	return &merged
}

// LoadSummary reads {framework}/summary.json from the backend. Returns (nil, nil)
// when no summary exists yet — callers treat that as a first-write case.
func LoadSummary(ctx context.Context, backend Backend, framework string) (*Summary, error) {
	data, err := backend.Get(ctx, framework+"/"+summaryFilename)
	if err != nil {
		var notFound *NotFoundError
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("read summary: %w", err)
	}
	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse summary: %w", err)
	}
	return &s, nil
}

// WriteSummary loads the existing summary (if any), merges current into it
// to preserve per-policy state for policies not in this run, and persists
// the result to {framework}/summary.json.
func WriteSummary(ctx context.Context, backend Backend, current *Summary) error {
	existing, err := LoadSummary(ctx, backend, current.Framework)
	if err != nil {
		return err
	}
	merged := MergeSummary(existing, current)

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}

	path := merged.Framework + "/" + summaryFilename
	if _, err := backend.StoreRaw(ctx, path, data, map[string]string{
		"type":      "framework_summary",
		"framework": merged.Framework,
	}); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}

func isManualPolicy(resourceTypes []string) bool {
	for _, rt := range resourceTypes {
		if strings.HasPrefix(rt, "manual:") {
			return true
		}
	}
	return false
}

// manualMetadataEntry caches the user-submitted fields we surface in the summary.
type manualMetadataEntry struct {
	EvidenceID  string
	Period      string
	Uploaded    bool
	CompletedBy string
	CompletedAt time.Time
}

// indexManualMetadata maps "manual:<id>" → metadata pulled from the OPA evidence
// payload (status, period) and the sidecar (completed_by, completed_at).
func indexManualMetadata(evidenceList []evidence.Evidence, sidecars []ManualSidecar) map[string]manualMetadataEntry {
	out := make(map[string]manualMetadataEntry)

	for i := range evidenceList {
		ev := &evidenceList[i]
		if !strings.HasPrefix(ev.ResourceType, "manual:") {
			continue
		}
		var payload struct {
			EvidenceID string `json:"evidence_id"`
			Period     string `json:"period"`
			Status     string `json:"status"`
		}
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			continue
		}
		out[ev.ResourceType] = manualMetadataEntry{
			EvidenceID: payload.EvidenceID,
			Period:     payload.Period,
			Uploaded:   payload.Status == "uploaded",
		}
	}

	for i := range sidecars {
		sc := &sidecars[i]
		var submitted struct {
			CompletedBy string    `json:"completed_by"`
			CompletedAt time.Time `json:"completed_at"`
		}
		if err := json.Unmarshal(sc.EvidenceJSON, &submitted); err != nil {
			continue
		}
		entry := out[sc.ResourceType]
		if entry.EvidenceID == "" {
			entry.EvidenceID = sc.EvidenceID
		}
		if entry.Period == "" {
			entry.Period = sc.Period
		}
		entry.Uploaded = true
		entry.CompletedBy = submitted.CompletedBy
		entry.CompletedAt = submitted.CompletedAt
		out[sc.ResourceType] = entry
	}

	return out
}

func buildManualPolicy(pr *evidence.PolicyResult, manualMeta map[string]manualMetadataEntry, ts time.Time) ManualPolicy {
	mp := ManualPolicy{
		PolicyID:  pr.PolicyID,
		ControlID: pr.ControlID,
		Name:      pr.Name,
		Severity:  string(pr.Severity),
		Status:    string(pr.Status),
		LastRun:   ts,
	}

	for _, rt := range pr.ResourceTypes {
		if !strings.HasPrefix(rt, "manual:") {
			continue
		}
		meta := manualMeta[rt]
		mp.Evidence = ManualEvidenceState{
			EvidenceID:  meta.EvidenceID,
			Period:      meta.Period,
			CompletedBy: meta.CompletedBy,
			CompletedAt: meta.CompletedAt,
		}
		if meta.Uploaded {
			mp.Evidence.Status = "uploaded"
		} else {
			mp.Evidence.Status = "not_uploaded"
		}
		break
	}

	return mp
}

func buildAutomatedPolicy(pr *evidence.PolicyResult, evidenceList []evidence.Evidence, ts time.Time) AutomatedPolicy {
	count := 0
	wanted := make(map[string]bool, len(pr.ResourceTypes))
	for _, rt := range pr.ResourceTypes {
		wanted[rt] = true
	}
	for i := range evidenceList {
		if wanted[evidenceList[i].ResourceType] {
			count++
		}
	}

	state := AutomatedEvidenceState{
		ResourceTypes: pr.ResourceTypes,
		Count:         count,
	}
	if count > 0 {
		state.Status = "collected"
	} else {
		state.Status = "missing"
	}

	return AutomatedPolicy{
		PolicyID:           pr.PolicyID,
		ControlID:          pr.ControlID,
		Name:               pr.Name,
		Severity:           string(pr.Severity),
		Status:             string(pr.Status),
		ResourcesEvaluated: pr.ResourcesEvaluated,
		ResourcesFailed:    pr.ResourcesFailed,
		LastRun:            ts,
		Evidence:           state,
	}
}
