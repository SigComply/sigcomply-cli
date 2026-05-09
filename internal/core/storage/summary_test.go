package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

func TestBuildSummary_SplitsManualAndAutomated(t *testing.T) {
	ts := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "run-12345678",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:           "soc2-cc6.1-mfa",
				ControlID:          "CC6.1",
				Name:               "MFA Required",
				Status:             evidence.StatusFail,
				Severity:           evidence.SeverityHigh,
				ResourceTypes:      []string{"aws:iam:user"},
				ResourcesEvaluated: 4,
				ResourcesFailed:    1,
			},
			{
				PolicyID:      "soc2-cc6.1-security-training",
				ControlID:     "CC6.1",
				Name:          "Security Training",
				Status:        evidence.StatusPass,
				Severity:      evidence.SeverityMedium,
				ResourceTypes: []string{"manual:cc6_1_training"},
			},
		},
	}
	result.CalculateSummary()

	manualPayload, err := json.Marshal(map[string]interface{}{
		"evidence_id": "cc6_1_training",
		"period":      "2026-Q2",
		"status":      "uploaded",
	})
	require.NoError(t, err)

	evidenceList := []evidence.Evidence{
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::1:user/alice", []byte(`{}`)),
		evidence.New("aws", "aws:iam:user", "arn:aws:iam::1:user/bob", []byte(`{}`)),
		evidence.New("manual", "manual:cc6_1_training", "cc6_1_training/2026-Q2", manualPayload),
	}

	sidecars := []ManualSidecar{{
		EvidenceID:   "cc6_1_training",
		Period:       "2026-Q2",
		ResourceType: "manual:cc6_1_training",
		EvidenceJSON: []byte(`{"completed_by":"alice@example.com","completed_at":"2026-04-15T09:00:00Z"}`),
	}}

	s := BuildSummary(result, evidenceList, sidecars)

	require.NotNil(t, s)
	assert.Equal(t, "1.0", s.SchemaVersion)
	assert.Equal(t, "soc2", s.Framework)
	assert.Equal(t, "run-12345678", s.LastRunID)
	assert.Equal(t, ts, s.LastRun)

	require.Len(t, s.Automated, 1)
	auto := s.Automated[0]
	assert.Equal(t, "soc2-cc6.1-mfa", auto.PolicyID)
	assert.Equal(t, "fail", auto.Status)
	assert.Equal(t, 4, auto.ResourcesEvaluated)
	assert.Equal(t, "collected", auto.Evidence.Status)
	assert.Equal(t, 2, auto.Evidence.Count)

	require.Len(t, s.Manual, 1)
	man := s.Manual[0]
	assert.Equal(t, "soc2-cc6.1-security-training", man.PolicyID)
	assert.Equal(t, "pass", man.Status)
	assert.Equal(t, "uploaded", man.Evidence.Status)
	assert.Equal(t, "cc6_1_training", man.Evidence.EvidenceID)
	assert.Equal(t, "2026-Q2", man.Evidence.Period)
	assert.Equal(t, "alice@example.com", man.Evidence.CompletedBy)
}

func TestBuildSummary_AutomatedEvidenceMissing(t *testing.T) {
	ts := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	result := &evidence.CheckResult{
		RunID:     "run-x",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{{
			PolicyID:      "soc2-cc6.1-mfa",
			ControlID:     "CC6.1",
			Status:        evidence.StatusSkip,
			Severity:      evidence.SeverityHigh,
			ResourceTypes: []string{"aws:iam:user"},
		}},
	}
	result.CalculateSummary()

	s := BuildSummary(result, nil, nil)

	require.Len(t, s.Automated, 1)
	assert.Equal(t, "missing", s.Automated[0].Evidence.Status)
	assert.Equal(t, 0, s.Automated[0].Evidence.Count)
}

func TestBuildSummary_ManualEvidenceNotUploaded(t *testing.T) {
	ts := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	notUploadedPayload, err := json.Marshal(map[string]interface{}{
		"evidence_id": "cc6_1_training",
		"period":      "2026-Q2",
		"status":      "not_uploaded",
	})
	require.NoError(t, err)

	result := &evidence.CheckResult{
		RunID:     "run-x",
		Framework: "soc2",
		Timestamp: ts,
		PolicyResults: []evidence.PolicyResult{{
			PolicyID:      "soc2-cc6.1-training",
			Status:        evidence.StatusFail,
			Severity:      evidence.SeverityMedium,
			ResourceTypes: []string{"manual:cc6_1_training"},
		}},
	}
	result.CalculateSummary()

	evidenceList := []evidence.Evidence{
		evidence.New("manual", "manual:cc6_1_training", "cc6_1_training/2026-Q2", notUploadedPayload),
	}

	s := BuildSummary(result, evidenceList, nil)

	require.Len(t, s.Manual, 1)
	assert.Equal(t, "not_uploaded", s.Manual[0].Evidence.Status)
}

func TestMergeSummary_PreservesPoliciesNotInCurrentRun(t *testing.T) {
	earlier := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	existing := &Summary{
		Framework: "soc2",
		Automated: []AutomatedPolicy{
			{PolicyID: "soc2-old-policy", Status: "pass", LastRun: earlier},
			{PolicyID: "soc2-cc6.1-mfa", Status: "fail", LastRun: earlier},
		},
		Manual: []ManualPolicy{
			{PolicyID: "soc2-cc6.1-training-old", Status: "pass", LastRun: earlier},
		},
	}

	current := &Summary{
		Framework:   "soc2",
		LastRun:     now,
		LastUpdated: now,
		Automated: []AutomatedPolicy{
			{PolicyID: "soc2-cc6.1-mfa", Status: "pass", LastRun: now}, // updated
		},
	}

	merged := MergeSummary(existing, current)

	require.Len(t, merged.Automated, 2, "kept untouched policy + updated one")
	statuses := map[string]string{}
	lastRuns := map[string]time.Time{}
	for _, p := range merged.Automated {
		statuses[p.PolicyID] = p.Status
		lastRuns[p.PolicyID] = p.LastRun
	}
	assert.Equal(t, "pass", statuses["soc2-cc6.1-mfa"], "current run wins for executed policy")
	assert.Equal(t, now, lastRuns["soc2-cc6.1-mfa"])
	assert.Equal(t, "pass", statuses["soc2-old-policy"], "untouched policy preserved")
	assert.Equal(t, earlier, lastRuns["soc2-old-policy"], "untouched last_run preserved")

	require.Len(t, merged.Manual, 1, "untouched manual policy preserved")
	assert.Equal(t, "soc2-cc6.1-training-old", merged.Manual[0].PolicyID)
}

func TestMergeSummary_NilExistingReturnsCurrent(t *testing.T) {
	current := &Summary{Framework: "soc2"}
	merged := MergeSummary(nil, current)
	assert.Same(t, current, merged)
}

func TestWriteSummary_RoundTripsViaBackend(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	require.NoError(t, backend.Init(context.Background()))

	ts := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	s := &Summary{
		SchemaVersion: "1.0",
		Framework:     "soc2",
		LastRun:       ts,
		LastRunID:     "run-1",
		LastUpdated:   ts,
		Automated: []AutomatedPolicy{{
			PolicyID: "soc2-cc6.1-mfa", Status: "pass", LastRun: ts,
		}},
	}

	require.NoError(t, WriteSummary(context.Background(), backend, s))

	loaded, err := LoadSummary(context.Background(), backend, "soc2")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "soc2", loaded.Framework)
	require.Len(t, loaded.Automated, 1)
	assert.Equal(t, "soc2-cc6.1-mfa", loaded.Automated[0].PolicyID)
}

func TestLoadSummary_ReturnsNilWhenMissing(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	require.NoError(t, backend.Init(context.Background()))

	loaded, err := LoadSummary(context.Background(), backend, "soc2")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestWriteSummary_MergesWithExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	backend := NewLocalBackend(&LocalConfig{Path: tmpDir})
	require.NoError(t, backend.Init(context.Background()))

	earlier := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	first := &Summary{
		SchemaVersion: "1.0",
		Framework:     "soc2",
		LastRun:       earlier,
		LastRunID:     "run-old",
		LastUpdated:   earlier,
		Automated: []AutomatedPolicy{
			{PolicyID: "soc2-old", Status: "pass", LastRun: earlier},
			{PolicyID: "soc2-mfa", Status: "fail", LastRun: earlier},
		},
	}
	require.NoError(t, WriteSummary(context.Background(), backend, first))

	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	second := &Summary{
		SchemaVersion: "1.0",
		Framework:     "soc2",
		LastRun:       now,
		LastRunID:     "run-new",
		LastUpdated:   now,
		Automated: []AutomatedPolicy{
			{PolicyID: "soc2-mfa", Status: "pass", LastRun: now},
		},
	}
	require.NoError(t, WriteSummary(context.Background(), backend, second))

	loaded, err := LoadSummary(context.Background(), backend, "soc2")
	require.NoError(t, err)

	assert.Equal(t, "run-new", loaded.LastRunID, "top-level state from latest run")
	require.Len(t, loaded.Automated, 2, "preserved untouched policy from earlier run")

	statuses := map[string]string{}
	for _, p := range loaded.Automated {
		statuses[p.PolicyID] = p.Status
	}
	assert.Equal(t, "pass", statuses["soc2-mfa"], "current run wins")
	assert.Equal(t, "pass", statuses["soc2-old"], "untouched policy preserved")
}
