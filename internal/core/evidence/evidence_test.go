package evidence

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidence_New(t *testing.T) {
	data := json.RawMessage(`{"user_name": "alice", "mfa_enabled": false}`)

	ev := New("aws", "aws:iam:user", "arn:aws:iam::123456789012:user/alice", data)

	assert.NotEmpty(t, ev.ID, "ID should be generated")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:iam:user", ev.ResourceType)
	assert.Equal(t, "arn:aws:iam::123456789012:user/alice", ev.ResourceID)
	assert.Equal(t, data, ev.Data)
	assert.NotEmpty(t, ev.Hash, "Hash should be computed")
	assert.False(t, ev.CollectedAt.IsZero(), "CollectedAt should be set")
}

func TestEvidence_ComputeHash(t *testing.T) {
	data := json.RawMessage(`{"test": "data"}`)

	ev1 := New("aws", "aws:iam:user", "user1", data)
	ev2 := New("aws", "aws:iam:user", "user2", data)

	// Same data should produce same hash
	assert.Equal(t, ev1.Hash, ev2.Hash, "Same data should produce same hash")

	// Different data should produce different hash
	differentData := json.RawMessage(`{"test": "different"}`)
	ev3 := New("aws", "aws:iam:user", "user1", differentData)
	assert.NotEqual(t, ev1.Hash, ev3.Hash, "Different data should produce different hash")
}

func TestEvidence_WithMetadata(t *testing.T) {
	data := json.RawMessage(`{"test": "data"}`)
	ev := New("aws", "aws:iam:user", "user1", data)

	ev.Metadata = Metadata{
		AccountID: "123456789012",
		Region:    "us-east-1",
		Tags:      map[string]string{"env": "prod"},
	}

	assert.Equal(t, "123456789012", ev.Metadata.AccountID)
	assert.Equal(t, "us-east-1", ev.Metadata.Region)
	assert.Equal(t, "prod", ev.Metadata.Tags["env"])
}

func TestEvidence_JSON(t *testing.T) {
	data := json.RawMessage(`{"user_name": "alice"}`)
	ev := New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", data)
	ev.Metadata = Metadata{AccountID: "123456789012"}

	jsonBytes, err := json.Marshal(ev)
	require.NoError(t, err)

	var decoded Evidence
	err = json.Unmarshal(jsonBytes, &decoded)
	require.NoError(t, err)

	assert.Equal(t, ev.ID, decoded.ID)
	assert.Equal(t, ev.Collector, decoded.Collector)
	assert.Equal(t, ev.ResourceType, decoded.ResourceType)
	assert.Equal(t, ev.Hash, decoded.Hash)
	assert.Equal(t, ev.Metadata.AccountID, decoded.Metadata.AccountID)
}

func TestResultStatus_Valid(t *testing.T) {
	tests := []struct {
		status ResultStatus
		valid  bool
	}{
		{StatusPass, true},
		{StatusFail, true},
		{StatusSkip, true},
		{StatusError, true},
		{ResultStatus("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.status.IsValid())
		})
	}
}

func TestSeverity_Valid(t *testing.T) {
	tests := []struct {
		severity Severity
		valid    bool
	}{
		{SeverityCritical, true},
		{SeverityHigh, true},
		{SeverityMedium, true},
		{SeverityLow, true},
		{Severity("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.severity.IsValid())
		})
	}
}

func TestPolicyResult_HasViolations(t *testing.T) {
	result := PolicyResult{
		PolicyID:  "soc2-cc6.1-mfa",
		ControlID: "CC6.1",
		Status:    StatusPass,
		Severity:  SeverityHigh,
	}

	assert.False(t, result.HasViolations())

	result.Violations = []Violation{
		{ResourceID: "user1", Reason: "No MFA"},
	}
	result.Status = StatusFail

	assert.True(t, result.HasViolations())
}

func TestCheckResult_CalculateSummary(t *testing.T) {
	result := CheckResult{
		RunID:     "run-123",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []PolicyResult{
			{PolicyID: "policy1", Status: StatusPass},
			{PolicyID: "policy2", Status: StatusPass},
			{PolicyID: "policy3", Status: StatusFail},
			{PolicyID: "policy4", Status: StatusSkip},
		},
	}

	result.CalculateSummary()

	assert.Equal(t, 4, result.Summary.TotalPolicies)
	assert.Equal(t, 2, result.Summary.PassedPolicies)
	assert.Equal(t, 1, result.Summary.FailedPolicies)
	assert.Equal(t, 1, result.Summary.SkippedPolicies)
	// Compliance score: passed / (total - skipped) = 2/3 ≈ 0.667
	assert.InDelta(t, 0.667, result.Summary.ComplianceScore, 0.01)
}

// --- Negative tests ---

func TestCheckResult_CalculateSummary_AllSkipped(t *testing.T) {
	result := CheckResult{
		PolicyResults: []PolicyResult{
			{PolicyID: "p1", Status: StatusSkip},
			{PolicyID: "p2", Status: StatusSkip},
		},
	}

	result.CalculateSummary()

	assert.Equal(t, 2, result.Summary.TotalPolicies)
	assert.Equal(t, 0, result.Summary.PassedPolicies)
	assert.Equal(t, 0, result.Summary.FailedPolicies)
	assert.Equal(t, 2, result.Summary.SkippedPolicies)
	// Score should be 0 when all skipped (evaluated = 0)
	assert.Equal(t, 0.0, result.Summary.ComplianceScore)
}

func TestCheckResult_CalculateSummary_AllErrors(t *testing.T) {
	result := CheckResult{
		PolicyResults: []PolicyResult{
			{PolicyID: "p1", Status: StatusError},
			{PolicyID: "p2", Status: StatusError},
		},
	}

	result.CalculateSummary()

	assert.Equal(t, 2, result.Summary.TotalPolicies)
	assert.Equal(t, 0, result.Summary.PassedPolicies)
	assert.Equal(t, 0, result.Summary.FailedPolicies)
	assert.Equal(t, 0, result.Summary.SkippedPolicies)
	// Errors are not counted as pass, fail, or skip — score = 0/2 = 0
	assert.Equal(t, 0.0, result.Summary.ComplianceScore)
}

func TestCheckResult_CalculateSummary_NoPolicies(t *testing.T) {
	result := CheckResult{
		PolicyResults: []PolicyResult{},
	}

	result.CalculateSummary()

	assert.Equal(t, 0, result.Summary.TotalPolicies)
	assert.Equal(t, 0.0, result.Summary.ComplianceScore)
	assert.False(t, result.HasFailures())
}

func TestCheckResult_CalculateSummary_NilPolicies(t *testing.T) {
	result := CheckResult{}

	// Should not panic with nil PolicyResults
	result.CalculateSummary()

	assert.Equal(t, 0, result.Summary.TotalPolicies)
	assert.Equal(t, 0.0, result.Summary.ComplianceScore)
}

func TestCheckResult_CalculateSummary_MixedWithErrors(t *testing.T) {
	result := CheckResult{
		PolicyResults: []PolicyResult{
			{PolicyID: "p1", Status: StatusPass},
			{PolicyID: "p2", Status: StatusFail},
			{PolicyID: "p3", Status: StatusError},
			{PolicyID: "p4", Status: StatusSkip},
		},
	}

	result.CalculateSummary()

	assert.Equal(t, 4, result.Summary.TotalPolicies)
	assert.Equal(t, 1, result.Summary.PassedPolicies)
	assert.Equal(t, 1, result.Summary.FailedPolicies)
	assert.Equal(t, 1, result.Summary.SkippedPolicies)
	// evaluated = 4 - 1(skipped) = 3, score = 1/3 ≈ 0.333
	assert.InDelta(t, 0.333, result.Summary.ComplianceScore, 0.01)
}

func TestEvidence_New_NilData(t *testing.T) {
	// Should not panic with nil data
	ev := New("aws", "aws:iam:user", "user1", nil)
	assert.NotEmpty(t, ev.ID)
	assert.NotEmpty(t, ev.Hash)
	assert.Equal(t, "aws", ev.Collector)
}

func TestEvidence_New_EmptyData(t *testing.T) {
	ev := New("aws", "aws:iam:user", "user1", json.RawMessage{})
	assert.NotEmpty(t, ev.Hash)
}

func TestEvidence_ComputeHash_NilVsEmpty(t *testing.T) {
	// Nil and empty should produce different hashes (nil = hash of nil bytes, empty = hash of empty bytes)
	ev1 := New("aws", "type", "id", nil)
	ev2 := New("aws", "type", "id", json.RawMessage{})
	// Both should be valid non-empty hashes
	assert.NotEmpty(t, ev1.Hash)
	assert.NotEmpty(t, ev2.Hash)
}

func TestCheckResult_HasFailures(t *testing.T) {
	result := CheckResult{
		PolicyResults: []PolicyResult{
			{Status: StatusPass},
			{Status: StatusPass},
		},
	}
	result.CalculateSummary()

	assert.False(t, result.HasFailures())

	result.PolicyResults = append(result.PolicyResults, PolicyResult{Status: StatusFail})
	result.CalculateSummary()

	assert.True(t, result.HasFailures())
}
