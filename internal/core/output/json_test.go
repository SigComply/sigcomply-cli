package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

func TestJSONFormatter_FormatCheckResult(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "test-run-123",
		Framework: "soc2",
		Timestamp: time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:           "soc2-cc6.1-mfa",
				ControlID:          "CC6.1",
				Status:             evidence.StatusPass,
				Severity:           evidence.SeverityHigh,
				Message:            "All resources compliant",
				ResourcesEvaluated: 3,
				ResourcesFailed:    0,
			},
			{
				PolicyID:           "soc2-cc6.2-encryption",
				ControlID:          "CC6.2",
				Status:             evidence.StatusFail,
				Severity:           evidence.SeverityMedium,
				Message:            "1 violation(s) found",
				ResourcesEvaluated: 2,
				ResourcesFailed:    1,
				Violations: []evidence.Violation{
					{
						ResourceID:   "arn:aws:s3:::my-bucket",
						ResourceType: "aws:s3:bucket",
						Reason:       "S3 bucket 'my-bucket' does not have encryption enabled",
					},
				},
			},
		},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	// Verify it's valid JSON
	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	// Verify structure
	assert.Equal(t, "soc2", result["framework"])
	assert.Equal(t, "test-run-123", result["run_id"])

	// Verify policy results
	policyResults, ok := result["policy_results"].([]interface{})
	require.True(t, ok)
	assert.Len(t, policyResults, 2)

	// Verify summary
	summary, ok := result["summary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(2), summary["total_policies"])
	assert.Equal(t, float64(1), summary["passed_policies"])
	assert.Equal(t, float64(1), summary["failed_policies"])
}

func TestJSONFormatter_FormatCheckResult_WithEvidence(t *testing.T) {
	evidenceData := []byte(`{"user_name":"alice","mfa_enabled":true}`)
	ev := evidence.New("aws", "aws:iam:user", "arn:aws:iam::123:user/alice", evidenceData)

	checkResult := &evidence.CheckResult{
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:           "soc2-cc6.1-mfa",
				ControlID:          "CC6.1",
				Status:             evidence.StatusPass,
				Severity:           evidence.SeverityHigh,
				ResourcesEvaluated: 1,
			},
		},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)
	formatter.WithEvidence([]evidence.Evidence{ev})
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	// Verify it's valid JSON with evidence
	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	evidenceList, ok := result["evidence"].([]interface{})
	require.True(t, ok)
	assert.Len(t, evidenceList, 1)
}

func TestJSONFormatter_FormatCheckResult_Compact(t *testing.T) {
	checkResult := &evidence.CheckResult{
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "soc2-cc6.1-mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusPass,
			},
		},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)
	formatter.SetCompact(true)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	// Compact JSON should not have newlines (except possibly at the end)
	output := buf.String()
	// Count newlines - compact should have at most 1 (trailing)
	newlineCount := 0
	for _, c := range output {
		if c == '\n' {
			newlineCount++
		}
	}
	assert.LessOrEqual(t, newlineCount, 1, "Compact JSON should have minimal newlines")
}

func TestJSONFormatter_FormatPolicyResult(t *testing.T) {
	result := evidence.PolicyResult{
		PolicyID:           "soc2-cc6.1-mfa",
		ControlID:          "CC6.1",
		Status:             evidence.StatusFail,
		Severity:           evidence.SeverityHigh,
		Message:            "1 violation(s) found",
		ResourcesEvaluated: 5,
		ResourcesFailed:    1,
		Violations: []evidence.Violation{
			{
				ResourceID:   "arn:aws:iam::123456789012:user/alice",
				ResourceType: "aws:iam:user",
				Reason:       "IAM user 'alice' does not have MFA enabled",
			},
		},
	}

	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)
	err := formatter.FormatPolicyResult(result)
	require.NoError(t, err)

	// Verify it's valid JSON
	var parsed evidence.PolicyResult
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "soc2-cc6.1-mfa", parsed.PolicyID)
	assert.Equal(t, evidence.StatusFail, parsed.Status)
	assert.Len(t, parsed.Violations, 1)
}

func TestJSONFormatter_FormatSummary(t *testing.T) {
	summary := evidence.CheckSummary{
		TotalPolicies:   5,
		PassedPolicies:  3,
		FailedPolicies:  1,
		SkippedPolicies: 1,
		ComplianceScore: 0.75,
	}

	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)
	err := formatter.FormatSummary(summary)
	require.NoError(t, err)

	// Verify it's valid JSON
	var parsed evidence.CheckSummary
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, 5, parsed.TotalPolicies)
	assert.Equal(t, 3, parsed.PassedPolicies)
	assert.Equal(t, 0.75, parsed.ComplianceScore)
}
