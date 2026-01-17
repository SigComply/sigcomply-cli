package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

func TestTextFormatter_FormatPolicyResult_Pass(t *testing.T) {
	result := evidence.PolicyResult{
		PolicyID:           "soc2-cc6.1-mfa",
		ControlID:          "CC6.1",
		Status:             evidence.StatusPass,
		Severity:           evidence.SeverityHigh,
		Message:            "All resources compliant",
		ResourcesEvaluated: 5,
		ResourcesFailed:    0,
		Violations:         []evidence.Violation{},
	}

	var buf bytes.Buffer
	formatter := NewTextFormatter(&buf)
	err := formatter.FormatPolicyResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "PASS")
	assert.Contains(t, output, "CC6.1")
	assert.Contains(t, output, "soc2-cc6.1-mfa")
}

func TestTextFormatter_FormatPolicyResult_Fail(t *testing.T) {
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
	formatter := NewTextFormatter(&buf)
	err := formatter.FormatPolicyResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "FAIL")
	assert.Contains(t, output, "CC6.1")
	assert.Contains(t, output, "alice")
	assert.Contains(t, output, "MFA")
}

func TestTextFormatter_FormatPolicyResult_Skip(t *testing.T) {
	result := evidence.PolicyResult{
		PolicyID:           "soc2-cc6.1-mfa",
		ControlID:          "CC6.1",
		Status:             evidence.StatusSkip,
		Severity:           evidence.SeverityHigh,
		Message:            "No matching resources to evaluate",
		ResourcesEvaluated: 0,
		ResourcesFailed:    0,
	}

	var buf bytes.Buffer
	formatter := NewTextFormatter(&buf)
	err := formatter.FormatPolicyResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SKIP")
	assert.Contains(t, output, "CC6.1")
}

func TestTextFormatter_FormatCheckResult(t *testing.T) {
	checkResult := &evidence.CheckResult{
		Framework: "soc2",
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
	formatter := NewTextFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Policy Evaluation")
	assert.Contains(t, output, "PASS")
	assert.Contains(t, output, "FAIL")
	assert.Contains(t, output, "Summary")
	assert.Contains(t, output, "1 passed")
	assert.Contains(t, output, "1 failed")
}

func TestTextFormatter_FormatSummary(t *testing.T) {
	summary := evidence.CheckSummary{
		TotalPolicies:   5,
		PassedPolicies:  3,
		FailedPolicies:  1,
		SkippedPolicies: 1,
		ComplianceScore: 0.75,
	}

	var buf bytes.Buffer
	formatter := NewTextFormatter(&buf)
	err := formatter.FormatSummary(summary)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "3 passed")
	assert.Contains(t, output, "1 failed")
	assert.Contains(t, output, "1 skipped")
	assert.Contains(t, output, "75")
}

func TestTextFormatter_StatusIcon(t *testing.T) {
	tests := []struct {
		status   evidence.ResultStatus
		expected string
	}{
		{evidence.StatusPass, "PASS"},
		{evidence.StatusFail, "FAIL"},
		{evidence.StatusSkip, "SKIP"},
		{evidence.StatusError, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			icon := statusText(tt.status)
			assert.Contains(t, icon, tt.expected)
		})
	}
}

func TestTextFormatter_SeverityText(t *testing.T) {
	tests := []struct {
		severity evidence.Severity
		expected string
	}{
		{evidence.SeverityCritical, "critical"},
		{evidence.SeverityHigh, "high"},
		{evidence.SeverityMedium, "medium"},
		{evidence.SeverityLow, "low"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			text := severityText(tt.severity)
			assert.Contains(t, text, tt.expected)
		})
	}
}
