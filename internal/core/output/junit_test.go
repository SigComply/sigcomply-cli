package output

import (
	"bytes"
	"encoding/xml"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

func TestJUnitFormatter_FormatCheckResult(t *testing.T) {
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
	formatter := NewJUnitFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	// Verify it's valid XML
	var testsuites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &testsuites)
	require.NoError(t, err)

	// Verify structure
	require.Len(t, testsuites.Suites, 1)
	suite := testsuites.Suites[0]
	assert.Equal(t, "soc2", suite.Name)
	assert.Equal(t, 2, suite.Tests)
	assert.Equal(t, 1, suite.Failures)
	assert.Equal(t, 0, suite.Errors)
	assert.Equal(t, 0, suite.Skipped)

	// Verify test cases
	require.Len(t, suite.TestCases, 2)

	// First test case (pass)
	assert.Equal(t, "soc2-cc6.1-mfa", suite.TestCases[0].Name)
	assert.Equal(t, "CC6.1", suite.TestCases[0].ClassName)
	assert.Nil(t, suite.TestCases[0].Failure)

	// Second test case (fail)
	assert.Equal(t, "soc2-cc6.2-encryption", suite.TestCases[1].Name)
	assert.Equal(t, "CC6.2", suite.TestCases[1].ClassName)
	require.NotNil(t, suite.TestCases[1].Failure)
	assert.Contains(t, suite.TestCases[1].Failure.Message, "1 violation(s) found")
	assert.Contains(t, suite.TestCases[1].Failure.Content, "my-bucket")
}

func TestJUnitFormatter_FormatCheckResult_AllPassing(t *testing.T) {
	checkResult := &evidence.CheckResult{
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "soc2-cc6.1-mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusPass,
				Message:   "All resources compliant",
			},
			{
				PolicyID:  "soc2-cc6.2-encryption",
				ControlID: "CC6.2",
				Status:    evidence.StatusPass,
				Message:   "All resources compliant",
			},
		},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJUnitFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	var testsuites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &testsuites)
	require.NoError(t, err)

	suite := testsuites.Suites[0]
	assert.Equal(t, 2, suite.Tests)
	assert.Equal(t, 0, suite.Failures)
	assert.Equal(t, 0, suite.Errors)

	// All test cases should have no failure
	for _, tc := range suite.TestCases {
		assert.Nil(t, tc.Failure)
	}
}

func TestJUnitFormatter_FormatCheckResult_WithSkipped(t *testing.T) {
	checkResult := &evidence.CheckResult{
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "soc2-cc6.1-mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusPass,
			},
			{
				PolicyID:  "soc2-cc7.1-logging",
				ControlID: "CC7.1",
				Status:    evidence.StatusSkip,
				Message:   "No matching resources to evaluate",
			},
		},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJUnitFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	var testsuites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &testsuites)
	require.NoError(t, err)

	suite := testsuites.Suites[0]
	assert.Equal(t, 2, suite.Tests)
	assert.Equal(t, 1, suite.Skipped)

	// Find the skipped test case
	var skippedCase *junitTestCase
	for i := range suite.TestCases {
		if suite.TestCases[i].Name == "soc2-cc7.1-logging" {
			skippedCase = &suite.TestCases[i]
			break
		}
	}
	require.NotNil(t, skippedCase)
	require.NotNil(t, skippedCase.Skipped)
	assert.Contains(t, skippedCase.Skipped.Message, "No matching resources")
}

func TestJUnitFormatter_FormatCheckResult_WithError(t *testing.T) {
	checkResult := &evidence.CheckResult{
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "soc2-cc6.1-mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusError,
				Message:   "Policy evaluation error: timeout",
			},
		},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJUnitFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	var testsuites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &testsuites)
	require.NoError(t, err)

	suite := testsuites.Suites[0]
	assert.Equal(t, 1, suite.Tests)
	assert.Equal(t, 1, suite.Errors)

	require.NotNil(t, suite.TestCases[0].Error)
	assert.Contains(t, suite.TestCases[0].Error.Message, "timeout")
}

func TestJUnitFormatter_FormatCheckResult_MultipleViolations(t *testing.T) {
	checkResult := &evidence.CheckResult{
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:           "soc2-cc6.1-mfa",
				ControlID:          "CC6.1",
				Status:             evidence.StatusFail,
				Message:            "2 violation(s) found",
				ResourcesEvaluated: 3,
				ResourcesFailed:    2,
				Violations: []evidence.Violation{
					{
						ResourceID:   "arn:aws:iam::123456789012:user/alice",
						ResourceType: "aws:iam:user",
						Reason:       "User alice does not have MFA enabled",
					},
					{
						ResourceID:   "arn:aws:iam::123456789012:user/bob",
						ResourceType: "aws:iam:user",
						Reason:       "User bob does not have MFA enabled",
					},
				},
			},
		},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJUnitFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	var testsuites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &testsuites)
	require.NoError(t, err)

	tc := testsuites.Suites[0].TestCases[0]
	require.NotNil(t, tc.Failure)

	// Verify both violations are in the failure content
	assert.Contains(t, tc.Failure.Content, "alice")
	assert.Contains(t, tc.Failure.Content, "bob")
}

func TestJUnitFormatter_XMLDeclaration(t *testing.T) {
	checkResult := &evidence.CheckResult{
		Framework:     "soc2",
		Timestamp:     time.Now(),
		PolicyResults: []evidence.PolicyResult{},
	}
	checkResult.CalculateSummary()

	var buf bytes.Buffer
	formatter := NewJUnitFormatter(&buf)
	err := formatter.FormatCheckResult(checkResult)
	require.NoError(t, err)

	output := buf.String()
	assert.NotEmpty(t, output)
	assert.Contains(t, output, "<?xml")
	assert.Contains(t, output, "encoding=\"UTF-8\"")
}
