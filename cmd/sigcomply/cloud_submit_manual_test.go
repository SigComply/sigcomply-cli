package sigcomply

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/sigcomply/sigcomply-cli/internal/core/config"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

func TestBuildCloudSubmitRequest_IncludesManualPolicies(t *testing.T) {
	cfg := config.New()
	cfg.Framework = frameworkSOC2

	checkResult := &evidence.CheckResult{
		RunID:     "run-123",
		Framework: frameworkSOC2,
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:           "soc2-cc6.1-mfa",
				ControlID:          "CC6.1",
				Name:               "MFA Required",
				Status:             evidence.StatusPass,
				Severity:           evidence.SeverityHigh,
				ResourcesEvaluated: 5,
				ResourcesFailed:    0,
				ResourceTypes:      []string{"aws:iam:user"},
			},
			{
				PolicyID:           "soc2-cc6.1-quarterly-access-review",
				ControlID:          "CC6.1",
				Name:               "Quarterly Access Review",
				Status:             evidence.StatusFail,
				Severity:           evidence.SeverityHigh,
				Category:           "access_control",
				ResourcesEvaluated: 1,
				ResourcesFailed:    1,
				ResourceTypes:      []string{"manual:quarterly_access_review"},
			},
			{
				PolicyID:           "soc2-cc3.1-risk-acceptance",
				ControlID:          "CC3.1",
				Name:               "Risk Acceptance Sign-off",
				Status:             evidence.StatusPass,
				Severity:           evidence.SeverityHigh,
				Category:           "vulnerability_management",
				ResourcesEvaluated: 1,
				ResourcesFailed:    0,
				ResourceTypes:      []string{"manual:risk_acceptance_signoff"},
			},
		},
	}
	checkResult.CalculateSummary()

	req := buildCloudSubmitRequest(cfg, checkResult)

	// Should include all 3 policies
	assert.Len(t, req.CheckResult.PolicyResults, 3)

	// Verify manual policy results are present with correct categories
	var foundAccessReview, foundRiskAcceptance bool
	for _, pr := range req.CheckResult.PolicyResults {
		if pr.PolicyID == "soc2-cc6.1-quarterly-access-review" {
			foundAccessReview = true
			assert.Equal(t, "access_control", pr.Category)
			assert.Equal(t, "fail", pr.Status)
			assert.Equal(t, 1, pr.ResourcesEvaluated)
			assert.Equal(t, 1, pr.ResourcesFailed)
		}
		if pr.PolicyID == "soc2-cc3.1-risk-acceptance" {
			foundRiskAcceptance = true
			assert.Equal(t, "vulnerability_management", pr.Category)
			assert.Equal(t, "pass", pr.Status)
		}
	}
	assert.True(t, foundAccessReview, "quarterly access review policy should be in cloud submission")
	assert.True(t, foundRiskAcceptance, "risk acceptance policy should be in cloud submission")

	// Verify summary includes manual policies
	assert.Equal(t, 3, req.CheckResult.Summary.TotalPolicies)
	assert.Equal(t, 2, req.CheckResult.Summary.PassedPolicies)
	assert.Equal(t, 1, req.CheckResult.Summary.FailedPolicies)
}
