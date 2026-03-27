// Package cloud provides the SigComply Cloud API client.
package cloud

import (
	"time"
)

// SubmitRequest is the top-level payload sent to POST /api/v1/cli/runs.
// It matches the Rails API contract: check_result is nested under the "check_result" key.
//
// Privacy invariant: this struct must never gain a freeform metadata field (e.g.
// run_metadata map[string]interface{}). Such a field would be an open door for
// resource identifiers to reach the cloud API if populated carelessly.
type SubmitRequest struct {
	// CheckResult contains the aggregated compliance check data.
	// Rails reads this nested structure via strong params and RunSubmissionService.
	CheckResult CheckResultPayload `json:"check_result"`
}

// CheckResultPayload is the check result payload nested inside SubmitRequest.
//
// Privacy invariant: this payload contains NO resource identifiers (no ARNs, usernames,
// email addresses, or account IDs). Violations are reduced to counts before this struct
// is populated. Raw evidence, full CheckResult with violation details, and attestations
// all stay in the customer's S3 bucket — they are never sent to SigComply.
type CheckResultPayload struct {
	// RunID is the unique identifier for this compliance check run.
	RunID string `json:"run_id"`

	// Framework is the compliance framework evaluated (e.g., "soc2").
	Framework string `json:"framework"`

	// Timestamp is when the compliance check was performed.
	Timestamp time.Time `json:"timestamp"`

	// PolicyResults contains per-policy aggregated results — no resource identifiers.
	PolicyResults []AggregatedPolicyResult `json:"policy_results"`

	// Summary contains overall aggregated compliance scores.
	Summary AggregatedSummary `json:"summary"`

	// Environment contains CI/CD context. Rails stores these in
	// policy_evaluations.cli_version, .runner, and .environment DB columns.
	Environment *EnvironmentInfo `json:"environment,omitempty"`
}

// AggregatedPolicyResult contains aggregated compliance data for a single policy.
// It intentionally omits violation details (resource IDs, ARNs, usernames) —
// only counts are sent to SigComply Cloud.
type AggregatedPolicyResult struct {
	// PolicyID is the policy identifier (e.g., "soc2-cc6.1-mfa").
	PolicyID string `json:"policy_id"`

	// ControlID is the control this policy maps to (e.g., "CC6.1").
	ControlID string `json:"control_id"`

	// Status is the policy outcome: "pass", "fail", or "skip".
	// "error" is mapped to "fail" before sending.
	Status string `json:"status"`

	// Severity is the policy severity: "critical", "high", "medium", or "low".
	Severity string `json:"severity"`

	// Message is a count-based human-readable summary of what the policy checked
	// and what failed (e.g. "3 out of 10 IAM users do not have MFA enabled").
	// Must NOT contain resource identifiers (no ARNs, usernames, or emails).
	Message string `json:"message,omitempty"`

	// Category is the dashboard grouping category for this policy.
	// One of: access_control, data_protection, logging, network_security,
	// vulnerability_management, configuration_management.
	Category string `json:"category,omitempty"`

	// ResourcesEvaluated is the total number of resources evaluated.
	ResourcesEvaluated int `json:"resources_evaluated"`

	// ResourcesFailed is the count of resources that failed this policy.
	// NOTE: Which resources failed is NOT sent — only the count.
	ResourcesFailed int `json:"resources_failed"`
}

// AggregatedSummary contains overall aggregated compliance scores for a run.
type AggregatedSummary struct {
	// TotalPolicies is the total number of policies evaluated.
	TotalPolicies int `json:"total_policies"`

	// PassedPolicies is the number of policies that passed.
	PassedPolicies int `json:"passed_policies"`

	// FailedPolicies is the number of policies that failed.
	FailedPolicies int `json:"failed_policies"`

	// SkippedPolicies is the number of policies that were skipped.
	SkippedPolicies int `json:"skipped_policies"`

	// ComplianceScore is the overall compliance score (0.0 to 1.0).
	ComplianceScore float64 `json:"compliance_score"`
}

// EnvironmentInfo contains CI/CD context about where the compliance check ran.
// This maps to the "environment" field inside check_result. Rails stores these fields
// in policy_evaluations.cli_version, .runner (from ci_provider), and .environment columns,
// and in the ci_context key of the metadata JSONB column.
type EnvironmentInfo struct {
	// CI indicates if this was run in a CI/CD environment.
	CI bool `json:"ci"`

	// CIProvider is the CI/CD platform: "github-actions" or "gitlab-ci".
	// Rails stores this in the policy_evaluations.runner column.
	CIProvider string `json:"ci_provider,omitempty"`

	// Repository is the source repository (e.g., "owner/repo").
	Repository string `json:"repository,omitempty"`

	// Branch is the git branch.
	Branch string `json:"branch,omitempty"`

	// CommitSHA is the git commit SHA.
	CommitSHA string `json:"commit_sha,omitempty"`

	// CLIVersion is the version of the CLI used.
	// Rails stores this in the policy_evaluations.cli_version column.
	CLIVersion string `json:"cli_version,omitempty"`
}

// SubmitResponse is the response from submitting check results.
// This matches the Rails API response structure.
type SubmitResponse struct {
	// Data contains the response payload.
	Data *SubmitResponseData `json:"data"`
}

// SubmitResponseData contains the response data wrapper.
type SubmitResponseData struct {
	// Run contains the run details.
	Run *RunResponseData `json:"run"`
}

// RunResponseData contains the details of the submitted run.
type RunResponseData struct {
	// ID is the unique identifier for this run (from Rails).
	ID string `json:"id"`

	// PolicyEvaluationID is the database ID of the created policy evaluation.
	PolicyEvaluationID int64 `json:"policy_evaluation_id,omitempty"`

	// Status indicates the acceptance status (e.g., "accepted").
	Status string `json:"status"`

	// DriftSummary contains drift information compared to previous runs.
	DriftSummary *DriftSummary `json:"drift_summary,omitempty"`
}

// Convenience methods for SubmitResponse.

// Success returns true if the submission was successful.
func (r *SubmitResponse) Success() bool {
	return r != nil && r.Data != nil && r.Data.Run != nil && r.Data.Run.Status == "accepted"
}

// RunID returns the run ID from the response.
func (r *SubmitResponse) RunID() string {
	if r != nil && r.Data != nil && r.Data.Run != nil {
		return r.Data.Run.ID
	}
	return ""
}

// GetDriftSummary returns the drift summary if available.
func (r *SubmitResponse) GetDriftSummary() *DriftSummary {
	if r != nil && r.Data != nil && r.Data.Run != nil {
		return r.Data.Run.DriftSummary
	}
	return nil
}

// DriftSummary describes changes since the last compliance check.
// This matches the Rails API response structure.
type DriftSummary struct {
	// HasDrift indicates if there are any changes.
	HasDrift bool `json:"has_drift"`

	// NewViolations is the count of new violations.
	NewViolations int `json:"new_violations"`

	// ResolvedViolations is the count of resolved violations.
	ResolvedViolations int `json:"resolved_violations"`

	// ScoreChange is the change in compliance score from previous run.
	// Positive means improvement, negative means regression.
	ScoreChange float64 `json:"score_change,omitempty"`

	// ChangedPolicies lists policies with status changes.
	ChangedPolicies []PolicyChange `json:"changed_policies,omitempty"`
}

// PolicyChange describes a policy that changed status.
// This matches the Rails API response structure.
type PolicyChange struct {
	// PolicyCode is the policy identifier (e.g., "aws-iam-mfa-enabled").
	PolicyCode string `json:"policy_code"`

	// Change describes the type of change (e.g., "new_violation", "resolved", "still_failing").
	Change string `json:"change"`
}

// APIError represents an error from the Cloud API.
type APIError struct {
	// Code is the error code.
	Code string `json:"code"`

	// Message is the error message.
	Message string `json:"message"`

	// Details contains additional error context.
	Details map[string]interface{} `json:"details,omitempty"`

	// HTTPStatus is the HTTP status code.
	HTTPStatus int `json:"-"`
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return e.Code + ": " + e.Message
	}
	return e.Message
}

// IsSubscriptionRequired returns true if the error is a 402 subscription required response.
func (e *APIError) IsSubscriptionRequired() bool {
	return e.HTTPStatus == 402
}

// UpgradeURL returns the upgrade URL from error details, if present.
func (e *APIError) UpgradeURL() string {
	if e.Details != nil {
		if url, ok := e.Details["upgrade_url"].(string); ok {
			return url
		}
	}
	return ""
}

// TokenInfo contains OIDC token information.
type TokenInfo struct {
	// Token is the raw OIDC token.
	Token string `json:"token"`

	// Provider is the token provider (github-actions, gitlab-ci).
	Provider string `json:"provider"`

	// Subject is the token subject claim.
	Subject string `json:"subject,omitempty"`

	// Issuer is the token issuer.
	Issuer string `json:"issuer,omitempty"`

	// Audience is the token audience.
	Audience string `json:"audience,omitempty"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// ClientConfig holds configuration for the Cloud client.
type ClientConfig struct {
	// BaseURL is the Cloud API base URL.
	BaseURL string

	// OIDCToken is an OIDC token for authentication.
	OIDCToken *TokenInfo

	// Timeout is the HTTP request timeout.
	Timeout time.Duration

	// RetryCount is the number of retries for failed requests.
	RetryCount int

	// UserAgent is the User-Agent header value.
	UserAgent string
}

// DefaultConfig returns a ClientConfig with default values.
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		BaseURL:    "https://api.sigcomply.com",
		Timeout:    30 * time.Second,
		RetryCount: 3,
		UserAgent:  "sigcomply-cli/1.0",
	}
}
