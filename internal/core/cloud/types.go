// Package cloud provides the TraceVault Cloud API client.
package cloud

import (
	"time"

	"github.com/tracevault/tracevault-cli/internal/core/attestation"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// SubmitRequest represents a request to submit compliance check results.
type SubmitRequest struct {
	// CheckResult contains the full policy evaluation results
	CheckResult *evidence.CheckResult `json:"check_result"`

	// Attestation contains the signed cryptographic proof
	Attestation *attestation.Attestation `json:"attestation"`

	// EvidenceLocation describes where the raw evidence is stored
	EvidenceLocation *EvidenceLocation `json:"evidence_location"`

	// RunMetadata contains additional run context
	RunMetadata *RunMetadata `json:"run_metadata,omitempty"`
}

// EvidenceLocation describes where evidence is stored.
// This structure is sent to the TraceVault Cloud API.
type EvidenceLocation struct {
	// URL is the full URL to the evidence location (e.g., "s3://bucket/path").
	// This is a convenience field for Rails to display/link to evidence.
	URL string `json:"url,omitempty"`

	// Backend is the storage type (local, s3, gcs)
	Backend string `json:"backend"`

	// Bucket is the storage bucket name (for cloud storage).
	// Required for S3/GCS backends.
	Bucket string `json:"bucket,omitempty"`

	// Path is the key/path prefix where evidence is stored.
	Path string `json:"path"`

	// ManifestPath is the path to the manifest file
	ManifestPath string `json:"manifest_path,omitempty"`

	// Encrypted indicates if the evidence is encrypted at rest.
	Encrypted bool `json:"encrypted,omitempty"`
}

// RunMetadata contains context about the compliance check run.
type RunMetadata struct {
	// CI indicates if this was run in a CI/CD environment
	CI bool `json:"ci"`

	// CIProvider is the CI/CD platform (github-actions, gitlab-ci)
	CIProvider string `json:"ci_provider,omitempty"`

	// Repository is the source repository
	Repository string `json:"repository,omitempty"`

	// Branch is the git branch
	Branch string `json:"branch,omitempty"`

	// CommitSHA is the git commit SHA
	CommitSHA string `json:"commit_sha,omitempty"`

	// RunURL is a link to the CI/CD run
	RunURL string `json:"run_url,omitempty"`

	// CLIVersion is the version of the CLI used
	CLIVersion string `json:"cli_version,omitempty"`
}

// SubmitResponse is the response from submitting check results.
// This matches the Rails API response structure.
type SubmitResponse struct {
	// Data contains the response payload
	Data *SubmitResponseData `json:"data"`
}

// SubmitResponseData contains the response data wrapper.
type SubmitResponseData struct {
	// Run contains the run details
	Run *RunResponseData `json:"run"`
}

// RunResponseData contains the details of the submitted run.
type RunResponseData struct {
	// ID is the unique identifier for this run (from Rails)
	ID string `json:"id"`

	// AttestationID is the database ID of the created attestation
	AttestationID int64 `json:"attestation_id,omitempty"`

	// PolicyEvaluationID is the database ID of the created policy evaluation
	PolicyEvaluationID int64 `json:"policy_evaluation_id,omitempty"`

	// Status indicates the acceptance status (e.g., "accepted")
	Status string `json:"status"`

	// DriftSummary contains drift information compared to previous runs
	DriftSummary *DriftSummary `json:"drift_summary,omitempty"`
}

// Convenience methods for SubmitResponse

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
	// HasDrift indicates if there are any changes
	HasDrift bool `json:"has_drift"`

	// NewViolations is the count of new violations
	NewViolations int `json:"new_violations"`

	// ResolvedViolations is the count of resolved violations
	ResolvedViolations int `json:"resolved_violations"`

	// ScoreChange is the change in compliance score from previous run.
	// Positive means improvement, negative means regression.
	ScoreChange float64 `json:"score_change,omitempty"`

	// ChangedPolicies lists policies with status changes
	ChangedPolicies []PolicyChange `json:"changed_policies,omitempty"`
}

// PolicyChange describes a policy that changed status.
// This matches the Rails API response structure.
type PolicyChange struct {
	// PolicyCode is the policy identifier (e.g., "aws-iam-mfa-enabled")
	PolicyCode string `json:"policy_code"`

	// Change describes the type of change (e.g., "new_violation", "resolved", "still_failing")
	Change string `json:"change"`
}

// APIError represents an error from the Cloud API.
type APIError struct {
	// Code is the error code
	Code string `json:"code"`

	// Message is the error message
	Message string `json:"message"`

	// Details contains additional error context
	Details map[string]interface{} `json:"details,omitempty"`

	// HTTPStatus is the HTTP status code
	HTTPStatus int `json:"-"`
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return e.Code + ": " + e.Message
	}
	return e.Message
}

// TokenInfo contains OIDC token information.
type TokenInfo struct {
	// Token is the raw OIDC token
	Token string `json:"token"`

	// Provider is the token provider (github-actions, gitlab-ci)
	Provider string `json:"provider"`

	// Subject is the token subject claim
	Subject string `json:"subject,omitempty"`

	// Issuer is the token issuer
	Issuer string `json:"issuer,omitempty"`

	// Audience is the token audience
	Audience string `json:"audience,omitempty"`

	// ExpiresAt is when the token expires
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// ClientConfig holds configuration for the Cloud client.
type ClientConfig struct {
	// BaseURL is the Cloud API base URL
	BaseURL string

	// APIToken is a static API token (alternative to OIDC)
	APIToken string

	// OIDCToken is an OIDC token for authentication
	OIDCToken *TokenInfo

	// Timeout is the HTTP request timeout
	Timeout time.Duration

	// RetryCount is the number of retries for failed requests
	RetryCount int

	// UserAgent is the User-Agent header value
	UserAgent string
}

// DefaultConfig returns a ClientConfig with default values.
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		BaseURL:    "https://api.tracevault.io",
		Timeout:    30 * time.Second,
		RetryCount: 3,
		UserAgent:  "tracevault-cli/1.0",
	}
}
