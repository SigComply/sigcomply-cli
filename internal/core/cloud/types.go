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
type EvidenceLocation struct {
	// Backend is the storage type (local, s3, gcs)
	Backend string `json:"backend"`

	// Path is the location reference (bucket/prefix for S3, path for local)
	Path string `json:"path"`

	// ManifestPath is the path to the manifest file
	ManifestPath string `json:"manifest_path,omitempty"`
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
type SubmitResponse struct {
	// Success indicates if the submission was successful
	Success bool `json:"success"`

	// RunID is the unique identifier for this run
	RunID string `json:"run_id"`

	// Message contains any additional information
	Message string `json:"message,omitempty"`

	// DashboardURL is a link to view this run in the dashboard
	DashboardURL string `json:"dashboard_url,omitempty"`

	// DriftSummary contains drift information compared to previous runs
	DriftSummary *DriftSummary `json:"drift_summary,omitempty"`
}

// DriftSummary describes changes since the last compliance check.
type DriftSummary struct {
	// HasDrift indicates if there are any changes
	HasDrift bool `json:"has_drift"`

	// NewViolations is the count of new violations
	NewViolations int `json:"new_violations"`

	// ResolvedViolations is the count of resolved violations
	ResolvedViolations int `json:"resolved_violations"`

	// ChangedPolicies lists policies with status changes
	ChangedPolicies []PolicyChange `json:"changed_policies,omitempty"`
}

// PolicyChange describes a policy that changed status.
type PolicyChange struct {
	PolicyID      string `json:"policy_id"`
	PreviousState string `json:"previous_state"`
	CurrentState  string `json:"current_state"`
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
		BaseURL:    "https://api.tracevault.com",
		Timeout:    30 * time.Second,
		RetryCount: 3,
		UserAgent:  "tracevault-cli/1.0",
	}
}
