// Package evidence provides core types for compliance evidence and policy evaluation results.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ResultStatus represents the outcome of a policy evaluation.
type ResultStatus string

// ResultStatus constants for policy evaluation outcomes.
const (
	StatusPass  ResultStatus = "pass"
	StatusFail  ResultStatus = "fail"
	StatusSkip  ResultStatus = "skip"
	StatusError ResultStatus = "error"
)

// IsValid checks if the status is a known valid value.
func (s ResultStatus) IsValid() bool {
	switch s {
	case StatusPass, StatusFail, StatusSkip, StatusError:
		return true
	}
	return false
}

// Severity indicates the importance of a policy or violation.
type Severity string

// Severity constants for policy importance levels.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// IsValid checks if the severity is a known valid value.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// Evidence represents raw data collected from an API or service.
type Evidence struct {
	ID           string          `json:"id"`
	Collector    string          `json:"collector"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Data         json.RawMessage `json:"data"`
	Hash         string          `json:"hash"`
	CollectedAt  time.Time       `json:"collected_at"`
	Metadata     Metadata        `json:"metadata"`
}

// Metadata contains additional context about collected evidence.
type Metadata struct {
	AccountID        string            `json:"account_id,omitempty"`
	Region           string            `json:"region,omitempty"`
	Organization     string            `json:"organization,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
	CollectorVersion string            `json:"collector_version,omitempty"`
}

// New creates a new Evidence with auto-generated ID, hash, and timestamp.
func New(collector, resourceType, resourceID string, data json.RawMessage) Evidence {
	return Evidence{
		ID:           uuid.New().String(),
		Collector:    collector,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Data:         data,
		Hash:         computeHash(data),
		CollectedAt:  time.Now().UTC(),
	}
}

// computeHash calculates SHA-256 hash of the data.
func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Violation represents a single policy violation for a specific resource.
type Violation struct {
	ResourceID   string                 `json:"resource_id"`
	ResourceType string                 `json:"resource_type"`
	Reason       string                 `json:"reason"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// PolicyResult represents the outcome of evaluating a single policy.
type PolicyResult struct {
	PolicyID           string       `json:"policy_id"`
	ControlID          string       `json:"control_id"`
	Name               string       `json:"name"`
	Status             ResultStatus `json:"status"`
	Severity           Severity     `json:"severity"`
	Message            string       `json:"message"`
	Remediation        string       `json:"remediation,omitempty"`
	ResourcesEvaluated int          `json:"resources_evaluated"`
	ResourcesFailed    int          `json:"resources_failed"`
	Violations         []Violation  `json:"violations,omitempty"`
	ResourceTypes      []string     `json:"resource_types,omitempty"`
}

// HasViolations returns true if there are any violations.
func (r *PolicyResult) HasViolations() bool {
	return len(r.Violations) > 0
}

// CheckSummary provides aggregate statistics for a compliance check run.
type CheckSummary struct {
	TotalPolicies   int     `json:"total_policies"`
	PassedPolicies  int     `json:"passed_policies"`
	FailedPolicies  int     `json:"failed_policies"`
	SkippedPolicies int     `json:"skipped_policies"`
	ComplianceScore float64 `json:"compliance_score"`
}

// RunEnvironment captures context about where the check was executed.
type RunEnvironment struct {
	CI         bool   `json:"ci"`
	CIProvider string `json:"ci_provider,omitempty"`
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`
	CLIVersion string `json:"cli_version,omitempty"`
}

// CheckResult represents the complete output of a compliance check run.
type CheckResult struct {
	RunID         string         `json:"run_id"`
	Framework     string         `json:"framework"`
	Timestamp     time.Time      `json:"timestamp"`
	PolicyResults []PolicyResult `json:"policy_results"`
	Summary       CheckSummary   `json:"summary"`
	Environment   RunEnvironment `json:"environment"`
}

// CalculateSummary computes the summary statistics from policy results.
func (r *CheckResult) CalculateSummary() {
	r.Summary = CheckSummary{}

	for i := range r.PolicyResults {
		r.Summary.TotalPolicies++
		switch r.PolicyResults[i].Status {
		case StatusPass:
			r.Summary.PassedPolicies++
		case StatusFail:
			r.Summary.FailedPolicies++
		case StatusSkip:
			r.Summary.SkippedPolicies++
		}
	}

	// Calculate compliance score: passed / (total - skipped)
	evaluated := r.Summary.TotalPolicies - r.Summary.SkippedPolicies
	if evaluated > 0 {
		r.Summary.ComplianceScore = float64(r.Summary.PassedPolicies) / float64(evaluated)
	}
}

// HasFailures returns true if any policy failed.
func (r *CheckResult) HasFailures() bool {
	return r.Summary.FailedPolicies > 0
}
