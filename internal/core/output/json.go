package output

import (
	"encoding/json"
	"io"

	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// JSONFormatter formats compliance results as JSON.
type JSONFormatter struct {
	writer   io.Writer
	compact  bool
	evidence []evidence.Evidence
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter(w io.Writer) *JSONFormatter {
	return &JSONFormatter{
		writer:  w,
		compact: false,
	}
}

// SetCompact sets whether to output compact (non-indented) JSON.
func (f *JSONFormatter) SetCompact(compact bool) *JSONFormatter {
	f.compact = compact
	return f
}

// WithEvidence sets evidence to include in the output.
func (f *JSONFormatter) WithEvidence(ev []evidence.Evidence) *JSONFormatter {
	f.evidence = ev
	return f
}

// jsonCheckResult is the JSON output structure for check results.
type jsonCheckResult struct {
	RunID         string                  `json:"run_id,omitempty"`
	Framework     string                  `json:"framework"`
	Timestamp     string                  `json:"timestamp"`
	PolicyResults []evidence.PolicyResult `json:"policy_results"`
	Summary       evidence.CheckSummary   `json:"summary"`
	Evidence      []evidence.Evidence     `json:"evidence,omitempty"`
}

// FormatCheckResult formats a complete check result as JSON.
func (f *JSONFormatter) FormatCheckResult(result *evidence.CheckResult) error {
	output := jsonCheckResult{
		RunID:         result.RunID,
		Framework:     result.Framework,
		Timestamp:     result.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		PolicyResults: result.PolicyResults,
		Summary:       result.Summary,
		Evidence:      f.evidence,
	}

	return f.encode(output)
}

// FormatPolicyResult formats a single policy result as JSON.
//
//nolint:gocritic // hugeParam acceptable for simple formatter
func (f *JSONFormatter) FormatPolicyResult(result evidence.PolicyResult) error {
	return f.encode(result)
}

// FormatSummary formats the check summary as JSON.
func (f *JSONFormatter) FormatSummary(summary evidence.CheckSummary) error {
	return f.encode(summary)
}

// encode writes the value as JSON to the writer.
func (f *JSONFormatter) encode(v interface{}) error {
	enc := json.NewEncoder(f.writer)
	if !f.compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}
