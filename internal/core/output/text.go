// Package output provides formatters for compliance check results.
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// TextFormatter formats compliance results as human-readable text.
type TextFormatter struct {
	writer io.Writer
}

// NewTextFormatter creates a new text formatter.
func NewTextFormatter(w io.Writer) *TextFormatter {
	return &TextFormatter{writer: w}
}

// FormatPolicyResult formats a single policy result.
//
//nolint:errcheck // fmt write errors are not actionable
func (f *TextFormatter) FormatPolicyResult(result evidence.PolicyResult) error { //nolint:gocritic // hugeParam acceptable for simple formatter
	status := statusText(result.Status)
	severity := severityText(result.Severity)

	// Print policy header
	fmt.Fprintf(f.writer, "  [%s] %s (%s) [%s]\n",
		status,
		result.ControlID,
		result.PolicyID,
		severity,
	)

	// Print message if present
	if result.Message != "" && result.Status != evidence.StatusPass {
		fmt.Fprintf(f.writer, "         %s\n", result.Message)
	}

	// Print resource counts
	if result.ResourcesEvaluated > 0 {
		fmt.Fprintf(f.writer, "         Resources: %d evaluated, %d failed\n",
			result.ResourcesEvaluated,
			result.ResourcesFailed,
		)
	}

	// Print violations
	for _, v := range result.Violations {
		fmt.Fprintf(f.writer, "         - %s\n", v.Reason)
		if v.ResourceID != "" {
			fmt.Fprintf(f.writer, "           Resource: %s\n", v.ResourceID)
		}
	}

	return nil
}

// FormatCheckResult formats a complete check result.
//
//nolint:errcheck // fmt write errors are not actionable
func (f *TextFormatter) FormatCheckResult(result *evidence.CheckResult) error {
	fmt.Fprintln(f.writer, "Policy Evaluation")
	fmt.Fprintln(f.writer, "-----------------")

	for i := range result.PolicyResults {
		if err := f.FormatPolicyResult(result.PolicyResults[i]); err != nil {
			return err
		}
	}

	fmt.Fprintln(f.writer)
	return f.FormatSummary(result.Summary)
}

// FormatSummary formats the check summary.
//
//nolint:errcheck // fmt write errors are not actionable
func (f *TextFormatter) FormatSummary(summary evidence.CheckSummary) error {
	fmt.Fprintln(f.writer, "Summary")
	fmt.Fprintln(f.writer, "-------")

	scorePercent := int(summary.ComplianceScore * 100)

	fmt.Fprintf(f.writer, "  Policies: %d total, %d passed, %d failed, %d skipped\n",
		summary.TotalPolicies,
		summary.PassedPolicies,
		summary.FailedPolicies,
		summary.SkippedPolicies,
	)

	fmt.Fprintf(f.writer, "  Compliance Score: %d%%\n", scorePercent)

	return nil
}

// statusText returns a text representation of the status.
func statusText(status evidence.ResultStatus) string {
	switch status {
	case evidence.StatusPass:
		return "PASS"
	case evidence.StatusFail:
		return "FAIL"
	case evidence.StatusSkip:
		return "SKIP"
	case evidence.StatusError:
		return "ERROR"
	default:
		return strings.ToUpper(string(status))
	}
}

// severityText returns a text representation of the severity.
func severityText(severity evidence.Severity) string {
	return string(severity)
}
