package output

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// JUnitFormatter formats compliance results as JUnit XML for CI/CD integration.
type JUnitFormatter struct {
	writer io.Writer
}

// NewJUnitFormatter creates a new JUnit XML formatter.
func NewJUnitFormatter(w io.Writer) *JUnitFormatter {
	return &JUnitFormatter{
		writer: w,
	}
}

// junitTestSuites is the root element of JUnit XML.
type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

// junitTestSuite represents a single test suite (one per framework).
type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      float64         `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

// junitTestCase represents a single test case (one per policy).
type junitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitError   `xml:"error,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

// junitFailure represents a test failure (policy violation).
type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// junitError represents a test error (execution error).
type junitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// junitSkipped represents a skipped test.
type junitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

// FormatCheckResult formats a complete check result as JUnit XML.
func (f *JUnitFormatter) FormatCheckResult(result *evidence.CheckResult) error {
	suite := f.buildTestSuite(result)

	testsuites := junitTestSuites{
		Suites: []junitTestSuite{suite},
	}

	// Write XML declaration
	if _, err := f.writer.Write([]byte(xml.Header)); err != nil {
		return err
	}

	// Encode with indentation
	enc := xml.NewEncoder(f.writer)
	enc.Indent("", "  ")
	return enc.Encode(testsuites)
}

// buildTestSuite converts a CheckResult into a JUnit test suite.
func (f *JUnitFormatter) buildTestSuite(result *evidence.CheckResult) junitTestSuite {
	suite := junitTestSuite{
		Name:      result.Framework,
		Timestamp: result.Timestamp.Format("2006-01-02T15:04:05"),
		Tests:     len(result.PolicyResults),
		TestCases: make([]junitTestCase, 0, len(result.PolicyResults)),
	}

	for i := range result.PolicyResults {
		pr := &result.PolicyResults[i]
		tc := f.buildTestCase(pr)
		suite.TestCases = append(suite.TestCases, tc)

		// Update counts
		switch pr.Status {
		case evidence.StatusFail:
			suite.Failures++
		case evidence.StatusError:
			suite.Errors++
		case evidence.StatusSkip:
			suite.Skipped++
		}
	}

	return suite
}

// buildTestCase converts a PolicyResult into a JUnit test case.
func (f *JUnitFormatter) buildTestCase(pr *evidence.PolicyResult) junitTestCase {
	tc := junitTestCase{
		Name:      pr.PolicyID,
		ClassName: pr.ControlID,
	}

	switch pr.Status {
	case evidence.StatusFail:
		tc.Failure = &junitFailure{
			Message: pr.Message,
			Type:    string(pr.Severity),
			Content: f.formatViolations(pr.Violations),
		}
	case evidence.StatusError:
		tc.Error = &junitError{
			Message: pr.Message,
			Type:    "error",
			Content: pr.Message,
		}
	case evidence.StatusSkip:
		tc.Skipped = &junitSkipped{
			Message: pr.Message,
		}
	}

	return tc
}

// formatViolations formats violations as a string for the failure content.
func (f *JUnitFormatter) formatViolations(violations []evidence.Violation) string {
	if len(violations) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, v := range violations {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("- %s (%s): %s", v.ResourceID, v.ResourceType, v.Reason))
	}
	return sb.String()
}
