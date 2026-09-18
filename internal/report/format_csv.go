package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// FormatCSV writes a CSV rendering of snap to w. One row per policy
// for the latest view, one row per exception for the exceptions view,
// one row per run for the integrity view. Designed to play well with
// auditor spreadsheets.
//
// The header row is the first record. CSV escaping is the standard
// encoding/csv behavior (RFC 4180): fields containing commas,
// quotes, or newlines are quoted.
func FormatCSV(w io.Writer, snap *Snapshot) error {
	if snap == nil {
		return fmt.Errorf("format csv: nil Snapshot")
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()

	switch snap.View {
	case ViewLatest:
		return formatCSVLatest(cw, snap.Latest)
	case ViewExceptions:
		return formatCSVExceptions(cw, snap.Exceptions)
	case ViewIntegrity:
		return formatCSVIntegrity(cw, snap.Integrity)
	case ViewScope:
		return formatCSVScope(cw, snap.Scope)
	case ViewCoverage:
		return formatCSVCoverage(cw, snap.Coverage)
	default:
		return fmt.Errorf("format csv: unsupported view %q", snap.View)
	}
}

func formatCSVLatest(cw *csv.Writer, v *LatestView) error {
	header := []string{"policy_id", "control_id", "status", "severity", "category", "last_evaluated", "run_id", "exception_id", "reason"}
	if err := cw.Write(header); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	for i := range v.Policies {
		p := &v.Policies[i]
		row := []string{
			p.PolicyID,
			p.ControlID,
			p.Status,
			p.Severity,
			p.Category,
			p.LastEvaluated.Format("2006-01-02T15:04:05Z"),
			p.RunID,
			p.ExceptionID,
			oneLine(p.Reason),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func formatCSVExceptions(cw *csv.Writer, v *ExceptionsView) error {
	header := []string{"policy_id", "scope", "state", "approved_by", "approved_at", "expires_at", "reason", "first_seen_run_id", "last_seen_run_id"}
	if err := cw.Write(header); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	for i := range v.Exceptions {
		e := &v.Exceptions[i]
		row := []string{
			e.PolicyID,
			e.Scope,
			e.State,
			e.ApprovedBy,
			e.ApprovedAt,
			e.ExpiresAt,
			e.Reason,
			e.FirstSeenRunID,
			e.LastSeenRunID,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func formatCSVIntegrity(cw *csv.Writer, v *IntegrityView) error {
	header := []string{"run_path", "run_id", "completed_at", "status", "signature_valid", "files_verified", "files_total", "first_mismatch_path", "error"}
	if err := cw.Write(header); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	for i := range v.Runs {
		row := &v.Runs[i]
		out := []string{
			row.RunPath,
			row.RunID,
			row.CompletedAt.Format("2006-01-02T15:04:05Z"),
			row.Status(),
			strconv.FormatBool(row.SignatureValid),
			strconv.Itoa(row.FilesVerified),
			strconv.Itoa(row.FilesTotal),
			row.FirstMismatchPath,
			row.Error,
		}
		if err := cw.Write(out); err != nil {
			return err
		}
	}
	return nil
}

// formatCSVScope emits one flat table covering both halves of the view:
// declared-source rows and skipped-control rows, distinguished by the
// "kind" column so the file stays a single rectangular CSV.
func formatCSVScope(cw *csv.Writer, v *ScopeView) error {
	if err := cw.Write([]string{"kind", "id", "state_or_reason", "status", "declared_by", "declared_at", "run_id"}); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	for _, s := range v.Sources {
		if err := cw.Write([]string{"declared_source", s.SourceID, s.State, v.Status, v.DeclaredBy, v.DeclaredAt, v.RunID}); err != nil {
			return err
		}
	}
	for _, s := range v.Skipped {
		kind := "skipped_policy"
		if s.Status == string(core.StatusError) {
			kind = "errored_policy"
		}
		if err := cw.Write([]string{kind, s.PolicyID, oneLine(s.Reason), s.Status, "", "", v.RunID}); err != nil {
			return err
		}
	}
	return nil
}

// formatCSVCoverage emits one row per declared control. Header first, so
// a nil view still yields a well-formed header-only file.
func formatCSVCoverage(cw *csv.Writer, v *CoverageView) error {
	if err := cw.Write([]string{
		"control_id", "assurance", "automated_policies", "manual_policies",
		"evaluated", "policies", "status", "overridden", "note",
	}); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	for i := range v.Rows {
		r := &v.Rows[i]
		if err := cw.Write([]string{
			r.ControlID, r.Assurance,
			strconv.Itoa(r.AutomatedPolicies), strconv.Itoa(r.ManualPolicies),
			strconv.Itoa(r.Evaluated), strconv.Itoa(r.Policies),
			r.Status, strconv.FormatBool(r.Overridden), oneLine(r.Note),
		}); err != nil {
			return err
		}
	}
	return nil
}
