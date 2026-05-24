package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
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
	default:
		return fmt.Errorf("format csv: unsupported view %q", snap.View)
	}
}

func formatCSVLatest(cw *csv.Writer, v *LatestView) error {
	header := []string{"policy_id", "control_id", "status", "severity", "category", "last_evaluated", "run_id", "exception_id"}
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
