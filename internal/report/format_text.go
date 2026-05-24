package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// FormatText writes a human-readable text rendering of snap to w.
// Output is deterministic: no "generated_at" timestamp is emitted from
// here. The CLI command can prefix a header if it wants.
//
// Format choices:
//   - latest: aligned columns via tabwriter (policy_id  control  status  severity  last_evaluated  exception)
//   - exceptions: aligned columns (policy_id  scope  state  approved_by  approved_at  expires_at  reason)
//   - integrity: aligned columns (run_path  status  files_verified/total  details)
func FormatText(w io.Writer, snap *Snapshot) error {
	if snap == nil {
		return fmt.Errorf("format text: nil Snapshot")
	}
	header := fmt.Sprintf("# sigcomply report — framework=%s period=%s view=%s\n\n",
		snap.Framework, snap.PeriodID, snap.View)
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	switch snap.View {
	case ViewLatest:
		return formatTextLatest(w, snap.Latest)
	case ViewExceptions:
		return formatTextExceptions(w, snap.Exceptions)
	case ViewIntegrity:
		return formatTextIntegrity(w, snap.Integrity)
	default:
		return fmt.Errorf("format text: unsupported view %q", snap.View)
	}
}

func formatTextLatest(w io.Writer, v *LatestView) error {
	if v == nil || len(v.Policies) == 0 {
		_, err := io.WriteString(w, "(no policy results for this period)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "POLICY_ID\tCONTROL\tSTATUS\tSEVERITY\tLAST_EVALUATED\tEXCEPTION"); err != nil {
		return err
	}
	for i := range v.Policies {
		p := &v.Policies[i]
		exc := p.ExceptionID
		if exc == "" {
			exc = "-"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.PolicyID, dash(p.ControlID), p.Status, dash(p.Severity),
			p.LastEvaluated.Format("2006-01-02T15:04:05Z"), exc); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func formatTextExceptions(w io.Writer, v *ExceptionsView) error {
	if v == nil || len(v.Exceptions) == 0 {
		_, err := io.WriteString(w, "(no exceptions applied in this period)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "POLICY_ID\tSCOPE\tSTATE\tAPPROVED_BY\tAPPROVED_AT\tEXPIRES_AT\tREASON"); err != nil {
		return err
	}
	for i := range v.Exceptions {
		e := &v.Exceptions[i]
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.PolicyID, dash(e.Scope), dash(e.State),
			dash(e.ApprovedBy), dash(e.ApprovedAt), dash(e.ExpiresAt),
			oneLine(e.Reason)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func formatTextIntegrity(w io.Writer, v *IntegrityView) error {
	if v == nil || len(v.Runs) == 0 {
		_, err := io.WriteString(w, "(no runs in this period)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "RUN_PATH\tSTATUS\tFILES_OK\tDETAIL"); err != nil {
		return err
	}
	for i := range v.Runs {
		row := &v.Runs[i]
		count := fmt.Sprintf("%d/%d", row.FilesVerified, row.FilesTotal)
		detail := "-"
		if row.FirstMismatchPath != "" {
			detail = "mismatch: " + row.FirstMismatchPath
		} else if row.Error != "" {
			detail = oneLine(row.Error)
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", row.RunPath, row.Status(), count, detail); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// dash returns "-" for empty strings so tabwriter columns stay aligned
// for the eye.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// oneLine collapses newlines into spaces so a multi-line Reason fits
// in a single tabwriter row.
func oneLine(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
}
