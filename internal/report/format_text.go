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
	case ViewScope:
		return formatTextScope(w, snap.Scope)
	case ViewCoverage:
		return formatTextCoverage(w, snap.Coverage)
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

func formatTextScope(w io.Writer, v *ScopeView) error {
	if v == nil {
		_, err := fmt.Fprintln(w, "(no runs in this period)")
		return err
	}

	if !v.Declared {
		if _, err := fmt.Fprintln(w, "Declared estate: none (experimental.scope not set)"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "Declared estate: %s (by %s on %s)\n",
			dash(v.Status), dash(v.DeclaredBy), dash(v.DeclaredAt)); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "SOURCE\tSTATE"); err != nil {
			return err
		}
		for _, s := range v.Sources {
			if _, err := fmt.Fprintf(tw, "%s\t%s\n", s.SourceID, s.State); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(v.Skipped) == 0 {
		_, err := fmt.Fprintln(w, "\nEvery control in the latest run was evaluated.")
		return err
	}

	// Skips are the half that matters even with no declaration: they
	// leave the compliance-score denominator, so they are precisely what
	// a green run can hide.
	if _, err := fmt.Fprintf(w, "\n%d control(s) NOT evaluated in the latest run (excluded from the compliance score):\n", len(v.Skipped)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "POLICY\tREASON"); err != nil {
		return err
	}
	for _, s := range v.Skipped {
		if _, err := fmt.Fprintf(tw, "%s\t%s\n", s.PolicyID, oneLine(s.Reason)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// formatTextCoverage renders what stands behind each control.
//
// The headline is the point of the view: a framework can be 100%
// "covered" while most of that coverage is documents nobody read. The
// per-control table is the detail an operator needs to decide where the
// next month of work goes.
func formatTextCoverage(w io.Writer, v *CoverageView) error {
	if v == nil {
		_, err := fmt.Fprintln(w, "(no runs in this period)")
		return err
	}
	if err := writeCoverageHeadline(w, v); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CONTROL\tASSURANCE\tAUTOMATED\tMANUAL\tEVALUATED\tSTATUS\tNOTE"); err != nil {
		return err
	}
	for i := range v.Rows {
		r := &v.Rows[i]
		assurance := r.Assurance
		if r.Overridden {
			assurance += " (overridden)"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d of %d\t%s\t%s\n",
			r.ControlID, assurance, r.AutomatedPolicies, r.ManualPolicies,
			r.Evaluated, r.Policies, r.Status, oneLine(r.Note)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeCoverageHeadline(w io.Writer, v *CoverageView) error {
	if _, err := fmt.Fprintf(w, "%d of %d controls have a check\n", v.Automated+v.Manual, v.Controls); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %d automated  — verified by inspecting your infrastructure\n", v.Automated); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %d manual     — a document is on file; its contents are not inspected\n", v.Manual); err != nil {
		return err
	}
	if v.Uncovered > 0 {
		if _, err := fmt.Fprintf(w, "  %d uncovered  — no policy implements the control\n", v.Uncovered); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nThis period\n  %d evaluated, %d not evaluated\n", v.Evaluated, v.NotEvaluated); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %d manual control(s) with evidence on file, %d without\n", v.ManualOnFile, v.ManualMissing); err != nil {
		return err
	}
	if v.Overridden > 0 {
		if _, err := fmt.Fprintf(w, "  %d control(s) running in a mode the project overrode\n", v.Overridden); err != nil {
			return err
		}
	}
	// A cadence longer than the audit period produces no result for
	// three quarters out of four. Say so, or every Q1-Q3 report reads
	// like an outage.
	_, err := fmt.Fprint(w, "\nA control whose cadence is longer than this period (annual, in a quarterly\nperiod) is expected to show \"not evaluated\" here — the NOTE column names\nthe cadence so you can tell that apart from a check that should have run.\n\n")
	return err
}
