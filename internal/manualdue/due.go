// Package manualdue answers one question, read-only and ahead of time:
// which manual-evidence entries have no file in the folder the next run
// will read?
//
// It exists because manual evidence has exactly one deadline signal
// today — a failing CI job on the day the evidence was already needed.
// This package supplies the earlier signal, and deliberately reports an
// entry only when its folder is genuinely empty: a warning that fires
// after the operator has already uploaded is a warning people learn to
// ignore, which would leave the product worse off than saying nothing.
//
// Non-custodial: the scan issues LIST calls only. It downloads no file
// bytes, writes nothing, contacts no cloud API, and needs no OIDC. See
// docs/architecture/10-cadence-model.md §Day-1 warnings.
package manualdue

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// githubAnnotationLimit is GitHub's per-step cap on warning
// annotations. Beyond it the runner silently drops them, so the
// overflow is collapsed into a single line instead.
const githubAnnotationLimit = 10

// Input is everything Scan needs. The caller resolves the period and
// builds the reader, so this package stays free of config parsing and
// is trivially testable with manual.InMemoryReader.
type Input struct {
	Framework string
	Catalog   map[string]manual.CatalogEntry
	Reader    manual.Reader
	Scheme    string
	Bucket    string
	Prefix    string
	Period    planner.Period
	Now       time.Time

	// Within limits the report to entries whose deadline falls inside
	// this lead time. Overdue entries are always reported regardless, so
	// a Within of zero means "only what is already late" — not "no
	// filter". Set Unfiltered for that.
	Within time.Duration

	// Unfiltered reports every empty folder, ignoring Within.
	Unfiltered bool
}

// Entry is one catalog entry with no evidence for the current period.
type Entry struct {
	CatalogID string `json:"catalog_id"`
	Cadence   string `json:"cadence"`
	FolderURI string `json:"folder_uri"`
	PeriodID  string `json:"period_id"`

	// PeriodEnd is the practical deadline: once the period closes,
	// runs derive the next period and stop reading this folder.
	PeriodEnd time.Time `json:"period_end"`

	// WindowCloses is period end plus the entry's grace period — the
	// last instant an upload can still satisfy the temporal-window
	// check, for a run that still derives this period.
	WindowCloses time.Time `json:"window_closes"`

	DaysLeft int  `json:"days_left"`
	Overdue  bool `json:"overdue"`

	// Instance and InstanceName are set when the entry fans out over a
	// set — today, one vendor in the project's third-party register.
	// They name which member's folder is empty, so the operator is told
	// "Acme Cloud has no assurance document" rather than the useless
	// "one of your vendors does".
	Instance     string `json:"instance,omitempty"`
	InstanceName string `json:"instance_name,omitempty"`
}

// Report is the result of one scan.
type Report struct {
	Framework string    `json:"framework"`
	PeriodID  string    `json:"period_id"`
	PeriodEnd time.Time `json:"period_end"`
	Checked   int       `json:"checked"`

	// Suppressed counts entries that are missing but whose deadline is
	// further out than Within. Reported so a quiet run is visibly
	// "nothing due yet" rather than "nothing examined".
	Suppressed int `json:"suppressed"`

	Missing []Entry `json:"missing"`
}

// Scan lists each catalog entry's current-period folder and reports the
// empty ones.
//
// A listing failure is returned as an error rather than being treated
// as "missing": an unreachable bucket is an unknown, and reporting
// unknowns as deadlines would manufacture exactly the false warnings
// this package is built to avoid.
func Scan(ctx context.Context, in *Input) (*Report, error) {
	rep := &Report{
		Framework: in.Framework,
		PeriodID:  in.Period.ID,
		PeriodEnd: in.Period.End,
	}
	for _, id := range manual.SortedCatalogIDs(in.Catalog) {
		entry := in.Catalog[id]

		// A fan-out entry has no folder of its own — its evidence lives
		// one folder per instance. Scanning the parent as well would
		// report a path nothing ever writes to as permanently overdue.
		if len(entry.Instances) > 0 {
			for i := range entry.Instances {
				inst := &entry.Instances[i]
				if !inst.Required {
					// An approved exemption owes no artifact, so it has
					// no deadline to warn about.
					continue
				}
				e, err := in.scanOne(ctx, &entry, inst.FolderID(entry.EvidenceID), rep)
				if err != nil {
					return nil, err
				}
				if e == nil {
					continue
				}
				e.Instance = inst.ID
				e.InstanceName = inst.Name
				rep.Missing = append(rep.Missing, *e)
			}
			continue
		}

		e, err := in.scanOne(ctx, &entry, entry.EvidenceID, rep)
		if err != nil {
			return nil, err
		}
		if e == nil {
			continue
		}
		rep.Missing = append(rep.Missing, *e)
	}
	sort.Slice(rep.Missing, func(i, j int) bool {
		if rep.Missing[i].DaysLeft != rep.Missing[j].DaysLeft {
			return rep.Missing[i].DaysLeft < rep.Missing[j].DaysLeft
		}
		if rep.Missing[i].CatalogID != rep.Missing[j].CatalogID {
			return rep.Missing[i].CatalogID < rep.Missing[j].CatalogID
		}
		return rep.Missing[i].Instance < rep.Missing[j].Instance
	})
	return rep, nil
}

// scanOne lists one folder and returns the Entry to report when it is
// empty and inside the warning horizon, or nil when there is nothing to
// say. It always counts the folder as checked, so "nothing due" stays
// distinguishable from "nothing examined".
func (in *Input) scanOne(ctx context.Context, entry *manual.CatalogEntry, folderID string, rep *Report) (*Entry, error) {
	prefix := manual.FolderPrefix(in.Prefix, folderID, in.Period.ID)
	items, err := in.Reader.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("manualdue: list %s: %w", prefix, err)
	}
	rep.Checked++
	if len(items) > 0 {
		return nil, nil
	}
	remaining := in.Period.End.Sub(in.Now)
	e := &Entry{
		CatalogID:    entry.EvidenceID,
		Cadence:      entry.Cadence,
		FolderURI:    manual.FolderURI(in.Scheme, in.Bucket, in.Prefix, folderID, in.Period.ID),
		PeriodID:     in.Period.ID,
		PeriodEnd:    in.Period.End,
		WindowCloses: in.Period.End.Add(entry.GracePeriod),
		DaysLeft:     int(remaining.Hours() / 24),
		Overdue:      remaining < 0,
	}
	if !in.Unfiltered && !e.Overdue && remaining > in.Within {
		rep.Suppressed++
		return nil, nil
	}
	return e, nil
}

// FormatText writes the operator-facing block. It is advisory output:
// the caller never turns it into a non-zero exit code.
func FormatText(w io.Writer, rep *Report) error {
	if rep == nil {
		return nil
	}
	if len(rep.Missing) == 0 {
		_, err := fmt.Fprintf(w,
			"manual evidence: no manual evidence is due — %d entr%s checked for period %s\n",
			rep.Checked, plural(rep.Checked), rep.PeriodID)
		return err
	}
	if _, err := fmt.Fprintf(w,
		"manual evidence: %d of %d entr%s have no file for period %s (ends %s)\n",
		len(rep.Missing), rep.Checked, plural(rep.Checked),
		rep.PeriodID, rep.PeriodEnd.UTC().Format("2006-01-02")); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "  ENTRY\tCADENCE\tDUE IN\tUPLOAD TO"); err != nil {
		return err
	}
	for i := range rep.Missing {
		e := &rep.Missing[i]
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
			entryLabel(e), dash(e.Cadence), dueIn(e), e.FolderURI); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w,
		"manual evidence: upload before the period ends; this notice does not fail the build.\n")
	return err
}

// FormatJSON writes the report for scripted consumers.
func FormatJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// FormatGitHubAnnotations emits GitHub Actions workflow commands so the
// notice surfaces on the run summary page. Annotations never change a
// job's conclusion — the exit code alone does that, and this command
// always exits zero.
func FormatGitHubAnnotations(w io.Writer, rep *Report) error {
	if rep == nil || len(rep.Missing) == 0 {
		return nil
	}
	// The overflow notice is itself an annotation, so it has to fit
	// inside the cap — otherwise the runner drops the very line that
	// says entries were dropped.
	shown := rep.Missing
	if len(shown) > githubAnnotationLimit {
		shown = shown[:githubAnnotationLimit-1]
	}
	for i := range shown {
		e := &shown[i]
		if _, err := fmt.Fprintf(w, "::warning title=Manual evidence %s::%s (%s) has no file for period %s — %s. Upload to %s\n",
			overdueWord(e), e.CatalogID, dash(e.Cadence), e.PeriodID, dueIn(e), e.FolderURI); err != nil {
			return err
		}
	}
	if extra := len(rep.Missing) - len(shown); extra > 0 {
		if _, err := fmt.Fprintf(w,
			"::warning title=Manual evidence due::and %d more entr%s — run `sigcomply evidence due` for the full list\n",
			extra, plural(extra)); err != nil {
			return err
		}
	}
	return nil
}

// FormatMarkdown writes a table for $GITHUB_STEP_SUMMARY.
func FormatMarkdown(w io.Writer, rep *Report) error {
	if rep == nil {
		return nil
	}
	if len(rep.Missing) == 0 {
		_, err := fmt.Fprintf(w, "## Manual evidence\n\nNothing due — %d entr%s checked for period `%s`.\n",
			rep.Checked, plural(rep.Checked), rep.PeriodID)
		return err
	}
	if _, err := fmt.Fprintf(w,
		"## Manual evidence due\n\n%d of %d entr%s have no file for period `%s` (ends %s).\n\n| Entry | Cadence | Due in | Upload to |\n|---|---|---|---|\n",
		len(rep.Missing), rep.Checked, plural(rep.Checked),
		rep.PeriodID, rep.PeriodEnd.UTC().Format("2006-01-02")); err != nil {
		return err
	}
	for i := range rep.Missing {
		e := &rep.Missing[i]
		if _, err := fmt.Fprintf(w, "| `%s` | %s | %s | `%s` |\n",
			e.CatalogID, dash(e.Cadence), dueIn(e), e.FolderURI); err != nil {
			return err
		}
	}
	return nil
}

func dueIn(e *Entry) string {
	switch {
	case e.Overdue:
		return fmt.Sprintf("overdue by %dd", -e.DaysLeft)
	case e.DaysLeft == 0:
		return "today"
	default:
		return fmt.Sprintf("%dd", e.DaysLeft)
	}
}

func overdueWord(e *Entry) string {
	if e.Overdue {
		return "overdue"
	}
	return "due"
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// entryLabel names a row. A fan-out row must say which member is
// missing — "vendor_assurance" alone would leave the operator to guess
// which of their vendors has no document on file.
func entryLabel(e *Entry) string {
	if e.Instance == "" {
		return e.CatalogID
	}
	if e.InstanceName != "" {
		return fmt.Sprintf("%s [%s]", e.CatalogID, e.InstanceName)
	}
	return fmt.Sprintf("%s [%s]", e.CatalogID, e.Instance)
}
