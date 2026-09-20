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
	"github.com/sigcomply/sigcomply-cli/internal/spec"
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

	// PeriodCfg is the project's period block. Each entry's folder is
	// resolved from it and the entry's own cadence via
	// planner.CadencePeriod — the same call the planner makes when it
	// builds the run's manual bindings, which is what keeps the folder
	// this command reports byte-identical to the one `check` reads.
	PeriodCfg spec.PeriodConfig

	// Reference is the instant every period in this scan is derived
	// from: the HEAD commit's timestamp under the default time_basis.
	// Deadlines are measured on it too, and deliberately not on the wall
	// clock — a stale HEAD would otherwise report the period the next
	// run will actually evaluate as already overdue.
	Reference time.Time

	// WithinDays limits the report to entries whose period closes inside
	// this lead time. Zero means "only what closes today" — the strict
	// reading of a zero lead time, not "no filter". Set Unfiltered for
	// that.
	WithinDays int

	// Unfiltered reports every empty folder, ignoring WithinDays.
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

	// DaysLeft counts down to PeriodEnd from the same reference clock the
	// period was derived from, so it is never negative: the run that will
	// read this folder derives this same period and reads it while the
	// window is still open. There is no "overdue" state for the period
	// being scanned — the one this command used to report came from
	// comparing a wall clock against a commit-derived period.
	DaysLeft int `json:"days_left"`

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
	Framework string `json:"framework"`

	// PeriodID and PeriodEnd describe the RUN's period — the one a
	// `sigcomply check` on this commit would stamp its results with.
	// They are context only: each missing entry carries the period of
	// its own folder, which follows the entry's cadence.
	PeriodID  string    `json:"period_id"`
	PeriodEnd time.Time `json:"period_end"`

	Checked int `json:"checked"`

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
	runPeriod, err := planner.DerivePeriod(&in.PeriodCfg, in.Reference)
	if err != nil {
		return nil, fmt.Errorf("manualdue: %w", err)
	}
	rep := &Report{
		Framework: in.Framework,
		PeriodID:  runPeriod.ID,
		PeriodEnd: runPeriod.End,
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
	period, err := planner.CadencePeriod(&in.PeriodCfg, in.Reference, entry.Cadence)
	if err != nil {
		return nil, fmt.Errorf("manualdue: %s: %w", entry.EvidenceID, err)
	}
	prefix := manual.FolderPrefix(in.Prefix, folderID, period.ID)
	items, err := in.Reader.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("manualdue: list %s: %w", prefix, err)
	}
	rep.Checked++
	if len(items) > 0 {
		return nil, nil
	}
	daysLeft := int(period.End.Sub(in.Reference).Hours() / 24)
	e := &Entry{
		CatalogID:    entry.EvidenceID,
		Cadence:      entry.Cadence,
		FolderURI:    manual.FolderURI(in.Scheme, in.Bucket, in.Prefix, folderID, period.ID),
		PeriodID:     period.ID,
		PeriodEnd:    period.End,
		WindowCloses: period.End.Add(entry.GracePeriod),
		DaysLeft:     daysLeft,
	}
	if !in.Unfiltered && daysLeft > in.WithinDays {
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
			"manual evidence: no manual evidence is due — %d entr%s checked, run period %s\n",
			rep.Checked, plural(rep.Checked), rep.PeriodID)
		return err
	}
	// Each entry has its own period — an annual entry's folder is the
	// year, a quarterly entry's is the quarter — so the count line names
	// the run's period only as context and the PERIOD column carries the
	// one that matters per row.
	if _, err := fmt.Fprintf(w,
		"manual evidence: %d of %d entr%s have an empty folder (run period %s)\n",
		len(rep.Missing), rep.Checked, plural(rep.Checked), rep.PeriodID); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "  ENTRY\tCADENCE\tPERIOD\tDUE IN\tUPLOAD TO"); err != nil {
		return err
	}
	for i := range rep.Missing {
		e := &rep.Missing[i]
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			entryLabel(e), dash(e.Cadence), e.PeriodID, dueIn(e), e.FolderURI); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w,
		"manual evidence: deadlines are measured from the HEAD commit's period; this notice does not fail the build.\n")
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
		if _, err := fmt.Fprintf(w, "::warning title=Manual evidence due::%s (%s) has no file for period %s — %s. Upload to %s\n",
			e.CatalogID, dash(e.Cadence), e.PeriodID, dueIn(e), e.FolderURI); err != nil {
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
		_, err := fmt.Fprintf(w, "## Manual evidence\n\nNothing due — %d entr%s checked, run period `%s`.\n",
			rep.Checked, plural(rep.Checked), rep.PeriodID)
		return err
	}
	if _, err := fmt.Fprintf(w,
		"## Manual evidence due\n\n%d of %d entr%s have an empty folder (run period `%s`).\n\n| Entry | Cadence | Period | Due in | Upload to |\n|---|---|---|---|---|\n",
		len(rep.Missing), rep.Checked, plural(rep.Checked), rep.PeriodID); err != nil {
		return err
	}
	for i := range rep.Missing {
		e := &rep.Missing[i]
		if _, err := fmt.Fprintf(w, "| `%s` | %s | `%s` | %s | `%s` |\n",
			e.CatalogID, dash(e.Cadence), e.PeriodID, dueIn(e), e.FolderURI); err != nil {
			return err
		}
	}
	return nil
}

func dueIn(e *Entry) string {
	if e.DaysLeft == 0 {
		return "today"
	}
	return fmt.Sprintf("%dd", e.DaysLeft)
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
