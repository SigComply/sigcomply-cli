package manualdue_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/manualdue"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

const (
	testPeriodQ1        = "2026-Q1"
	testCatalogAccess   = "access_review_quarterly"
	testCatalogTraining = "security_awareness_training"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func catalog() map[string]manual.CatalogEntry {
	return map[string]manual.CatalogEntry{
		testCatalogAccess: {
			EvidenceID:  testCatalogAccess,
			Cadence:     "quarterly",
			GracePeriod: 15 * 24 * time.Hour,
		},
		testCatalogTraining: {
			EvidenceID:  testCatalogTraining,
			Cadence:     "annual",
			GracePeriod: 30 * 24 * time.Hour,
		},
	}
}

func baseInput(t *testing.T, files map[string]manual.InMemoryFile, now time.Time) manualdue.Input {
	t.Helper()
	return manualdue.Input{
		Framework: "soc2",
		Catalog:   catalog(),
		Reader:    &manual.InMemoryReader{Files: files},
		Scheme:    "s3",
		Bucket:    "acme-evidence",
		Prefix:    "manual/",
		PeriodCfg: spec.PeriodConfig{},
		Reference: now,
		// Most tests care about the emptiness gate, not the lead window.
		Unfiltered: true,
	}
}

func TestScan_EmptyFoldersAreMissing(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Checked != 2 {
		t.Errorf("Checked = %d; want 2", rep.Checked)
	}
	if len(rep.Missing) != 2 {
		t.Fatalf("Missing = %d; want 2", len(rep.Missing))
	}
	if rep.PeriodID != testPeriodQ1 {
		t.Errorf("PeriodID = %q; want 2026-Q1", rep.PeriodID)
	}
}

// The zero-false-warning rule: an entry whose folder already holds a
// file is never reported, no matter how close the deadline is. This is
// the whole point of gating on emptiness rather than on the date alone.
func TestScan_PopulatedFolderIsNotMissing(t *testing.T) {
	files := map[string]manual.InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       []byte("%PDF-1.4"),
			UploadedAt: mustTime(t, "2026-02-01T00:00:00Z"),
		},
	}
	in := baseInput(t, files, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Missing) != 1 {
		t.Fatalf("Missing = %d; want 1", len(rep.Missing))
	}
	if rep.Missing[0].CatalogID != testCatalogTraining {
		t.Errorf("Missing[0] = %q; want security_awareness_training", rep.Missing[0].CatalogID)
	}
}

// A file in some other period's folder must not suppress the warning —
// the collector only ever reads the current period's folder.
func TestScan_FileInAnotherPeriodDoesNotCount(t *testing.T) {
	files := map[string]manual.InMemoryFile{
		"manual/access_review_quarterly/2025-Q4/evidence.pdf": {Data: []byte("x")},
	}
	in := baseInput(t, files, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Missing) != 2 {
		t.Fatalf("Missing = %d; want 2 (the 2025-Q4 file is not in scope)", len(rep.Missing))
	}
}

func TestScan_DaysLeftAndWindowClose(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := rep.Missing[0]
	if got.DaysLeft != 14 {
		t.Errorf("DaysLeft = %d; want 14", got.DaysLeft)
	}
	// quarterly grace is 15d, so the last moment an upload still counts
	// is period end + 15d.
	wantClose := mustTime(t, "2026-03-31T23:59:59Z").Add(time.Second - time.Nanosecond).Add(15 * 24 * time.Hour)
	if !got.WindowCloses.Equal(wantClose) {
		t.Errorf("WindowCloses = %s; want %s", got.WindowCloses, wantClose)
	}
}

func TestScan_WithinFiltersDistantDeadlines(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-01-05T00:00:00Z"))
	in.Unfiltered = false
	in.WithinDays = 30
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Missing) != 0 {
		t.Fatalf("Missing = %d; want 0 (period end is ~85 days out)", len(rep.Missing))
	}
	if rep.Checked != 2 {
		t.Errorf("Checked = %d; want 2 — filtering must not hide what was examined", rep.Checked)
	}
	if rep.Suppressed != 2 {
		t.Errorf("Suppressed = %d; want 2", rep.Suppressed)
	}
}

// An entry whose window closes today is reported however tight the lead
// time — --within-days 0 means "only what closes today", not "nothing".
func TestScan_ClosingTodayIsAlwaysReported(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-31T09:00:00Z"))
	in.Unfiltered = false
	in.WithinDays = 0
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Only the quarterly entry closes today; the annual one's window
	// runs to the end of the year.
	if len(rep.Missing) != 1 {
		t.Fatalf("Missing = %d; want 1", len(rep.Missing))
	}
	if rep.Missing[0].CatalogID != testCatalogAccess {
		t.Errorf("CatalogID = %q; want the quarterly entry", rep.Missing[0].CatalogID)
	}
	if rep.Missing[0].DaysLeft != 0 {
		t.Errorf("DaysLeft = %d; want 0", rep.Missing[0].DaysLeft)
	}
}

func TestScan_DeterministicOrder(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	var first []string
	for i := 0; i < 5; i++ {
		rep, err := manualdue.Scan(context.Background(), &in)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		ids := make([]string, 0, len(rep.Missing))
		for _, e := range rep.Missing {
			ids = append(ids, e.CatalogID)
		}
		if i == 0 {
			first = ids
			continue
		}
		if strings.Join(ids, ",") != strings.Join(first, ",") {
			t.Fatalf("order drifted: %v vs %v", ids, first)
		}
	}
}

func TestScan_FolderURIMatchesCollectScheme(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := manual.FolderURI("s3", "acme-evidence", "manual/", testCatalogAccess, testPeriodQ1)
	for _, e := range rep.Missing {
		if e.CatalogID == testCatalogAccess && e.FolderURI != want {
			t.Errorf("FolderURI = %q; want %q", e.FolderURI, want)
		}
	}
}

type errReader struct{}

func (errReader) Get(context.Context, string) ([]byte, time.Time, error) {
	return nil, time.Time{}, context.DeadlineExceeded
}
func (errReader) List(context.Context, string) ([]manual.FileInfo, error) {
	return nil, context.DeadlineExceeded
}

// A storage failure must surface as an error, never as "everything is
// missing" — inventing warnings we cannot substantiate is the failure
// mode this command exists to avoid.
func TestScan_ListErrorIsAnError(t *testing.T) {
	in := baseInput(t, nil, mustTime(t, "2026-03-17T00:00:00Z"))
	in.Reader = errReader{}
	if _, err := manualdue.Scan(context.Background(), &in); err == nil {
		t.Fatal("expected an error when the backend cannot be listed")
	}
}

func TestFormatText_NothingDue(t *testing.T) {
	rep := &manualdue.Report{Framework: "soc2", PeriodID: testPeriodQ1, Checked: 2}
	var buf bytes.Buffer
	if err := manualdue.FormatText(&buf, rep); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	if !strings.Contains(buf.String(), "no manual evidence is due") {
		t.Errorf("missing all-clear line:\n%s", buf.String())
	}
}

func TestFormatText_ListsEntries(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var buf bytes.Buffer
	if err := manualdue.FormatText(&buf, rep); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{testCatalogAccess, testPeriodQ1, "s3://acme-evidence/manual/"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatJSON_RoundTrips(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var buf bytes.Buffer
	if err := manualdue.FormatJSON(&buf, rep); err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var back manualdue.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Missing) != len(rep.Missing) {
		t.Errorf("round-trip lost entries: %d vs %d", len(back.Missing), len(rep.Missing))
	}
}

func TestFormatGitHubAnnotations_CapsAtLimit(t *testing.T) {
	cat := map[string]manual.CatalogEntry{}
	for i := 0; i < 15; i++ {
		id := string(rune('a'+i)) + "_entry"
		cat[id] = manual.CatalogEntry{EvidenceID: id, Cadence: "annual", GracePeriod: 30 * 24 * time.Hour}
	}
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	in.Catalog = cat
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var buf bytes.Buffer
	if err := manualdue.FormatGitHubAnnotations(&buf, rep); err != nil {
		t.Fatalf("FormatGitHubAnnotations: %v", err)
	}
	out := buf.String()
	// GitHub renders at most 10 warning annotations per step, and the
	// overflow notice is one of them — so 9 entries + 1 overflow line.
	if n := strings.Count(out, "::warning"); n != 10 {
		t.Errorf("::warning count = %d; want 10 (9 entries + overflow)", n)
	}
	if !strings.Contains(out, "6 more") {
		t.Errorf("missing overflow line:\n%s", out)
	}
}

// --within-days 0 must mean "only what closes today", not "no filter".
// The natural reading of a zero lead time is the strict one, and silently
// widening it would report 47 entries to someone who asked for the few
// that are genuinely urgent.
func TestScan_ZeroWithinReportsOnlyWhatClosesToday(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	in.Unfiltered = false
	in.WithinDays = 0
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Missing) != 0 {
		t.Errorf("Missing = %d; want 0 — nothing is overdue on 2026-03-17", len(rep.Missing))
	}
	if rep.Suppressed != 2 {
		t.Errorf("Suppressed = %d; want 2", rep.Suppressed)
	}
}

// An annual entry's folder is the year, not whichever quarter the run
// happens to land in — the folder `check` will read, and the folder the
// Evidence SPA tells the customer to upload to.
func TestScan_FolderFollowsTheEntryCadence(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := map[string]string{
		testCatalogAccess:   testPeriodQ1,
		testCatalogTraining: "2026",
	}
	for _, e := range rep.Missing {
		wantPeriod, ok := want[e.CatalogID]
		if !ok {
			t.Fatalf("unexpected entry %q", e.CatalogID)
		}
		if e.PeriodID != wantPeriod {
			t.Errorf("%s: PeriodID = %q; want %q", e.CatalogID, e.PeriodID, wantPeriod)
		}
		wantURI := manual.FolderURI("s3", "acme-evidence", "manual/", e.CatalogID, wantPeriod)
		if e.FolderURI != wantURI {
			t.Errorf("%s: FolderURI = %q; want %q", e.CatalogID, e.FolderURI, wantURI)
		}
	}
}

// An annual upload made in January satisfies the folder a December run
// reads, so it must not still be reported as due in December.
func TestScan_AnnualUploadSatisfiesTheWholeYear(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{
		"manual/security_awareness_training/2026/evidence.pdf": {Data: []byte("x")},
	}, mustTime(t, "2026-12-20T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range rep.Missing {
		if e.CatalogID == testCatalogTraining {
			t.Errorf("%s reported as due despite a January upload in %s", e.CatalogID, e.FolderURI)
		}
	}
}

// Deadlines are measured on the clock the period was derived from. A
// stale HEAD used to report the previous quarter as overdue by however
// many days the wall clock had moved on.
func TestScan_DeadlineUsesThePeriodReferenceClock(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-03-17T00:00:00Z"))
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var quarterly *manualdue.Entry
	for i := range rep.Missing {
		if rep.Missing[i].CatalogID == testCatalogAccess {
			quarterly = &rep.Missing[i]
		}
	}
	if quarterly == nil {
		t.Fatal("quarterly entry not reported")
	}
	if quarterly.DaysLeft < 0 {
		t.Errorf("DaysLeft = %d; want a non-negative count — 2026-03-17 is inside 2026-Q1", quarterly.DaysLeft)
	}
	if quarterly.DaysLeft != 14 {
		t.Errorf("DaysLeft = %d; want 14", quarterly.DaysLeft)
	}
}

// A custom calendar cannot be subdivided, so every entry keeps the run's
// period whatever its cadence.
func TestScan_CustomCalendarKeepsOnePeriodForEveryEntry(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-02-10T00:00:00Z"))
	in.PeriodCfg = spec.PeriodConfig{
		FiscalCalendar: spec.FiscalCalendarConfig{
			Type: "custom",
			Periods: []spec.CustomPeriod{
				{ID: "2026-P01", Start: "2026-01-04", End: "2026-01-31"},
				{ID: "2026-P02", Start: "2026-02-01", End: "2026-02-28"},
			},
		},
	}
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Missing) != 2 {
		t.Fatalf("Missing = %d; want 2", len(rep.Missing))
	}
	for _, e := range rep.Missing {
		if e.PeriodID != "2026-P02" {
			t.Errorf("%s: PeriodID = %q; want the run period 2026-P02", e.CatalogID, e.PeriodID)
		}
	}
}
