package manualdue_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/manualdue"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func q1(t *testing.T) planner.Period {
	return planner.Period{
		ID:      "2026-Q1",
		PriorID: "2025-Q4",
		Start:   mustTime(t, "2026-01-01T00:00:00Z"),
		End:     mustTime(t, "2026-03-31T23:59:59Z"),
	}
}

func catalog() map[string]manual.CatalogEntry {
	return map[string]manual.CatalogEntry{
		"access_review_quarterly": {
			EvidenceID:  "access_review_quarterly",
			Cadence:     "quarterly",
			GracePeriod: 15 * 24 * time.Hour,
		},
		"security_awareness_training": {
			EvidenceID:  "security_awareness_training",
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
		Period:    q1(t),
		Now:       now,
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
	if rep.PeriodID != "2026-Q1" {
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
	if rep.Missing[0].CatalogID != "security_awareness_training" {
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
	wantClose := mustTime(t, "2026-04-15T23:59:59Z")
	if !got.WindowCloses.Equal(wantClose) {
		t.Errorf("WindowCloses = %s; want %s", got.WindowCloses, wantClose)
	}
}

func TestScan_WithinFiltersDistantDeadlines(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-01-05T00:00:00Z"))
	in.Within = 30 * 24 * time.Hour
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

// An overdue entry is always reported, however far past the deadline —
// --within is a lead-time window, not a two-sided filter.
func TestScan_OverdueAlwaysReported(t *testing.T) {
	in := baseInput(t, map[string]manual.InMemoryFile{}, mustTime(t, "2026-04-20T00:00:00Z"))
	in.Within = 24 * time.Hour
	rep, err := manualdue.Scan(context.Background(), &in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Missing) != 2 {
		t.Fatalf("Missing = %d; want 2", len(rep.Missing))
	}
	if rep.Missing[0].DaysLeft >= 0 {
		t.Errorf("DaysLeft = %d; want negative (overdue)", rep.Missing[0].DaysLeft)
	}
	if !rep.Missing[0].Overdue {
		t.Error("Overdue = false; want true")
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
	want := manual.FolderURI("s3", "acme-evidence", "manual/", "access_review_quarterly", "2026-Q1")
	for _, e := range rep.Missing {
		if e.CatalogID == "access_review_quarterly" && e.FolderURI != want {
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
	rep := &manualdue.Report{Framework: "soc2", PeriodID: "2026-Q1", Checked: 2}
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
	for _, want := range []string{"access_review_quarterly", "2026-Q1", "s3://acme-evidence/manual/"} {
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
