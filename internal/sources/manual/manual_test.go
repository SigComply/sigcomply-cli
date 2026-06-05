package manual

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
)

// realPDF creates a genuine, pdfcpu-compatible PDF via fileconv so
// that merge tests work correctly. Using this instead of a hand-crafted
// byte sequence ensures the merged PDF passes both validatePDF and
// pdfcpu's internal parser.
func realPDF(t *testing.T) []byte {
	t.Helper()
	pdf, _, err := fileconv.ToPDF("test.png", ".png", minimalPNG())
	if err != nil {
		t.Fatalf("realPDF: %v", err)
	}
	return pdf
}

// fakePDF returns a payload that passes validatePDF: starts with the
// PDF magic bytes, is padded past minPDFBytes, and contains the /Page
// marker. Used only in tests that don't exercise the merge path (e.g.
// single-file present/absent/window checks). Tests that exercise merging
// (multi-file, copy-paste) use realPDF() instead.
func fakePDF() []byte {
	parts := [][]byte{
		[]byte("%PDF-1.4\n"),
		[]byte("1 0 obj\n<< /Type /Page >>\nendobj\n"),
		bytes.Repeat([]byte("x"), minPDFBytes),
	}
	return bytes.Join(parts, nil)
}

// minimalPNG returns a 1×1 white PNG suitable for fileconv input.
func minimalPNG() []byte {
	return []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D,
		0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x08, 0x02,
		0x00, 0x00, 0x00,
		0x90, 0x77, 0x53, 0xDE,
		0x00, 0x00, 0x00, 0x0C,
		0x49, 0x44, 0x41, 0x54,
		0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		0xE2, 0x21, 0xBC, 0x33,
		0x00, 0x00, 0x00, 0x00,
		0x49, 0x45, 0x4E, 0x44,
		0xAE, 0x42, 0x60, 0x82,
	}
}

func newTestPlugin(files map[string]InMemoryFile) *Plugin {
	return New(Options{
		Reader: &InMemoryReader{Files: files},
		Bucket: "acme-evidence",
		Prefix: "manual/",
		Scheme: "s3",
		Catalog: map[string]CatalogEntry{
			"access_review_quarterly": {
				EvidenceID:   "access_review_quarterly",
				Filename:     "evidence.pdf", // kept for compat; ignored in collection
				Cadence:      "quarterly",
				TemporalRule: "retrospective",
				GracePeriod:  15 * 24 * time.Hour,
			},
		},
	})
}

func baseReq(periodID string, extra map[string]any) core.SlotRequest {
	params := map[string]any{
		"catalog_id":   "access_review_quarterly",
		"period_id":    periodID,
		"period_start": mustTime("2026-01-01T00:00:00Z"),
		"period_end":   mustTime("2026-03-31T23:59:59Z"),
		"now":          mustTime("2026-04-01T00:00:00Z"),
	}
	for k, v := range extra {
		params[k] = v
	}
	return core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params:        params,
	}
}

func unmarshalManifest(t *testing.T, records []core.EvidenceRecord) manualManifest {
	t.Helper()
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1", len(records))
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return m
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := newTestPlugin(nil)
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != EvidenceTypeID {
		t.Errorf("Emits = %v; want [%s]", emits, EvidenceTypeID)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := newTestPlugin(nil)
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_PresentInWindow: single PDF in folder, all checks pass.
func TestCollect_PresentInWindow(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       realPDF(t),
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)

	if !m.FilePresent {
		t.Errorf("FilePresent = false; want true")
	}
	if !m.InTemporalWindow {
		t.Errorf("InTemporalWindow = false; want true")
	}
	if !m.FileValid {
		t.Errorf("FileValid = false; want true; failures = %v", m.ValidationFailures)
	}
	if len(m.ValidationFailures) != 0 {
		t.Errorf("ValidationFailures = %v; want empty", m.ValidationFailures)
	}
	if !strings.HasPrefix(m.FileHash, "sha256:") {
		t.Errorf("FileHash = %q; want sha256: prefix", m.FileHash)
	}
	// ExpectedURI is now the folder URI, not a specific file.
	wantURI := "s3://acme-evidence/manual/access_review_quarterly/2026-Q1/"
	if m.ExpectedURI != wantURI {
		t.Errorf("ExpectedURI = %q; want %q", m.ExpectedURI, wantURI)
	}
	if len(m.SourceFiles) != 1 {
		t.Errorf("len(SourceFiles) = %d; want 1", len(m.SourceFiles))
	} else {
		sf := m.SourceFiles[0]
		if sf.Filename != "evidence.pdf" {
			t.Errorf("SourceFiles[0].Filename = %q; want evidence.pdf", sf.Filename)
		}
		if sf.Type != "pdf" {
			t.Errorf("SourceFiles[0].Type = %q; want pdf", sf.Type)
		}
		if sf.Converted {
			t.Error("SourceFiles[0].Converted = true; want false for PDF")
		}
	}
}

// TestCollect_Missing: empty folder → file_present=false.
func TestCollect_Missing(t *testing.T) {
	p := newTestPlugin(map[string]InMemoryFile{})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if m.FilePresent {
		t.Errorf("FilePresent = true; want false (empty folder)")
	}
	if m.InTemporalWindow {
		t.Errorf("InTemporalWindow = true; want false (empty folder)")
	}
	wantURI := "s3://acme-evidence/manual/access_review_quarterly/2026-Q1/"
	if m.ExpectedURI != wantURI {
		t.Errorf("ExpectedURI = %q; want %q", m.ExpectedURI, wantURI)
	}
}

// TestCollect_PresentOutsideWindow: file exists but upload time is before period.
func TestCollect_PresentOutsideWindow(t *testing.T) {
	uploadedAt := mustTime("2025-11-15T10:00:00Z") // before period start
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       realPDF(t),
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if !m.FilePresent {
		t.Errorf("FilePresent should be true")
	}
	if m.InTemporalWindow {
		t.Errorf("InTemporalWindow should be false (uploaded before period)")
	}
}

// TestCollect_MultipleFiles: multiple files in folder are merged into one PDF.
func TestCollect_MultipleFiles(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/01_review.pdf": {
			Data:       realPDF(t),
			UploadedAt: uploadedAt,
		},
		"manual/access_review_quarterly/2026-Q1/02_approval.png": {
			Data:       minimalPNG(),
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)

	if !m.FilePresent {
		t.Errorf("FilePresent = false; want true")
	}
	if !m.FileValid {
		t.Errorf("FileValid = false; want true; failures = %v", m.ValidationFailures)
	}
	if len(m.SourceFiles) != 2 {
		t.Errorf("len(SourceFiles) = %d; want 2", len(m.SourceFiles))
	}
	// Verify both source file types are recorded.
	types := map[string]bool{}
	for _, sf := range m.SourceFiles {
		types[sf.Type] = true
	}
	if !types["pdf"] {
		t.Error("SourceFiles missing pdf entry")
	}
	if !types["png"] {
		t.Error("SourceFiles missing png entry")
	}
	// PNG was converted.
	for _, sf := range m.SourceFiles {
		if sf.Type == "png" && !sf.Converted {
			t.Error("PNG SourceFile.Converted = false; want true")
		}
	}
}

// TestCollect_ImageOnlyFolder: only image files in folder, all converted.
func TestCollect_ImageOnlyFolder(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/scan.png": {
			Data:       minimalPNG(),
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)

	if !m.FilePresent {
		t.Errorf("FilePresent = false; want true")
	}
	if !m.FileValid {
		t.Errorf("FileValid = false; want true; failures = %v", m.ValidationFailures)
	}
	if len(m.SourceFiles) != 1 || !m.SourceFiles[0].Converted {
		t.Errorf("expected one converted source file; got %+v", m.SourceFiles)
	}
}

// TestCollect_UnsupportedFileType: .docx in folder → validation failure with clear message.
func TestCollect_UnsupportedFileType(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       realPDF(t),
			UploadedAt: uploadedAt,
		},
		"manual/access_review_quarterly/2026-Q1/report.docx": {
			Data:       []byte("PK...fake docx..."),
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)

	if !m.FilePresent {
		t.Errorf("FilePresent = false; want true")
	}
	// file_valid=false because of unsupported type.
	if m.FileValid {
		t.Errorf("FileValid = true; want false (unsupported .docx present)")
	}
	// The error message must be actionable.
	found := false
	for _, f := range m.ValidationFailures {
		if strings.Contains(f, "unsupported_file_type") && strings.Contains(f, ".docx") {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidationFailures = %v; want unsupported_file_type entry mentioning .docx", m.ValidationFailures)
	}
}

// TestCollect_AllUnsupportedTypes: only unsupported files → file_valid=false, file_present=true.
func TestCollect_AllUnsupportedTypes(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/report.docx": {
			Data:       []byte("PK...fake docx..."),
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if !m.FilePresent {
		t.Errorf("FilePresent = false; want true (files exist)")
	}
	if m.FileValid {
		t.Errorf("FileValid = true; want false (only unsupported types)")
	}
}

// TestCollect_PresentButEmpty: 0-byte PDF → validation failure.
func TestCollect_PresentButEmpty(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       []byte{},
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if !m.FilePresent {
		t.Errorf("FilePresent = false; want true (0-byte file is still 'present at path')")
	}
	if m.FileValid {
		t.Errorf("FileValid = true; want false (0-byte file fails validatePDF)")
	}
	if len(m.ValidationFailures) == 0 {
		t.Errorf("ValidationFailures empty; want size-check failure")
	}
}

// TestCollect_PresentButNotPDF: non-PDF bytes with .pdf extension → missing_pdf_header.
func TestCollect_PresentButNotPDF(t *testing.T) {
	nonPDF := append([]byte("This is not a PDF, just plain text. "), bytes.Repeat([]byte("x"), minPDFBytes)...)
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       nonPDF,
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if m.FileValid {
		t.Errorf("FileValid = true; want false (missing PDF header)")
	}
	found := false
	for _, f := range m.ValidationFailures {
		if strings.HasPrefix(f, "missing_pdf_header") {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidationFailures = %v; want missing_pdf_header entry", m.ValidationFailures)
	}
}

// TestCollect_DetectsCopyPasteOfPriorPeriod: same source files in Q1 and Q2.
func TestCollect_DetectsCopyPasteOfPriorPeriod(t *testing.T) {
	body := realPDF(t)
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       body,
			UploadedAt: mustTime("2026-02-15T10:00:00Z"),
		},
		"manual/access_review_quarterly/2026-Q2/evidence.pdf": {
			Data:       body,
			UploadedAt: mustTime("2026-05-15T10:00:00Z"),
		},
	})
	req := baseReq("2026-Q2", map[string]any{
		"prior_period_id": "2026-Q1",
		"period_start":    mustTime("2026-04-01T00:00:00Z"),
		"period_end":      mustTime("2026-06-30T23:59:59Z"),
	})
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if m.FileValid {
		t.Errorf("FileValid = true; want false (copy-paste of prior period)")
	}
	found := false
	for _, f := range m.ValidationFailures {
		if strings.HasPrefix(f, "copy_paste_of_prior_period") {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidationFailures = %v; want copy_paste_of_prior_period entry", m.ValidationFailures)
	}
}

// TestCollect_PriorPeriodMissingIsNotAFailure: no Q4 files exist, Q1 should still pass.
func TestCollect_PriorPeriodMissingIsNotAFailure(t *testing.T) {
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       realPDF(t),
			UploadedAt: mustTime("2026-02-15T10:00:00Z"),
		},
	})
	req := baseReq("2026-Q1", map[string]any{
		"prior_period_id": "2025-Q4",
	})
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if !m.FileValid {
		t.Errorf("FileValid = false; want true (prior period missing is fine); failures = %v", m.ValidationFailures)
	}
}

// TestCollect_LatestUploadTimeUsed: when multiple files exist, the latest
// upload time governs the temporal window check.
func TestCollect_LatestUploadTimeUsed(t *testing.T) {
	// First file within window, second file outside (future) — still pass
	// because both are "within" (the window end has a grace period).
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/doc1.pdf": {
			Data:       realPDF(t),
			UploadedAt: mustTime("2026-02-10T00:00:00Z"),
		},
		"manual/access_review_quarterly/2026-Q1/doc2.pdf": {
			Data:       realPDF(t),
			UploadedAt: mustTime("2026-02-20T00:00:00Z"),
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	if !m.InTemporalWindow {
		t.Errorf("InTemporalWindow = false; want true")
	}
	// UploadedAt should be the latest.
	want := mustTime("2026-02-20T00:00:00Z")
	if !m.UploadedAt.Equal(want) {
		t.Errorf("UploadedAt = %v; want %v", m.UploadedAt, want)
	}
}

func TestValidatePDF_Cases(t *testing.T) {
	headerOnly := append([]byte("%PDF-1.4\n"), bytes.Repeat([]byte(" "), minPDFBytes)...)
	cases := []struct {
		name         string
		data         []byte
		wantFailures int
	}{
		{"valid", fakePDF(), 0},
		{"empty", []byte{}, 3}, // size + magic + pages all fail
		{"too_small_with_header", []byte("%PDF-1.4"), 2},
		{"large_but_no_header", append([]byte("not a pdf "), bytes.Repeat([]byte("x"), minPDFBytes)...), 2},
		{"header_but_no_pages", headerOnly, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validatePDF(tc.data)
			if len(got) != tc.wantFailures {
				t.Errorf("validatePDF: got %d failures (%v); want %d", len(got), got, tc.wantFailures)
			}
		})
	}
}

func TestCollect_RejectsBadEvidenceType(t *testing.T) {
	p := newTestPlugin(nil)
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_MissingCatalogID(t *testing.T) {
	p := newTestPlugin(nil)
	_, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypeID},
		Params:        map[string]any{"period_id": "2026-Q1"},
	})
	if err == nil || !strings.Contains(err.Error(), "catalog_id missing") {
		t.Errorf("want catalog_id missing error; got %v", err)
	}
}

func TestCollect_UnknownCatalogEntry(t *testing.T) {
	p := newTestPlugin(nil)
	_, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypeID},
		Params: map[string]any{
			"catalog_id": "does_not_exist",
			"period_id":  "2026-Q1",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Errorf("want unknown-catalog error; got %v", err)
	}
}

func TestCollect_MissingPeriodID(t *testing.T) {
	p := newTestPlugin(nil)
	_, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypeID},
		Params:        map[string]any{"catalog_id": "access_review_quarterly"},
	})
	if err == nil || !strings.Contains(err.Error(), "period_id missing") {
		t.Errorf("want period_id missing error; got %v", err)
	}
}

func TestBuildURI_AllSchemes(t *testing.T) {
	for _, sc := range []string{"s3", "gs", "azure", "file", ""} {
		p := New(Options{Bucket: "b", Prefix: "manual/", Scheme: sc})
		got := p.buildURI("manual/x/y/z/")
		if got == "" {
			t.Errorf("scheme %q produced empty URI", sc)
		}
	}
	pNoBucket := New(Options{Scheme: "file"})
	if got := pNoBucket.buildURI("manual/x/"); got != "manual/x/" {
		t.Errorf("no-bucket file URI = %q", got)
	}
}

func TestSortedCatalogIDs(t *testing.T) {
	got := SortedCatalogIDs(map[string]CatalogEntry{"b": {}, "a": {}, "c": {}})
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SortedCatalogIDs[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestInMemoryReader_List(t *testing.T) {
	r := &InMemoryReader{Files: map[string]InMemoryFile{
		"manual/ev/2026-Q1/a.pdf": {Data: []byte("a")},
		"manual/ev/2026-Q1/b.png": {Data: []byte("b")},
		"manual/ev/2026-Q2/c.pdf": {Data: []byte("c")},
	}}
	items, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d; want 2", len(items))
	}
	if items[0].Key != "manual/ev/2026-Q1/a.pdf" {
		t.Errorf("items[0].Key = %q; want a.pdf", items[0].Key)
	}
	if items[1].Key != "manual/ev/2026-Q1/b.png" {
		t.Errorf("items[1].Key = %q; want b.png", items[1].Key)
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// ---------------------------------------------------------------------------
// extToTypeName
// ---------------------------------------------------------------------------

func TestExtToTypeName_AllCases(t *testing.T) {
	cases := []struct {
		ext  string
		want string
	}{
		{".pdf", "pdf"},
		{".jpg", "jpeg"},
		{".jpeg", "jpeg"},
		{".png", "png"},
		{".gif", "gif"},
		{".tif", "tiff"},
		{".tiff", "tiff"},
		{".webp", "webp"},
		{".bmp", "bmp"},
		{".unknown", "unknown"}, // default: strip leading dot
		{".XYZ", "XYZ"},         // default: strip leading dot, preserve case
	}
	for _, tc := range cases {
		t.Run(tc.ext, func(t *testing.T) {
			got := extToTypeName(tc.ext)
			if got != tc.want {
				t.Errorf("extToTypeName(%q) = %q; want %q", tc.ext, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isInTemporalWindow
// ---------------------------------------------------------------------------

func TestIsInTemporalWindow_ZeroUploadedAt(t *testing.T) {
	// zero uploadedAt must always return false
	start := mustTime("2026-01-01T00:00:00Z")
	end := mustTime("2026-03-31T23:59:59Z")
	if isInTemporalWindow(time.Time{}, start, end, 0) {
		t.Error("isInTemporalWindow with zero uploadedAt should return false")
	}
}

func TestIsInTemporalWindow_ZeroStart(t *testing.T) {
	// zero start must always return false
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	end := mustTime("2026-03-31T23:59:59Z")
	if isInTemporalWindow(uploadedAt, time.Time{}, end, 0) {
		t.Error("isInTemporalWindow with zero start should return false")
	}
}

func TestIsInTemporalWindow_ZeroEnd(t *testing.T) {
	// zero end must always return false
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	start := mustTime("2026-01-01T00:00:00Z")
	if isInTemporalWindow(uploadedAt, start, time.Time{}, 0) {
		t.Error("isInTemporalWindow with zero end should return false")
	}
}

func TestIsInTemporalWindow_WithGrace(t *testing.T) {
	start := mustTime("2026-01-01T00:00:00Z")
	end := mustTime("2026-03-31T23:59:59Z")
	grace := 15 * 24 * time.Hour

	// uploaded exactly at period_end + grace boundary — still in window
	atGraceBoundary := end.Add(grace)
	if !isInTemporalWindow(atGraceBoundary, start, end, grace) {
		t.Error("upload exactly at grace boundary should be in window")
	}

	// uploaded one nanosecond after grace — out of window
	afterGrace := end.Add(grace + time.Nanosecond)
	if isInTemporalWindow(afterGrace, start, end, grace) {
		t.Error("upload just after grace should be out of window")
	}
}

func TestIsInTemporalWindow_BeforeStart(t *testing.T) {
	start := mustTime("2026-01-01T00:00:00Z")
	end := mustTime("2026-03-31T23:59:59Z")
	uploadedAt := mustTime("2025-12-31T23:59:58Z")
	if isInTemporalWindow(uploadedAt, start, end, 0) {
		t.Error("upload before period_start should be out of window")
	}
}

// ---------------------------------------------------------------------------
// timeParam
// ---------------------------------------------------------------------------

func TestTimeParam_PresentAndAbsent(t *testing.T) {
	want := mustTime("2026-02-15T10:00:00Z")
	m := map[string]any{"ts": want, "other": "not a time"}

	if got := timeParam(m, "ts"); !got.Equal(want) {
		t.Errorf("timeParam present: got %v; want %v", got, want)
	}
	if got := timeParam(m, "missing"); !got.IsZero() {
		t.Errorf("timeParam missing: got %v; want zero", got)
	}
	// key present but wrong type → zero
	if got := timeParam(m, "other"); !got.IsZero() {
		t.Errorf("timeParam wrong type: got %v; want zero", got)
	}
}

// ---------------------------------------------------------------------------
// InMemoryReader.Get
// ---------------------------------------------------------------------------

func TestInMemoryReader_Get_FoundAndMissing(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	r := &InMemoryReader{Files: map[string]InMemoryFile{
		"manual/ev/2026-Q1/a.pdf": {Data: []byte("body"), UploadedAt: uploadedAt},
	}}

	// present key
	data, ts, err := r.Get(context.Background(), "manual/ev/2026-Q1/a.pdf")
	if err != nil {
		t.Fatalf("Get (present): %v", err)
	}
	if string(data) != "body" {
		t.Errorf("Get data: got %q; want %q", data, "body")
	}
	if !ts.Equal(uploadedAt) {
		t.Errorf("Get uploadedAt: got %v; want %v", ts, uploadedAt)
	}

	// missing key → ErrNotFound
	_, _, err = r.Get(context.Background(), "manual/ev/2026-Q1/missing.pdf")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get (missing): got %v; want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Collect — fetch error propagation
// ---------------------------------------------------------------------------

// errReader returns ErrNotFound from List but a transport error from Get.
type errOnGetReader struct {
	listItems []FileInfo
	getErr    error
}

func (r *errOnGetReader) Get(_ context.Context, _ string) ([]byte, time.Time, error) {
	return nil, time.Time{}, r.getErr
}

func (r *errOnGetReader) List(_ context.Context, _ string) ([]FileInfo, error) {
	return r.listItems, nil
}

func TestCollect_FetchErrorPropagates(t *testing.T) {
	// List returns one supported file, but Get fails with a transport error.
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	sentinel := errors.New("synthetic transport failure")
	p := New(Options{
		Reader: &errOnGetReader{
			listItems: []FileInfo{{Key: "manual/access_review_quarterly/2026-Q1/evidence.pdf", UploadedAt: uploadedAt}},
			getErr:    sentinel,
		},
		Bucket:  "acme-evidence",
		Prefix:  "manual/",
		Scheme:  "s3",
		Catalog: map[string]CatalogEntry{"access_review_quarterly": {EvidenceID: "access_review_quarterly", GracePeriod: 0}},
	})
	_, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err == nil {
		t.Fatal("Collect: expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Collect error: got %v; want to wrap sentinel", err)
	}
}

// ---------------------------------------------------------------------------
// localReader.List
// ---------------------------------------------------------------------------

func TestLocalReader_List_Success(t *testing.T) {
	tmp := t.TempDir()
	subdir := filepath.Join(tmp, "manual", "ev", "2026-Q1")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Write two files and a sub-directory (should be skipped).
	for _, name := range []string{"a.pdf", "b.png"} {
		if err := os.WriteFile(filepath.Join(subdir, name), []byte(name), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(subdir, "nested"), 0o750); err != nil {
		t.Fatalf("MkdirAll nested: %v", err)
	}

	r := &localReader{root: tmp}
	items, err := r.List(context.Background(), "manual/ev/2026-Q1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d; want 2", len(items))
	}
	// Items must be sorted by key.
	if items[0].Key != "manual/ev/2026-Q1/a.pdf" {
		t.Errorf("items[0].Key = %q; want manual/ev/2026-Q1/a.pdf", items[0].Key)
	}
	if items[1].Key != "manual/ev/2026-Q1/b.png" {
		t.Errorf("items[1].Key = %q; want manual/ev/2026-Q1/b.png", items[1].Key)
	}
	// UploadedAt must be non-zero (taken from os.Stat ModTime).
	for _, item := range items {
		if item.UploadedAt.IsZero() {
			t.Errorf("item %q: UploadedAt is zero; want non-zero", item.Key)
		}
	}
}

func TestLocalReader_List_MissingDir(t *testing.T) {
	r := &localReader{root: t.TempDir()}
	items, err := r.List(context.Background(), "does/not/exist/")
	if err != nil {
		t.Fatalf("List (missing dir): %v; want nil error (missing dir is not an error)", err)
	}
	if len(items) != 0 {
		t.Errorf("List (missing dir): got %d items; want 0", len(items))
	}
}

func TestLocalReader_List_EmptyDir(t *testing.T) {
	tmp := t.TempDir()
	subdir := filepath.Join(tmp, "manual", "ev", "empty")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	r := &localReader{root: tmp}
	items, err := r.List(context.Background(), "manual/ev/empty/")
	if err != nil {
		t.Fatalf("List (empty dir): %v", err)
	}
	if len(items) != 0 {
		t.Errorf("List (empty dir): got %d items; want 0", len(items))
	}
}

// ---------------------------------------------------------------------------
// RegisterReader panic guards
// ---------------------------------------------------------------------------

func TestRegisterReader_PanicsOnEmptyID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterReader with empty ID: expected panic, got none")
		}
	}()
	RegisterReader("", func(_ map[string]any) (Reader, string, string, string, error) {
		return nil, "", "", "", nil
	})
}

func TestRegisterReader_PanicsOnNilFactory(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterReader with nil factory: expected panic, got none")
		}
	}()
	RegisterReader("test-nil-factory-should-panic", nil)
}

func TestRegisterReader_PanicsOnDuplicate(t *testing.T) {
	// "local" is registered by init() — re-registering must panic.
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterReader duplicate: expected panic, got none")
		}
	}()
	RegisterReader("local", func(_ map[string]any) (Reader, string, string, string, error) {
		return nil, "", "", "", nil
	})
}

// ---------------------------------------------------------------------------
// Collect — list error propagation
// ---------------------------------------------------------------------------

// errListReader returns an error from List so we can cover the list-error
// branch inside Collect.
type errListReader struct {
	listErr error
}

func (r *errListReader) Get(_ context.Context, _ string) ([]byte, time.Time, error) {
	return nil, time.Time{}, ErrNotFound
}
func (r *errListReader) List(_ context.Context, _ string) ([]FileInfo, error) {
	return nil, r.listErr
}

func TestCollect_ListErrorPropagates(t *testing.T) {
	sentinel := errors.New("synthetic list transport error")
	p := New(Options{
		Reader: &errListReader{listErr: sentinel},
		Bucket: "acme-evidence",
		Prefix: "manual/",
		Scheme: "s3",
		Catalog: map[string]CatalogEntry{
			"access_review_quarterly": {EvidenceID: "access_review_quarterly"},
		},
	})
	_, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err == nil {
		t.Fatal("Collect: expected error from List, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Collect error: got %v; want to wrap sentinel", err)
	}
}

// ---------------------------------------------------------------------------
// parseCollectParams — now defaults to time.Now() when omitted
// ---------------------------------------------------------------------------

func TestCollect_NowDefaultsToCurrentTime(t *testing.T) {
	// Omit "now" from params. parseCollectParams should default to time.Now().
	before := time.Now().UTC()
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       realPDF(t),
			UploadedAt: mustTime("2026-02-15T10:00:00Z"),
		},
	})
	params := map[string]any{
		"catalog_id":   "access_review_quarterly",
		"period_id":    "2026-Q1",
		"period_start": mustTime("2026-01-01T00:00:00Z"),
		"period_end":   mustTime("2026-03-31T23:59:59Z"),
		// Deliberately omit "now".
	}
	records, err := p.Collect(context.Background(), core.SlotRequest{
		PolicyID:      "test",
		AcceptedTypes: []string{EvidenceTypeID},
		Params:        params,
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1", len(records))
	}
	// CollectedAt should be between before and after (i.e., time.Now() was used).
	collectedAt := records[0].CollectedAt
	if collectedAt.Before(before) || collectedAt.After(after) {
		t.Errorf("CollectedAt = %v; want between %v and %v (now default)", collectedAt, before, after)
	}
}

// ---------------------------------------------------------------------------
// mergeAndValidate — merge failure path
// ---------------------------------------------------------------------------

func TestMergeAndValidate_MergeFailure(t *testing.T) {
	// pdfmerge.Merge with a single PDF is a no-op pass-through; to trigger
	// a real merge error we need ≥2 inputs that pdfcpu cannot parse.
	bad := []byte("not a pdf at all")
	hash, size, failures := mergeAndValidate([][]byte{bad, bad})
	if hash != "" {
		t.Errorf("hash = %q; want empty on merge failure", hash)
	}
	if size != 0 {
		t.Errorf("size = %d; want 0 on merge failure", size)
	}
	if len(failures) == 0 {
		t.Error("failures is empty; want at least one merge_failed entry")
	}
	found := false
	for _, f := range failures {
		if strings.HasPrefix(f, "merge_failed") {
			found = true
		}
	}
	if !found {
		t.Errorf("failures = %v; want merge_failed entry", failures)
	}
}

// ---------------------------------------------------------------------------
// fetchAndConvert — conversion failure (corrupt image bytes)
// ---------------------------------------------------------------------------

func TestCollect_ConversionFailureRecordedAsValidationFailure(t *testing.T) {
	// A .png file with garbage bytes will fail fileconv.ToPDF (image decode error).
	// The plugin should record a conversion_failed validation_failure and
	// continue — not abort the Collect call.
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       realPDF(t),
			UploadedAt: uploadedAt,
		},
		"manual/access_review_quarterly/2026-Q1/corrupt.png": {
			Data:       []byte("this is not a png"), // valid ext, corrupt bytes
			UploadedAt: uploadedAt,
		},
	})
	records, err := p.Collect(context.Background(), baseReq("2026-Q1", nil))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	// file_valid must be false because of conversion failure
	if m.FileValid {
		t.Errorf("FileValid = true; want false (corrupt PNG)")
	}
	found := false
	for _, f := range m.ValidationFailures {
		if strings.HasPrefix(f, "conversion_failed") {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidationFailures = %v; want conversion_failed entry", m.ValidationFailures)
	}
}

// ---------------------------------------------------------------------------
// checkPriorPeriod — unsupported file in prior period folder
// ---------------------------------------------------------------------------

func TestCollect_PriorPeriodUnsupportedFileSkipped(t *testing.T) {
	// Prior period folder contains only an unsupported file (.docx).
	// The prior-period check must not flag a copy-paste (no matching hashes).
	body := realPDF(t)
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q2/evidence.pdf": {
			Data:       body,
			UploadedAt: mustTime("2026-05-15T10:00:00Z"),
		},
		"manual/access_review_quarterly/2026-Q1/report.docx": {
			Data:       []byte("PK fake docx"),
			UploadedAt: mustTime("2026-02-15T10:00:00Z"),
		},
	})
	req := baseReq("2026-Q2", map[string]any{
		"prior_period_id": "2026-Q1",
		"period_start":    mustTime("2026-04-01T00:00:00Z"),
		"period_end":      mustTime("2026-06-30T23:59:59Z"),
	})
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	// Should be valid — prior period has only unsupported files so no fingerprint match.
	if !m.FileValid {
		t.Errorf("FileValid = false; want true (prior-period unsupported file skipped); failures = %v", m.ValidationFailures)
	}
	for _, f := range m.ValidationFailures {
		if strings.HasPrefix(f, "copy_paste_of_prior_period") {
			t.Errorf("unexpected copy_paste_of_prior_period failure: %s", f)
		}
	}
}

// checkPriorPeriod — prior folder Get error is silently skipped
func TestCollect_PriorPeriodGetErrorSkipped(t *testing.T) {
	// Prior period List succeeds (returns a PDF key), but Get for that key
	// fails. The check should silently skip that file and not flag copy-paste.
	body := realPDF(t)
	baseFiles := map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q2/evidence.pdf": {
			Data:       body,
			UploadedAt: mustTime("2026-05-15T10:00:00Z"),
		},
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       body,
			UploadedAt: mustTime("2026-02-15T10:00:00Z"),
		},
	}
	p := New(Options{
		Reader: &selectiveGetReader{
			files: baseFiles,
			failKeys: map[string]bool{
				"manual/access_review_quarterly/2026-Q1/evidence.pdf": true,
			},
		},
		Bucket: "acme-evidence",
		Prefix: "manual/",
		Scheme: "s3",
		Catalog: map[string]CatalogEntry{
			"access_review_quarterly": {EvidenceID: "access_review_quarterly", GracePeriod: 15 * 24 * time.Hour},
		},
	})
	req := baseReq("2026-Q2", map[string]any{
		"prior_period_id": "2026-Q1",
		"period_start":    mustTime("2026-04-01T00:00:00Z"),
		"period_end":      mustTime("2026-06-30T23:59:59Z"),
	})
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := unmarshalManifest(t, records)
	// With the prior Get failing, priorFiles ends up empty, so no copy-paste flag.
	for _, f := range m.ValidationFailures {
		if strings.HasPrefix(f, "copy_paste_of_prior_period") {
			t.Errorf("unexpected copy_paste failure when prior Get errored: %s", f)
		}
	}
}

// selectiveGetReader is an InMemoryReader that fails Get for specific keys.
type selectiveGetReader struct {
	files    map[string]InMemoryFile
	failKeys map[string]bool
}

func (r *selectiveGetReader) Get(_ context.Context, key string) ([]byte, time.Time, error) {
	if r.failKeys[key] {
		return nil, time.Time{}, errors.New("synthetic selective get error")
	}
	f, ok := r.files[key]
	if !ok {
		return nil, time.Time{}, ErrNotFound
	}
	return append([]byte(nil), f.Data...), f.UploadedAt, nil
}

func (r *selectiveGetReader) List(_ context.Context, prefix string) ([]FileInfo, error) {
	var items []FileInfo
	for key, f := range r.files {
		if strings.HasPrefix(key, prefix) {
			items = append(items, FileInfo{Key: key, UploadedAt: f.UploadedAt})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items, nil
}
