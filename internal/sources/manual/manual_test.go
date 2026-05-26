package manual

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakePDF returns a payload that passes validatePDF: starts with the
// PDF magic bytes, is padded past minPDFBytes, and contains the /Page
// marker. Real PDFs are always much larger; this is the minimum a
// unit test needs to look "valid enough" to the sanity checks.
func fakePDF() []byte {
	parts := [][]byte{
		[]byte("%PDF-1.4\n"),
		[]byte("1 0 obj\n<< /Type /Page >>\nendobj\n"),
		bytes.Repeat([]byte("x"), minPDFBytes),
	}
	return bytes.Join(parts, nil)
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
				Filename:     "evidence.pdf",
				Cadence:      "quarterly",
				TemporalRule: "retrospective",
				GracePeriod:  15 * 24 * time.Hour,
			},
		},
	})
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

func TestCollect_PresentInWindow(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	periodStart := mustTime("2026-01-01T00:00:00Z")
	periodEnd := mustTime("2026-03-31T23:59:59Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       fakePDF(),
			UploadedAt: uploadedAt,
		},
	})
	req := core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params: map[string]any{
			"catalog_id":   "access_review_quarterly",
			"period_id":    "2026-Q1",
			"period_start": periodStart,
			"period_end":   periodEnd,
			"now":          mustTime("2026-04-01T00:00:00Z"),
		},
	}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1", len(records))
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
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
	if m.ExpectedURI != "s3://acme-evidence/manual/access_review_quarterly/2026-Q1/evidence.pdf" {
		t.Errorf("ExpectedURI = %q", m.ExpectedURI)
	}
}

func TestCollect_Missing(t *testing.T) {
	p := newTestPlugin(map[string]InMemoryFile{})
	req := core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params: map[string]any{
			"catalog_id":   "access_review_quarterly",
			"period_id":    "2026-Q1",
			"period_start": mustTime("2026-01-01T00:00:00Z"),
			"period_end":   mustTime("2026-03-31T23:59:59Z"),
		},
	}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1", len(records))
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	if m.FilePresent {
		t.Errorf("FilePresent = true; want false (missing)")
	}
	if m.InTemporalWindow {
		t.Errorf("InTemporalWindow = true; want false (missing)")
	}
}

func TestCollect_PresentOutsideWindow(t *testing.T) {
	uploadedAt := mustTime("2025-11-15T10:00:00Z") // before period start
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       fakePDF(),
			UploadedAt: uploadedAt,
		},
	})
	req := core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params: map[string]any{
			"catalog_id":   "access_review_quarterly",
			"period_id":    "2026-Q1",
			"period_start": mustTime("2026-01-01T00:00:00Z"),
			"period_end":   mustTime("2026-03-31T23:59:59Z"),
		},
	}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !m.FilePresent {
		t.Errorf("FilePresent should be true (we did upload one)")
	}
	if m.InTemporalWindow {
		t.Errorf("InTemporalWindow should be false (uploaded before period)")
	}
}

func TestCollect_PresentButEmpty(t *testing.T) {
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       []byte{},
			UploadedAt: uploadedAt,
		},
	})
	req := core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params: map[string]any{
			"catalog_id":   "access_review_quarterly",
			"period_id":    "2026-Q1",
			"period_start": mustTime("2026-01-01T00:00:00Z"),
			"period_end":   mustTime("2026-03-31T23:59:59Z"),
		},
	}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !m.FilePresent {
		t.Errorf("FilePresent = false; want true (0-byte file is still 'present at path')")
	}
	if m.FileValid {
		t.Errorf("FileValid = true; want false (0-byte file fails size check)")
	}
	if len(m.ValidationFailures) == 0 {
		t.Errorf("ValidationFailures empty; want size-check failure")
	}
}

func TestCollect_PresentButNotPDF(t *testing.T) {
	// Customer uploaded a .txt or .docx where evidence.pdf is expected.
	// Pad to >= minPDFBytes so only the magic-bytes check trips.
	nonPDF := append([]byte("This is not a PDF, just plain text. "), bytes.Repeat([]byte("x"), minPDFBytes)...)
	uploadedAt := mustTime("2026-02-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       nonPDF,
			UploadedAt: uploadedAt,
		},
	})
	req := core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params: map[string]any{
			"catalog_id":   "access_review_quarterly",
			"period_id":    "2026-Q1",
			"period_start": mustTime("2026-01-01T00:00:00Z"),
			"period_end":   mustTime("2026-03-31T23:59:59Z"),
		},
	}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
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

func TestCollect_DetectsCopyPasteOfPriorPeriod(t *testing.T) {
	// Same bytes uploaded under both Q1 and Q2 paths. The Q2 collection
	// should mark validation as failed for copy_paste_of_prior_period.
	body := fakePDF()
	uploadedAt := mustTime("2026-05-15T10:00:00Z")
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       body,
			UploadedAt: mustTime("2026-02-15T10:00:00Z"),
		},
		"manual/access_review_quarterly/2026-Q2/evidence.pdf": {
			Data:       body,
			UploadedAt: uploadedAt,
		},
	})
	req := core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params: map[string]any{
			"catalog_id":      "access_review_quarterly",
			"period_id":       "2026-Q2",
			"prior_period_id": "2026-Q1",
			"period_start":    mustTime("2026-04-01T00:00:00Z"),
			"period_end":      mustTime("2026-06-30T23:59:59Z"),
		},
	}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
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

func TestCollect_PriorPeriodMissingIsNotAFailure(t *testing.T) {
	// First-ever run: no prior period file exists. The check must
	// silently skip — honest customers running their first quarter
	// should not fail validation because there's nothing to compare.
	p := newTestPlugin(map[string]InMemoryFile{
		"manual/access_review_quarterly/2026-Q1/evidence.pdf": {
			Data:       fakePDF(),
			UploadedAt: mustTime("2026-02-15T10:00:00Z"),
		},
	})
	req := core.SlotRequest{
		PolicyID:      "soc2.cc6.3.access_review",
		AcceptedTypes: []string{EvidenceTypeID},
		SlotName:      "review_document",
		Params: map[string]any{
			"catalog_id":      "access_review_quarterly",
			"period_id":       "2026-Q1",
			"prior_period_id": "2025-Q4",
			"period_start":    mustTime("2026-01-01T00:00:00Z"),
			"period_end":      mustTime("2026-03-31T23:59:59Z"),
		},
	}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m manualManifest
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !m.FileValid {
		t.Errorf("FileValid = false; want true (prior period missing is fine); failures = %v", m.ValidationFailures)
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
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"user_record"}})
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
		got := p.buildURI("manual/x/y/z.pdf")
		if got == "" {
			t.Errorf("scheme %q produced empty URI", sc)
		}
	}
	pNoBucket := New(Options{Scheme: "file"})
	if got := pNoBucket.buildURI("manual/x"); got != "manual/x" {
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

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
