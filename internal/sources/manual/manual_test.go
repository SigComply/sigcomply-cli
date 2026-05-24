package manual

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

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
			Data:       []byte("fake pdf bytes"),
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
			Data:       []byte("fake"),
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
