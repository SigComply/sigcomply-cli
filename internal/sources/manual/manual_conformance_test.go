package manual

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// manual_conformance_test.go is the manual.pdf plugin's L1+L2 contract test
// (WU-2.9). Unlike the API plugins this reads committed local files (no network,
// no cassette) through the real `local` backend at testdata/store/manual/.
//
// The merged-PDF file_hash is deterministic only for a single source file:
// pdfcpu's merge (pdfmerge.Merge) embeds a fresh document ID, so a multi-file
// merge is NOT byte-stable. So the full sourcetest.RunConformance harness (which
// asserts determinism) runs on a single-PDF folder; the multi-format image→PDF
// merge is covered by TestManualMultiFormatMerge below, which schema-validates
// the record without the determinism gate.

func manualPlugin(t *testing.T, catalogID string) core.SourcePlugin {
	t.Helper()
	reader, scheme, bucket, prefix, err := buildLocalReader(map[string]any{
		"path": "testdata/store", "prefix": "manual/",
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{
		Reader: reader, Scheme: scheme, Bucket: bucket, Prefix: prefix,
		Catalog: map[string]CatalogEntry{catalogID: {EvidenceID: catalogID}},
	})
}

func manualParams(catalogID string) map[string]any {
	return map[string]any{
		"catalog_id":   catalogID,
		"period_id":    "2026-Q1",
		"period_start": time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		"period_end":   time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		"now":          time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
	}
}

func TestManualConformance(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: manualPlugin(t, "e2e_doc_single"),
		Request: core.SlotRequest{
			AcceptedTypes: []string{EvidenceTypeID},
			Params:        manualParams("e2e_doc_single"),
		},
		EvidenceTypes:  sourcetest.BuiltinEvidenceTypes(t),
		OptionalFields: []string{"signed_document.validation_failures"},
	})
	if len(recs) != 1 {
		t.Fatalf("signed_document records = %d, want 1", len(recs))
	}
	var m manualManifest
	if err := json.Unmarshal(recs[0].Payload, &m); err != nil {
		t.Fatal(err)
	}
	if !m.FilePresent || !m.FileValid || !m.InTemporalWindow || len(m.SourceFiles) != 1 {
		t.Errorf("manifest = %+v; want present, valid, in-window, 1 source file", m)
	}
}

// TestManualMultiFormatMerge exercises image→PDF conversion for every supported
// format plus the multi-file merge. The record is schema-validated, but the
// determinism harness is skipped (pdfcpu merge is not byte-stable).
func TestManualMultiFormatMerge(t *testing.T) {
	p := manualPlugin(t, "e2e_doc_multi")
	recs, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypeID},
		Params:        manualParams("e2e_doc_multi"),
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}

	// Schema-conformant against signed_document.v1.
	et, ok := sourcetest.BuiltinEvidenceTypes(t).Lookup(EvidenceTypeID)
	if !ok {
		t.Fatal("signed_document type not registered")
	}
	if err := evidencetypes.Validate(et.Schema, recs[0].Payload); err != nil {
		t.Errorf("schema validation: %v", err)
	}

	var m manualManifest
	if err := json.Unmarshal(recs[0].Payload, &m); err != nil {
		t.Fatal(err)
	}
	if !m.FilePresent || !m.FileValid || len(m.ValidationFailures) != 0 {
		t.Errorf("manifest = %+v; want present, valid, no failures", m)
	}
	// One source_file per fixture: policy.pdf + png/jpg/gif/tif/bmp/webp = 7.
	if len(m.SourceFiles) != 7 {
		t.Fatalf("source_files = %d, want 7 (pdf + 6 image formats)", len(m.SourceFiles))
	}
	var converted int
	for _, sf := range m.SourceFiles {
		if sf.Converted {
			converted++ // images are converted to PDF; the .pdf is not
		}
	}
	if converted != 6 {
		t.Errorf("converted source files = %d, want 6 (every image format)", converted)
	}
}
