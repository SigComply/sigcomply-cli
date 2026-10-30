package pdfmerge_test

import (
	"context"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/pdfmerge"
)

// FuzzMerge merges a known-good PDF with arbitrary bytes. Uploaded PDFs
// are untrusted input and pdfcpu is a large parser: Merge must return an
// error for bytes it cannot merge, never panic. Run in CI by the fuzz
// job; crashers live in testdata/fuzz/FuzzMerge and run under go test.
func FuzzMerge(f *testing.F) {
	good := mustRealPDF(f)
	f.Add(good)
	f.Add([]byte("%PDF-1.4 garbage"))
	f.Add([]byte("%PDF-1.7\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\ntrailer<</Root 1 0 R/Encrypt 3 0 R>>\n%%EOF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		out, err := pdfmerge.Merge(context.Background(), [][]byte{good, data})
		if err == nil && len(out) == 0 {
			t.Fatal("Merge returned no bytes and no error")
		}
	})
}
