// Package pdfmerge merges one or more in-memory PDFs into a single PDF
// using pdfcpu. The single-PDF case is a no-op pass-through so callers
// don't need to branch on count.
package pdfmerge

import (
	"bytes"
	"fmt"
	"io"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// Merge takes one or more PDF byte slices and returns a single merged
// PDF. Order is preserved. A single-element input is returned as-is
// without invoking pdfcpu. Returns an error if any input cannot be
// parsed as a valid PDF by pdfcpu (relaxed validation mode).
func Merge(pdfs [][]byte) ([]byte, error) {
	if len(pdfs) == 0 {
		return nil, fmt.Errorf("pdfmerge: no PDFs to merge")
	}
	if len(pdfs) == 1 {
		return pdfs[0], nil
	}

	rsc := make([]io.ReadSeeker, len(pdfs))
	for i, p := range pdfs {
		rsc[i] = bytes.NewReader(p)
	}

	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed

	var out bytes.Buffer
	if err := pdfapi.MergeRaw(rsc, &out, false, conf); err != nil {
		return nil, fmt.Errorf("pdfmerge: merge failed: %w", err)
	}
	return out.Bytes(), nil
}
