// Package pdfmerge merges one or more in-memory PDFs into a single PDF
// using pdfcpu. The single-PDF case is a no-op pass-through so callers
// don't need to branch on count.
package pdfmerge

import (
	"bytes"
	"context"
	"fmt"
	"io"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// openable returns the PDF decrypted when it is encrypted with an owner
// password only, which every viewer opens without asking for a password
// (vendor SOC 2 and penetration-test reports often ship this way).
// pdfcpu refuses to merge an encrypted file, so the merged copy carries
// the decrypted content; the original bytes are what the record hashes.
// Anything else (not encrypted, or needing a user password) is returned
// unchanged, and a PDF that needs a password still fails the merge.
func openable(ctx context.Context, pdf []byte) []byte {
	if !bytes.Contains(pdf, []byte("/Encrypt")) {
		return pdf
	}
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	conf.UserPW = ""
	var out bytes.Buffer
	if err := pdfapi.Decrypt(ctx, bytes.NewReader(pdf), &out, conf); err != nil {
		return pdf
	}
	return out.Bytes()
}

// Merge takes one or more PDF byte slices and returns a single merged
// PDF. Order is preserved. A single-element input is returned as-is
// without invoking pdfcpu. Returns an error if any input cannot be
// parsed as a valid PDF by pdfcpu (relaxed validation mode).
// ctx bounds pdfcpu's merge so a canceled run stops mid-document.
func Merge(ctx context.Context, pdfs [][]byte) ([]byte, error) {
	if len(pdfs) == 0 {
		return nil, fmt.Errorf("pdfmerge: no PDFs to merge")
	}
	if len(pdfs) == 1 {
		return pdfs[0], nil
	}

	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed

	rsc := make([]io.ReadSeeker, len(pdfs))
	for i, p := range pdfs {
		rsc[i] = bytes.NewReader(openable(ctx, p))
	}

	var out bytes.Buffer
	if err := pdfapi.MergeRaw(ctx, rsc, &out, false, conf); err != nil {
		// pdfcpu's error does not say which input broke the merge, and
		// the user needs a file name to act on. Re-read each input on
		// its own to find the first one pdfcpu cannot read.
		for i, p := range pdfs {
			if _, readErr := pdfapi.ReadAndValidate(ctx, bytes.NewReader(p), conf); readErr != nil {
				return nil, &PartError{Index: i, Err: readErr}
			}
		}
		return nil, fmt.Errorf("pdfmerge: merge failed: %w", err)
	}
	return out.Bytes(), nil
}

// PartError reports the input, by its position in the slice given to
// Merge, that pdfcpu could not read.
type PartError struct {
	Index int
	Err   error
}

func (e *PartError) Error() string {
	return fmt.Sprintf("pdfmerge: input %d is not a readable PDF: %v", e.Index, e.Err)
}

func (e *PartError) Unwrap() error { return e.Err }
