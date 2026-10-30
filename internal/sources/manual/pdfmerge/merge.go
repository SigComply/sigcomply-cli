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

// MaxObjects is the largest object number a PDF may use to be merged.
// pdfcpu sizes its renumbering table by the highest object number, so a
// 1 KB file that numbers one object 300,000,000 made a merge allocate
// about 9 GB. A 5,000-page scan uses some tens of thousands of objects.
const MaxObjects = 1_000_000

// newConfig returns pdfcpu's stateless configuration in relaxed
// validation mode. The default configuration reads (and on first use
// writes) a config.yml and user fonts under the user's config directory;
// a CLI merging evidence in CI has no use for either.
func newConfig() *model.Configuration {
	conf := model.NewStatelessConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	return conf
}

// guard runs f and turns a panic into an error. pdfcpu recovers only its
// own internal panics; anything else (an index out of range on a
// malformed file) would otherwise end the whole run.
func guard(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pdf parser failed: %v", r)
		}
	}()
	return f()
}

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
	conf := newConfig()
	conf.UserPW = ""
	var out bytes.Buffer
	if err := guard(func() error { return pdfapi.Decrypt(ctx, bytes.NewReader(pdf), &out, conf) }); err != nil {
		return pdf
	}
	return out.Bytes()
}

// checkPart reads and validates one input on its own and refuses one
// whose object numbers exceed MaxObjects, before the merge sizes any
// table by them.
func checkPart(ctx context.Context, pdf []byte) error {
	return guard(func() error {
		pctx, err := pdfapi.ReadAndValidate(ctx, bytes.NewReader(pdf), newConfig())
		if err != nil {
			return err
		}
		if size := pctx.Size; size != nil && *size > MaxObjects {
			return fmt.Errorf("uses object numbers up to %d; the limit is %d", *size, MaxObjects)
		}
		return nil
	})
}

// Merge takes one or more PDF byte slices and returns a single merged
// PDF. Order is preserved. A single-element input is returned as-is
// without invoking pdfcpu. Each input is first read and validated on
// its own (relaxed mode), so a bad input comes back as a PartError that
// names it; a panic inside pdfcpu comes back as an error, never as a
// crashed run. ctx bounds pdfcpu's work so a canceled run stops
// mid-document.
func Merge(ctx context.Context, pdfs [][]byte) ([]byte, error) {
	if len(pdfs) == 0 {
		return nil, fmt.Errorf("pdfmerge: no PDFs to merge")
	}
	if len(pdfs) == 1 {
		return pdfs[0], nil
	}

	rsc := make([]io.ReadSeeker, len(pdfs))
	for i, p := range pdfs {
		p = openable(ctx, p)
		if err := checkPart(ctx, p); err != nil {
			return nil, &PartError{Index: i, Err: err}
		}
		rsc[i] = bytes.NewReader(p)
	}

	var out bytes.Buffer
	if err := guard(func() error { return pdfapi.MergeRaw(ctx, rsc, &out, false, newConfig()) }); err != nil {
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
