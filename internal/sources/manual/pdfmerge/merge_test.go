package pdfmerge_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/pdfmerge"
)

// realPDF creates a valid single-page PDF via fileconv (uses gofpdf
// internally). This is the only way to get a PDF that pdfcpu will
// accept without errors.
func realPDF(t *testing.T) []byte {
	t.Helper()
	return mustRealPDF(t)
}

func mustRealPDF(tb testing.TB) []byte {
	tb.Helper()
	pdf, _, err := fileconv.ToPDF("test.png", ".png", minimalPNG())
	if err != nil {
		tb.Fatalf("realPDF: fileconv: %v", err)
	}
	return pdf
}

func TestMerge_Single(t *testing.T) {
	data := realPDF(t)
	out, err := pdfmerge.Merge(context.Background(), [][]byte{data})
	if err != nil {
		t.Fatalf("Merge(single): %v", err)
	}
	// Single-PDF shortcut: bytes are identical.
	if !bytes.Equal(out, data) {
		t.Error("single-PDF merge returned different bytes")
	}
}

func TestMerge_Multiple(t *testing.T) {
	p1 := realPDF(t)
	p2 := realPDF(t)
	out, err := pdfmerge.Merge(context.Background(), [][]byte{p1, p2})
	if err != nil {
		t.Fatalf("Merge(two PDFs): %v", err)
	}
	if len(out) == 0 {
		t.Fatal("merged PDF is empty")
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Errorf("merged output is not a PDF; prefix: %q", out[:minInt(10, len(out))])
	}
	// Merged PDF is typically larger than either input.
	if len(out) <= len(p1)/2 {
		t.Errorf("merged PDF (%d bytes) suspiciously small vs input (%d bytes)", len(out), len(p1))
	}
}

func TestMerge_Empty(t *testing.T) {
	_, err := pdfmerge.Merge(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for empty slice; got nil")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// minimalPNG returns a 1×1 white PNG.
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

// encrypt protects pdf with the given passwords (AES-256).
func encrypt(t *testing.T, pdf []byte, userPW, ownerPW string) []byte {
	t.Helper()
	conf := model.NewAESConfiguration(userPW, ownerPW, 256)
	var out bytes.Buffer
	if err := pdfapi.Encrypt(context.Background(), bytes.NewReader(pdf), &out, conf); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return out.Bytes()
}

// A PDF with only an owner password opens in every viewer without a
// password (vendor SOC 2 reports and pentest reports often ship this way).
// It passes on its own, so it must also merge with other files.
func TestMerge_OwnerPasswordOnlyPDF(t *testing.T) {
	secured := encrypt(t, realPDF(t), "", "owner-secret")
	out, err := pdfmerge.Merge(context.Background(), [][]byte{realPDF(t), secured})
	if err != nil {
		t.Fatalf("Merge(plain, owner-password-only): %v", err)
	}
	if n, err := pdfapi.PageCount(context.Background(), bytes.NewReader(out), model.NewDefaultConfiguration()); err != nil || n != 2 {
		t.Errorf("merged page count = %d (%v); want 2", n, err)
	}
}

// A PDF that needs a password to open cannot be merged: that stays a
// merge failure.
func TestMerge_UserPasswordPDFStillFails(t *testing.T) {
	locked := encrypt(t, realPDF(t), "user-secret", "owner-secret")
	if _, err := pdfmerge.Merge(context.Background(), [][]byte{realPDF(t), locked}); err == nil {
		t.Fatal("Merge = nil error; want a failure for a PDF that needs a password to open")
	}
}

// A failed merge names which input could not be read, so the caller can
// name the file instead of "merge source 1".
func TestMerge_FailureNamesThePart(t *testing.T) {
	good := realPDF(t)
	_, err := pdfmerge.Merge(context.Background(), [][]byte{good, []byte("%PDF-1.4 garbage"), good})
	var pe *pdfmerge.PartError
	if !errors.As(err, &pe) {
		t.Fatalf("want a *PartError; got %v", err)
	}
	if pe.Index != 1 {
		t.Errorf("PartError.Index = %d; want 1", pe.Index)
	}
}
