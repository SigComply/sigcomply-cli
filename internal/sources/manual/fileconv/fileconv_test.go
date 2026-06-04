package fileconv_test

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"strings"
	"testing"

	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
)

// tinyImage is a 2×2 image used to encode real bytes for each format.
func tinyImage() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	for y := 0; y < 2; y++ {
		for x := 0; x < 2; x++ {
			img.Set(x, y, color.White)
		}
	}
	return img
}

// TestToPDF_ImageFormats encodes a real image for each advertised image
// format and asserts it actually converts to a PDF. Before this test the
// TIFF path was broken (gofpdf has no TIFF decoder) yet build/test/lint
// were green because nothing pushed real TIFF bytes through ToPDF.
func TestToPDF_ImageFormats(t *testing.T) {
	img := tinyImage()
	gifBuf := &bytes.Buffer{}
	if err := gif.Encode(gifBuf, img, nil); err != nil {
		t.Fatalf("encode gif: %v", err)
	}
	tiffBuf := &bytes.Buffer{}
	if err := tiff.Encode(tiffBuf, img, nil); err != nil {
		t.Fatalf("encode tiff: %v", err)
	}
	bmpBuf := &bytes.Buffer{}
	if err := bmp.Encode(bmpBuf, img); err != nil {
		t.Fatalf("encode bmp: %v", err)
	}
	cases := []struct {
		name string
		ext  string
		data []byte
	}{
		{"gif.gif", ".gif", gifBuf.Bytes()},
		{"scan.tif", ".tif", tiffBuf.Bytes()},
		{"scan.tiff", ".tiff", tiffBuf.Bytes()},
		{"image.bmp", ".bmp", bmpBuf.Bytes()},
	}
	for _, c := range cases {
		out, converted, err := fileconv.ToPDF(c.name, c.ext, c.data)
		if err != nil {
			t.Errorf("ToPDF(%s): unexpected error: %v", c.ext, err)
			continue
		}
		if !converted {
			t.Errorf("ToPDF(%s): converted=false; want true", c.ext)
		}
		if !isPDFBytes(out) {
			t.Errorf("ToPDF(%s): output is not a PDF (no %%PDF- prefix)", c.ext)
		}
	}
}

func TestSupportedExt(t *testing.T) {
	supported := []string{".pdf", ".jpg", ".jpeg", ".png", ".gif", ".tif", ".tiff", ".webp", ".bmp"}
	for _, ext := range supported {
		if !fileconv.SupportedExt(ext) {
			t.Errorf("SupportedExt(%q) = false; want true", ext)
		}
	}
	unsupported := []string{".docx", ".xlsx", ".pptx", ".txt", ".csv", ".html", ".odt", ""}
	for _, ext := range unsupported {
		if fileconv.SupportedExt(ext) {
			t.Errorf("SupportedExt(%q) = true; want false", ext)
		}
	}
}

func TestIsPDF(t *testing.T) {
	if !fileconv.IsPDF(".pdf") {
		t.Error("IsPDF(.pdf) = false")
	}
	if fileconv.IsPDF(".png") {
		t.Error("IsPDF(.png) = true")
	}
}

func TestNormalizeExt(t *testing.T) {
	cases := []struct{ in, want string }{
		{"evidence.PDF", ".pdf"},
		{"scan.JPEG", ".jpeg"},
		{"image.PNG", ".png"},
		{"noext", ""},
	}
	for _, tc := range cases {
		got := fileconv.NormalizeExt(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeExt(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestToPDF_PassThrough(t *testing.T) {
	data := minimalPDF()
	out, converted, err := fileconv.ToPDF("evidence.pdf", ".pdf", data)
	if err != nil {
		t.Fatalf("ToPDF PDF pass-through: %v", err)
	}
	if converted {
		t.Error("converted = true for PDF pass-through; want false")
	}
	if !bytes.Equal(out, data) {
		t.Error("pass-through PDF bytes changed")
	}
}

func TestToPDF_JPEG(t *testing.T) {
	out, converted, err := fileconv.ToPDF("screenshot.jpg", ".jpg", minimalJPEG())
	if err != nil {
		t.Fatalf("ToPDF JPEG: %v", err)
	}
	if !converted {
		t.Error("converted = false for JPEG; want true")
	}
	if len(out) == 0 {
		t.Error("output PDF is empty")
	}
	// Output must be a PDF.
	if !isPDFBytes(out) {
		t.Errorf("output does not start with %%PDF-; got %q", out[:minInt(len(out), 10)])
	}
}

func TestToPDF_PNG(t *testing.T) {
	out, converted, err := fileconv.ToPDF("image.png", ".png", minimalPNG())
	if err != nil {
		t.Fatalf("ToPDF PNG: %v", err)
	}
	if !converted {
		t.Error("converted = false for PNG; want true")
	}
	if !isPDFBytes(out) {
		t.Error("PNG → PDF: output not a PDF")
	}
}

func TestToPDF_UnsupportedType(t *testing.T) {
	_, _, err := fileconv.ToPDF("report.docx", ".docx", []byte("PK...fake docx..."))
	if err == nil {
		t.Fatal("expected error for .docx; got nil")
	}
	var ute *fileconv.UnsupportedTypeError
	if !isUnsupportedTypeError(err, &ute) {
		t.Fatalf("expected UnsupportedTypeError, got %T: %v", err, err)
	}
	if ute.Ext != ".docx" {
		t.Errorf("UnsupportedTypeError.Ext = %q; want .docx", ute.Ext)
	}
	if !strings.Contains(err.Error(), ".pdf") {
		t.Errorf("error message should list supported exts; got %q", err.Error())
	}
}

func TestSupportedExtsList(t *testing.T) {
	list := fileconv.SupportedExtsList()
	for _, ext := range []string{".pdf", ".jpg", ".png", ".gif", ".tiff", ".webp", ".bmp"} {
		if !strings.Contains(list, ext) {
			t.Errorf("SupportedExtsList() missing %q; got %q", ext, list)
		}
	}
}

// --- helpers ---

func isPDFBytes(b []byte) bool {
	return len(b) > 5 && string(b[:5]) == "%PDF-"
}

func isUnsupportedTypeError(err error, target **fileconv.UnsupportedTypeError) bool {
	if ute, ok := err.(*fileconv.UnsupportedTypeError); ok {
		*target = ute
		return true
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// minimalPDF returns the smallest byte sequence that passes validatePDF.
// It is NOT a real renderable PDF — only used for pass-through tests.
func minimalPDF() []byte {
	// Must start with %PDF-, contain /Page, and be >= 100 bytes.
	base := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Page >>\nendobj\n")
	for len(base) < 110 {
		base = append(base, 'x')
	}
	return base
}

// minimalJPEG returns a 1×1 white JPEG.
func minimalJPEG() []byte {
	// Smallest valid JFIF JPEG for a 1x1 white pixel.
	return []byte{
		0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
		0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
		0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
		0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
		0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
		0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
		0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
		0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
		0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
		0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
		0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
		0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
		0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
		0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
		0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
		0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
		0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
		0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
		0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
		0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
		0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
		0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
		0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
		0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01,
		0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD2, 0x8A, 0x28, 0x03, 0xFF, 0xD9,
	}
}

// minimalPNG returns a 1×1 white PNG.
func minimalPNG() []byte {
	return []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, // IHDR length
		0x49, 0x48, 0x44, 0x52, // IHDR
		0x00, 0x00, 0x00, 0x01, // width=1
		0x00, 0x00, 0x00, 0x01, // height=1
		0x08, 0x02, // bit depth=8, color type=2 (RGB)
		0x00, 0x00, 0x00, // compression, filter, interlace
		0x90, 0x77, 0x53, 0xDE, // CRC
		0x00, 0x00, 0x00, 0x0C, // IDAT length
		0x49, 0x44, 0x41, 0x54, // IDAT
		0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, // zlib data
		0xE2, 0x21, 0xBC, 0x33, // CRC
		0x00, 0x00, 0x00, 0x00, // IEND length
		0x49, 0x45, 0x4E, 0x44, // IEND
		0xAE, 0x42, 0x60, 0x82, // CRC
	}
}
