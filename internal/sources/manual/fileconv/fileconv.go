// Package fileconv converts common image formats to PDF bytes. It is
// stdlib-plus-gofpdf only — no content understanding, no text extraction.
// The sole purpose is byte-level format translation so that customers can
// upload JPEG screenshots, PNG exports, or scanned TIFFs alongside PDFs
// without pre-converting them manually.
//
// Supported input formats: .pdf (pass-through), .jpg/.jpeg, .png, .gif
// (via gofpdf native), .tif/.tiff, .webp, .bmp (via x/image decode → PNG
// re-encode → gofpdf — gofpdf has no native TIFF/WebP/BMP support).
//
// Unsupported formats (e.g. .docx, .xlsx) are not converted; callers
// receive a typed UnsupportedTypeError with the full list of supported
// extensions so the message can be surfaced directly in CI logs.
package fileconv

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"path/filepath"
	"strings"

	"github.com/phpdave11/gofpdf"

	// Register TIFF, WebP and BMP decoders into image.Decode. gofpdf has
	// no native decoder for any of these, so they go through the x/image
	// decode → PNG re-encode path.
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

// supportedExts is the canonical set of extensions this package handles.
// Order is preserved for error messages; checked via the map below.
var supportedExts = []string{
	".pdf",
	".jpg", ".jpeg",
	".png",
	".gif",
	".tif", ".tiff",
	".webp",
	".bmp",
}

var supportedExtSet = func() map[string]bool {
	m := make(map[string]bool, len(supportedExts))
	for _, e := range supportedExts {
		m[e] = true
	}
	return m
}()

// SupportedExt reports whether ext (must be lowercase, leading dot) is
// a format this package can handle.
func SupportedExt(ext string) bool {
	return supportedExtSet[ext]
}

// IsPDF reports whether ext is ".pdf".
func IsPDF(ext string) bool { return ext == ".pdf" }

// SupportedExtsList returns the supported extensions joined with spaces
// for use in error messages.
func SupportedExtsList() string {
	return strings.Join(supportedExts, " ")
}

// UnsupportedTypeError is returned by ToPDF when the extension is not
// in the supported set. The message is human-readable and suitable for
// CI log output.
type UnsupportedTypeError struct {
	Filename string
	Ext      string
}

func (e *UnsupportedTypeError) Error() string {
	return fmt.Sprintf(
		"file %q has unsupported extension %q; supported formats: %s",
		e.Filename, e.Ext, SupportedExtsList(),
	)
}

// ToPDF converts data (a file named filename with the given lowercase ext)
// to PDF bytes. If the file is already a PDF, it is returned as-is with
// converted=false. Images are wrapped in a single A4 page with the image
// scaled to fit while preserving aspect ratio; converted=true.
//
// Returns UnsupportedTypeError for unrecognized extensions.
func ToPDF(filename, ext string, data []byte) (pdf []byte, converted bool, err error) {
	switch ext {
	case ".pdf":
		return data, false, nil
	case ".jpg", ".jpeg":
		out, e := imageToPDF(filename, "JPEG", data)
		return out, e == nil, e
	case ".png":
		out, e := imageToPDF(filename, "PNG", data)
		return out, e == nil, e
	case ".gif":
		out, e := imageToPDF(filename, "GIF", data)
		return out, e == nil, e
	case ".tif", ".tiff", ".webp", ".bmp":
		// gofpdf can't read these. Decode via x/image (registered above)
		// then re-encode as PNG, which gofpdf does support.
		pngData, e := reencodeAsPNG(data)
		if e != nil {
			return nil, false, fmt.Errorf("fileconv: decode %s: %w", filename, e)
		}
		out, e := imageToPDF(filename+".png", "PNG", pngData)
		return out, e == nil, e
	default:
		return nil, false, &UnsupportedTypeError{
			Filename: filepath.Base(filename),
			Ext:      ext,
		}
	}
}

// NormalizeExt returns the lowercase extension of a filename with the
// leading dot. Callers use this instead of filepath.Ext to avoid
// case-sensitivity inconsistencies on case-preserving filesystems.
func NormalizeExt(filename string) string {
	return strings.ToLower(filepath.Ext(filename))
}

// imageToPDF wraps imageData in a single A4-portrait page. The image is
// scaled to fill the page while preserving its aspect ratio (letterbox /
// pillarbox if the image proportions differ from A4).
func imageToPDF(name, imgType string, imageData []byte) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(false, 0)
	pdf.AddPage()

	opt := gofpdf.ImageOptions{ImageType: imgType, ReadDpi: true}
	info := pdf.RegisterImageOptionsReader(name, opt, bytes.NewReader(imageData))
	if err := pdf.Error(); err != nil {
		return nil, fmt.Errorf("fileconv: register image %s: %w", name, err)
	}

	pageW, pageH := pdf.GetPageSize()
	imgW := info.Width()  // natural width in mm (at image DPI)
	imgH := info.Height() // natural height in mm (at image DPI)

	// Scale to fit page, maintaining aspect ratio.
	scaleW := pageW / imgW
	scaleH := pageH / imgH
	scale := scaleW
	if scaleH < scaleW {
		scale = scaleH
	}
	drawW := imgW * scale
	drawH := imgH * scale

	// Center on page.
	x := (pageW - drawW) / 2
	y := (pageH - drawH) / 2

	pdf.ImageOptions(name, x, y, drawW, drawH, false, opt, 0, "")

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("fileconv: render PDF for %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// reencodeAsPNG decodes any format registered in the image package
// (including WebP and BMP registered by blank imports above) and
// re-encodes as PNG bytes suitable for gofpdf.
func reencodeAsPNG(data []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
