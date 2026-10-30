// Package fileconv converts common image formats to PDF bytes. It is
// stdlib-plus-gofpdf only — no content understanding, no text extraction.
// The sole purpose is byte-level format translation so that customers can
// upload JPEG screenshots, PNG exports, or scanned TIFFs alongside PDFs
// without pre-converting them manually.
//
// Supported input formats: .pdf (pass-through), .jpg/.jpeg, .gif (via
// gofpdf native), .png, .tif/.tiff, .webp, .bmp (via image/png or x/image
// decode → PNG re-encode → gofpdf: gofpdf has no native TIFF/WebP/BMP
// support, and its own PNG reader inflates without a limit).
//
// Unsupported formats (e.g. .docx, .xlsx) are not converted; callers
// receive a typed UnsupportedTypeError with the full list of supported
// extensions so the message can be surfaced directly in CI logs.
package fileconv

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif"  // registers GIF for image.DecodeConfig
	_ "image/jpeg" // registers JPEG for image.DecodeConfig
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

// extPDF is the one extension that is passed through unconverted.
const extPDF = ".pdf"

// supportedExts is the canonical set of extensions this package handles.
// Order is preserved for error messages; checked via the map below.
var supportedExts = []string{
	extPDF,
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
func IsPDF(ext string) bool { return ext == extPDF }

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

// Retryable implements sources.RetryableError: an extension this
// package cannot convert will not become convertible on a second
// attempt, so the collector must not spend its retry budget on it.
// Declared as a method rather than taught to the classifier so the
// knowledge stays next to the error (and so fileconv keeps its
// stdlib-plus-gofpdf dependency set).
func (e *UnsupportedTypeError) Retryable() bool { return false }

// MaxImagePixels is the largest image, in pixels (width × height), that
// ToPDF converts. Decoders allocate about four bytes per pixel before
// reading any pixel data, so a header of a few dozen bytes can otherwise
// ask for gigabytes. 50 megapixels covers a phone photo at its default
// resolution and a 600 dpi A4 scan (about 35 megapixels); a phone's
// high-resolution mode (108 or 200 megapixels) is over the limit and must
// be downscaled before upload.
const MaxImagePixels = 50_000_000

// ImageTooLargeError is returned by ToPDF when an image header declares
// more than MaxImagePixels pixels (or a zero or negative dimension).
type ImageTooLargeError struct {
	Filename      string
	Width, Height int
}

func (e *ImageTooLargeError) Error() string {
	return fmt.Sprintf(
		"image %q is %d×%d pixels; the limit is %d megapixels, so downscale it or save it as a PDF",
		e.Filename, e.Width, e.Height, MaxImagePixels/1_000_000,
	)
}

// Retryable implements sources.RetryableError: the file will be just as
// large on a second attempt.
func (e *ImageTooLargeError) Retryable() bool { return false }

// ToPDF converts data (a file named filename with the given lowercase ext)
// to PDF bytes. If the file is already a PDF, it is returned as-is with
// converted=false. Images are wrapped in a single A4 page with the image
// scaled to fit while preserving aspect ratio; converted=true.
//
// Every image's header is read first and an image larger than
// MaxImagePixels is refused with ImageTooLargeError. A panic inside an
// image decoder (gofpdf indexes past short pixel data) is returned as an
// error, so one bad upload fails its own policy instead of the run.
//
// Returns UnsupportedTypeError for unrecognized extensions.
func ToPDF(filename, ext string, data []byte) (pdf []byte, converted bool, err error) {
	if ext == extPDF {
		return data, false, nil
	}
	if !SupportedExt(ext) {
		return nil, false, &UnsupportedTypeError{
			Filename: filepath.Base(filename),
			Ext:      ext,
		}
	}
	defer func() {
		if r := recover(); r != nil {
			pdf, converted = nil, false
			err = fmt.Errorf("fileconv: %s is not a readable image (decoder failed: %v)", filename, r)
		}
	}()
	if err := checkDimensions(filename, data); err != nil {
		return nil, false, err
	}
	var out []byte
	switch ext {
	case ".jpg", ".jpeg":
		out, err = imageToPDF(filename, "JPEG", data)
	case ".gif":
		out, err = imageToPDF(filename, "GIF", data)
	default: // ".png", ".tif", ".tiff", ".webp", ".bmp"
		// gofpdf can't read TIFF, WebP or BMP: decode via x/image
		// (registered above), then re-encode as PNG. An uploaded PNG
		// takes the same path: gofpdf inflates a PNG's whole IDAT
		// stream with no limit, so a small file with a valid header
		// could decompress to gigabytes. image/png reads no more pixel
		// data than the header declares, and the re-encoded PNG is
		// bounded by MaxImagePixels.
		pngData, e := reencodeAsPNG(data)
		if e != nil {
			return nil, false, fmt.Errorf("fileconv: decode %s: %w", filename, e)
		}
		out, err = imageToPDF(filename+".png", "PNG", pngData)
	}
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// checkDimensions reads only the image header and refuses images over
// MaxImagePixels, before any decoder allocates the pixel buffer.
func checkDimensions(filename string, data []byte) error {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("fileconv: read image header of %s: %w", filename, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > MaxImagePixels {
		return &ImageTooLargeError{Filename: filepath.Base(filename), Width: cfg.Width, Height: cfg.Height}
	}
	return nil
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
