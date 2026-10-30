package fileconv_test

import (
	"bytes"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
)

// fuzzExts are the image extensions FuzzToPDF picks from; the PDF
// pass-through is excluded because it does not parse anything.
var fuzzExts = []string{extJPG, extPNG, extGIF, extTIF, extWebP, extBMP}

// FuzzToPDF feeds arbitrary bytes to every image converter. Uploaded
// evidence is untrusted input: ToPDF must return an error for bytes it
// cannot convert, never panic, and anything it does return must be a PDF.
// Run in CI by the fuzz job; crashers live in testdata/fuzz/FuzzToPDF.
func FuzzToPDF(f *testing.F) {
	img := image.NewGray(image.Rect(0, 0, 3, 2))
	encoders := []func(*bytes.Buffer) error{
		func(b *bytes.Buffer) error { return jpeg.Encode(b, img, nil) },
		func(b *bytes.Buffer) error { return png.Encode(b, img) },
		func(b *bytes.Buffer) error { return gif.Encode(b, img, nil) },
		func(b *bytes.Buffer) error { return tiff.Encode(b, img, nil) },
		nil, // no WebP encoder: seeded with the header below
		func(b *bytes.Buffer) error { return bmp.Encode(b, img) },
	}
	for i, enc := range encoders {
		if enc == nil {
			continue
		}
		var b bytes.Buffer
		if err := enc(&b); err != nil {
			f.Fatalf("seed %s: %v", fuzzExts[i], err)
		}
		f.Add(uint8(i), b.Bytes()) //nolint:gosec // i < len(fuzzExts)
	}
	f.Add(uint8(1), pngWithIDAT(100, 100, []byte{0, 1, 2, 3}))
	f.Add(uint8(4), webpVP8XHeader(3, 2))
	f.Add(uint8(3), tiffHeader(3, 2))
	f.Add(uint8(5), bmpHeader(3, 2))
	f.Add(uint8(0), jpegHeader(3, 2))
	f.Add(uint8(2), gifHeader(3, 2))

	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		ext := fuzzExts[int(which)%len(fuzzExts)]
		out, converted, err := fileconv.ToPDF("fuzz"+ext, ext, data)
		if err != nil {
			if converted || out != nil {
				t.Fatalf("ToPDF(%s) returned output with error %v", ext, err)
			}
			return
		}
		if !converted || !bytes.HasPrefix(out, []byte("%PDF-")) {
			t.Fatalf("ToPDF(%s) succeeded without a PDF (converted=%v)", ext, converted)
		}
	})
}
