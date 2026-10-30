package fileconv_test

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"runtime"
	"testing"

	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
)

// pngChunk frames one PNG chunk with its CRC.
func pngChunk(typ string, data []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(data))) //nolint:gosec // test fixture, small
	out = append(out, typ...)
	out = append(out, data...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(append([]byte(typ), data...)))
}

// pngWithIDAT builds a PNG whose IHDR declares w×h RGBA pixels and whose
// IDAT holds idat (compressed). The pixel data need not match the header.
func pngWithIDAT(w, h uint32, idat []byte) []byte {
	ihdr := binary.BigEndian.AppendUint32(nil, w)
	ihdr = binary.BigEndian.AppendUint32(ihdr, h)
	ihdr = append(ihdr, 8, 6, 0, 0, 0) // 8-bit RGBA
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(idat); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, pngChunk("IHDR", ihdr)...)
	out = append(out, pngChunk("IDAT", z.Bytes())...)
	return append(out, pngChunk("IEND", nil)...)
}

// TestToPDF_TruncatedPNGDoesNotPanic is the 74-byte PNG from the AppSec
// review: its IHDR declares 100×100 RGBA but the IDAT holds 4 bytes.
// gofpdf indexes past the end of the inflated data and panics, which
// crashed the whole `check` run. It must come back as an error.
func TestToPDF_TruncatedPNGDoesNotPanic(t *testing.T) {
	data := pngWithIDAT(100, 100, []byte{0, 1, 2, 3})
	out, converted, err := fileconv.ToPDF("short.png", extPNG, data)
	if err == nil {
		t.Fatalf("ToPDF(truncated PNG) = %d bytes, nil error; want an error", len(out))
	}
	if converted {
		t.Error("converted = true on error")
	}
}

// bmpHeader is a header-only 24-bit BMP declaring w×h pixels.
func bmpHeader(w, h uint32) []byte {
	le := binary.LittleEndian
	b := []byte("BM")
	b = le.AppendUint32(b, 54)
	b = le.AppendUint32(b, 0)
	b = le.AppendUint32(b, 54) // pixel offset
	b = le.AppendUint32(b, 40) // DIB header size
	b = le.AppendUint32(b, w)
	b = le.AppendUint32(b, h)
	b = le.AppendUint16(b, 1)
	b = le.AppendUint16(b, 24) // bits per pixel
	b = le.AppendUint32(b, 0)
	return append(b, make([]byte, 20)...)
}

func gifHeader(w, h uint16) []byte {
	b := []byte("GIF89a")
	b = binary.LittleEndian.AppendUint16(b, w)
	b = binary.LittleEndian.AppendUint16(b, h)
	return append(b, 0, 0, 0)
}

func jpegHeader(w, h uint16) []byte {
	b := []byte{0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 8} // SOI, SOF0 (length 17), precision
	b = binary.BigEndian.AppendUint16(b, h)
	b = binary.BigEndian.AppendUint16(b, w)
	b = append(b, 3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0)
	return append(b, 0xFF, 0xDA, 0x00, 0x02) // SOS: the header ends here
}

// tiffHeader is a little-endian grayscale TIFF whose single IFD declares
// w×h pixels and no real strip data.
func tiffHeader(w, h uint32) []byte {
	type entry struct {
		tag, typ uint16
		val      uint32
	}
	const short, long = 3, 4
	entries := []entry{
		{256, long, w},
		{257, long, h},
		{258, short, 8},
		{259, short, 1},
		{262, short, 1},
		{273, long, 8},
		{277, short, 1},
		{278, long, h},
		{279, long, 1},
	}
	le := binary.LittleEndian
	b := []byte("II")
	b = le.AppendUint16(b, 42)
	b = le.AppendUint32(b, 8)
	b = le.AppendUint16(b, uint16(len(entries))) //nolint:gosec // fixed table
	for _, e := range entries {
		b = le.AppendUint16(b, e.tag)
		b = le.AppendUint16(b, e.typ)
		b = le.AppendUint32(b, 1)
		if e.typ == short {
			b = le.AppendUint16(b, uint16(e.val)) //nolint:gosec // small constants
			b = le.AppendUint16(b, 0)
		} else {
			b = le.AppendUint32(b, e.val)
		}
	}
	return le.AppendUint32(b, 0)
}

// webpVP8XHeader is an extended-format WebP whose VP8X chunk declares a
// w×h canvas (each at most 2^24).
func webpVP8XHeader(w, h uint32) []byte {
	le := binary.LittleEndian
	chunk := make([]byte, 4, 10) // flags and reserved bytes, then two 24-bit sizes
	for _, v := range []uint32{w - 1, h - 1} {
		chunk = append(chunk, byte(v), byte(v>>8), byte(v>>16)) //nolint:gosec // 24-bit fields, truncation intended
	}
	b := []byte("RIFF")
	b = le.AppendUint32(b, uint32(4+8+len(chunk))) //nolint:gosec // small
	b = append(b, "WEBPVP8X"...)
	b = le.AppendUint32(b, uint32(len(chunk))) //nolint:gosec // small
	return append(b, chunk...)
}

// TestToPDF_RejectsDimensionBombs feeds each image format a header that
// declares far more pixels than MaxImagePixels and almost no data. The
// decoders allocate width×height×4 bytes up front, so without a header
// check a few dozen bytes could ask for gigabytes. Every format must be
// refused with ImageTooLargeError before anything is decoded.
func TestToPDF_RejectsDimensionBombs(t *testing.T) {
	cases := []struct {
		name, ext string
		data      []byte
	}{
		{"bomb.png", extPNG, pngWithIDAT(20000, 20000, nil)},
		{"bomb.gif", extGIF, gifHeader(65535, 65535)},
		{"bomb.jpg", extJPG, jpegHeader(65535, 65535)},
		{"bomb.jpeg", extJPEG, jpegHeader(65535, 65535)},
		{"bomb.bmp", extBMP, bmpHeader(20000, 20000)},
		{"bomb.tif", extTIF, tiffHeader(20000, 20000)},
		{"bomb.webp", extWebP, webpVP8XHeader(16000, 16000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, converted, err := fileconv.ToPDF(c.name, c.ext, c.data)
			runtime.ReadMemStats(&after)
			var tooLarge *fileconv.ImageTooLargeError
			if !errors.As(err, &tooLarge) {
				t.Fatalf("ToPDF(%s) err = %v; want *ImageTooLargeError", c.name, err)
			}
			if converted {
				t.Error("converted = true on error")
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
				t.Errorf("ToPDF(%s) allocated %d MiB before refusing; want the header check to run first", c.name, grew>>20)
			}
		})
	}
}

// TestToPDF_AcceptsImagesAtTheCap checks the cap is inclusive and that
// an ordinary image of every format still converts.
func TestToPDF_AcceptsImagesAtTheCap(t *testing.T) {
	img := image.NewGray(image.Rect(0, 0, 64, 48))
	enc := map[string]func(*bytes.Buffer) error{
		extPNG:  func(b *bytes.Buffer) error { return png.Encode(b, img) },
		extJPG:  func(b *bytes.Buffer) error { return jpeg.Encode(b, img, nil) },
		extGIF:  func(b *bytes.Buffer) error { return gif.Encode(b, img, nil) },
		extBMP:  func(b *bytes.Buffer) error { return bmp.Encode(b, img) },
		extTIFF: func(b *bytes.Buffer) error { return tiff.Encode(b, img, nil) },
	}
	for ext, f := range enc {
		var b bytes.Buffer
		if err := f(&b); err != nil {
			t.Fatalf("encode %s: %v", ext, err)
		}
		if _, _, err := fileconv.ToPDF("ok"+ext, ext, b.Bytes()); err != nil {
			t.Errorf("ToPDF(%s 64x48) = %v; want success", ext, err)
		}
	}
	if fileconv.MaxImagePixels < 40_000_000 {
		t.Errorf("MaxImagePixels = %d; a 40-megapixel phone photo must still convert", fileconv.MaxImagePixels)
	}
}
