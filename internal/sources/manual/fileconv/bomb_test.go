package fileconv_test

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/fileconv"
)

// pngBomb builds a PNG whose IHDR declares a 16×16 image of colorType
// (6 = RGBA, 4 = gray+alpha) and whose IDAT inflates to inflated bytes
// of zeros: a few kilobytes on disk that decompress far past what the
// header allows.
func pngBomb(colorType byte, inflated int) []byte {
	ihdr := binary.BigEndian.AppendUint32(nil, 16)
	ihdr = binary.BigEndian.AppendUint32(ihdr, 16)
	ihdr = append(ihdr, 8, colorType, 0, 0, 0)
	var z bytes.Buffer
	zw, err := zlib.NewWriterLevel(&z, zlib.BestCompression)
	if err != nil {
		panic(err)
	}
	chunk := make([]byte, 1<<20)
	for n := 0; n < inflated; n += len(chunk) {
		if _, err := zw.Write(chunk); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, pngChunk("IHDR", ihdr)...)
	out = append(out, pngChunk("IDAT", z.Bytes())...)
	return append(out, pngChunk("IEND", nil)...)
}

// TestToPDF_PNGDecompressionBombIsBounded: a PNG with alpha and a small
// valid header passes the pixel limit, and gofpdf then inflated its
// whole IDAT stream into memory to split off the alpha channel. A
// zlib bomb of a few hundred kilobytes became gigabytes and an OOM kill
// that recover() cannot catch. ToPDF must read no more pixel data than
// the header declares.
func TestToPDF_PNGDecompressionBombIsBounded(t *testing.T) {
	const inflated = 128 << 20
	for name, colorType := range map[string]byte{"rgba": 6, "gray+alpha": 4} {
		data := pngBomb(colorType, inflated)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		out, converted, err := fileconv.ToPDF("bomb.png", extPNG, data)
		runtime.ReadMemStats(&after)
		if err == nil || converted || out != nil {
			t.Errorf("%s: ToPDF(bomb) = %d bytes, converted=%v, err=%v; want an error", name, len(out), converted, err)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 32<<20 {
			t.Errorf("%s: ToPDF allocated %d MB for a %d KB file declaring 16×16 pixels", name, grew>>20, len(data)>>10)
		}
	}
}
