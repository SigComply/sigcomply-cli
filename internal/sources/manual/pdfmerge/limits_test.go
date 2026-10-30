package pdfmerge_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources/manual/pdfmerge"
)

// TestMerge_RefusesHugeObjectNumbers is the FuzzMerge crasher
// testdata/fuzz/FuzzMerge/e690d46da5f9bf1b reduced to its cause: one
// object renumbered to 303021135. pdfcpu sizes a map by the highest
// object number when it renumbers objects for the merge, so this 1 KB
// file made a single merge allocate about 9 GB. Merge must refuse it,
// name the file, and allocate little.
func TestMerge_RefusesHugeObjectNumbers(t *testing.T) {
	good := realPDF(t)
	bomb := bytes.Replace(good, []byte("\n3 0 obj"), []byte("\n303021135 0 obj"), 1)
	if bytes.Equal(bomb, good) {
		t.Fatal("fixture: object 3 not found in the generated PDF")
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := pdfmerge.Merge(context.Background(), [][]byte{good, bomb})
	runtime.ReadMemStats(&after)
	var pe *pdfmerge.PartError
	if !errors.As(err, &pe) || pe.Index != 1 {
		t.Fatalf("Merge err = %v; want a *PartError for input 1", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 256<<20 {
		t.Errorf("Merge allocated %d MiB before refusing; want under 256", grew>>20)
	}
}

// TestNoDefaultPDFCPUConfiguration guards the pdfcpu configuration
// class: model.NewDefaultConfiguration reads and writes a config.yml in
// the user's config directory (and loads user fonts from it), which a CLI
// running in CI has no reason to touch. Every pdfcpu call in non-test
// code must use the stateless configuration instead.
func TestNoDefaultPDFCPUConfiguration(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	banned := regexp.MustCompile(`model\.NewDefaultConfiguration\(|api\.LoadConfiguration\(|model\.NewAESConfiguration\(|model\.NewRC4Configuration\(`)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" || name == "node_modules" || (strings.HasPrefix(name, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // walking the repo's own sources
		if err != nil {
			return err
		}
		if banned.Match(src) {
			t.Errorf("%s uses a pdfcpu configuration that reads the user config dir; use pdfmerge's stateless configuration", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
