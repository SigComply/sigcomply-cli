package manualcatalog_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	fwregistry "github.com/sigcomply/sigcomply-cli/internal/frameworks"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin" // registers every framework
)

// updateCatalogGolden regenerates testdata/<framework>_golden.json, the
// manual catalog exactly as `sigcomply evidence catalog -o json` prints
// it (the binary E2E test in cmd/sigcomply compares the two):
//
//	go test ./internal/manualcatalog/ -run TestCatalogGolden -update
//
// The Evidence SPA validates these files with its catalog type guard;
// copy them there in the same task.
var updateCatalogGolden = flag.Bool("update", false, "regenerate the manual catalog goldens")

func TestCatalogGolden(t *testing.T) {
	ids := fwregistry.IDs()
	written := 0
	for _, id := range ids {
		f, ok := fwregistry.Lookup(id)
		if !ok || f.ManualCatalogExport == nil {
			continue
		}
		written++
		// The same encoder settings as runEvidenceCatalog.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(f.ManualCatalogExport()); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("testdata", id+"_golden.json")
		if *updateCatalogGolden {
			if err := os.MkdirAll("testdata", 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(path) //nolint:gosec // #nosec G304 -- fixed testdata path
		if err != nil {
			t.Fatalf("%v (generate with -update)", err)
		}
		if !bytes.Equal(got, buf.Bytes()) {
			t.Errorf("%s is stale; rerun with -update and copy it to the Evidence SPA", path)
		}
	}
	if written == 0 {
		t.Fatalf("no framework exports a manual catalog (registered: %v)", ids)
	}
}
