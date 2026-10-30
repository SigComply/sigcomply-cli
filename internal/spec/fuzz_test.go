package spec

import (
	"os"
	"path/filepath"
	"testing"
)

// addSeeds adds every file under testdata/<dir> to the fuzz corpus.
func addSeeds(f *testing.F, dir string) {
	f.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", dir, "*"))
	if err != nil || len(paths) == 0 {
		f.Fatalf("no seeds in testdata/%s: %v", dir, err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // fixed testdata paths
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
}

// FuzzLoadProjectConfig: .sigcomply.yaml comes from the repository, and
// a pull request can change it. Loading it must return an error for bad
// input, never panic. Run in CI by the fuzz job; crashers live in
// testdata/fuzz/FuzzLoadProjectConfig and run under go test.
func FuzzLoadProjectConfig(f *testing.F) {
	addSeeds(f, "project_config")
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = LoadProjectConfig(data) //nolint:errcheck // the property is "no panic"
	})
}

// FuzzLoadPolicy: project-local policy.yaml files come from the
// repository too. Same property as FuzzLoadProjectConfig.
func FuzzLoadPolicy(f *testing.F) {
	addSeeds(f, "policy")
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := LoadPolicy(data)
		if err == nil && p.ID == "" {
			t.Fatal("LoadPolicy accepted a policy without an id")
		}
	})
}
