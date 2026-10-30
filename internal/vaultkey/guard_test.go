package vaultkey_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoHandBuiltVaultKeys is the class guard for path-unsafe vault
// keys: every key under a run folder or the state prefix is built with
// vaultkey.Join or JoinUnder, which validate each segment. A
// fmt.Sprintf that formats one of the run's well-known file or folder
// names is a builder that skipped the validation.
func TestNoHandBuiltVaultKeys(t *testing.T) {
	handBuilt := regexp.MustCompile(`Sprintf\("[^"]*(policies/|manifest\.json|result\.json|summary\.json|state/|envelopes/|attachments/)`)
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
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
			for i, line := range strings.Split(string(src), "\n") {
				if handBuilt.MatchString(line) {
					t.Errorf("%s:%d builds a vault key with Sprintf; use vaultkey.Join or JoinUnder", path, i+1)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
