package vaultkey_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	stringLiteral = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	keyFragment   = regexp.MustCompile(`(?:"|/)(?:policies|state|envelopes|attachments)/|/(?:result|manifest|summary)\.json`)
	// readSideFragments: file → fragments it may use to read or match
	// keys a vault listing returned. Writes never appear here.
	readSideFragments = map[string]map[string]bool{
		"internal/report/report.go":         {"/manifest.json": true, "/policies/": true, "/result.json": true, `"policies/`: true},
		"internal/report/scope.go":          {"/summary.json": true},
		"internal/vault/vaulttest/suite.go": {`"envelopes/`: true},
	}
)

// TestNoHandBuiltVaultKeys is the class guard for path-unsafe vault
// keys: every key under a run folder or the state prefix is built with
// vaultkey.Join or JoinUnder, which validate each segment. A
// fmt.Sprintf that formats one of the run's well-known file or folder
// names is a builder that skipped the validation.
//
// It also flags any string literal that is a piece of such a key (a
// well-known name next to a "/": "/result.json", "policies/"), which
// catches concatenation as well as Sprintf. A bare segment name
// ("manifest.json") is what Join takes and is not flagged. The read side
// matches listed keys against fixed prefixes and suffixes; those uses
// are listed in readSideFragments.
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
			rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
			for i, line := range strings.Split(string(src), "\n") {
				if handBuilt.MatchString(line) {
					t.Errorf("%s:%d builds a vault key with Sprintf; use vaultkey.Join or JoinUnder", path, i+1)
				}
				checkKeyLiterals(t, path, rel, i+1, line)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// checkKeyLiterals flags a string literal on line that is a piece of a
// vault key, unless rel lists it as a read-side use.
func checkKeyLiterals(t *testing.T, path, rel string, lineNo int, line string) {
	t.Helper()
	if strings.HasPrefix(strings.TrimSpace(line), "//") || strings.HasPrefix(rel, "internal/vaultkey/") {
		return
	}
	for _, lit := range stringLiteral.FindAllString(line, -1) {
		if keyFragment.MatchString(lit) && !readSideFragments[rel][keyFragment.FindString(lit)] {
			t.Errorf("%s:%d: the literal %s is a piece of a vault key; build keys with vaultkey.Join or JoinUnder (or list a read-side prefix in readSideFragments)", path, lineNo, lit)
		}
	}
}
