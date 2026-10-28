package cmd

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// updateE2EGoldens regenerates testdata/e2e-outcomes/*.json:
//
//	go test ./cmd/sigcomply/ -run TestBinaryE2E -update
//
// Read the diff before committing it: each changed entry is a verdict
// the binary now reaches differently.
var updateE2EGoldens = flag.Bool("update", false, "regenerate the binary E2E goldens in testdata/e2e-outcomes/")

// e2eOutcome is what the goldens pin per policy: the verdict, the
// resource counts and the flagged resource IDs.
type e2eOutcome struct {
	Status             core.PolicyStatus `json:"status"`
	ResourcesEvaluated int               `json:"resources_evaluated"`
	ResourcesFailed    int               `json:"resources_failed"`
	Violated           []string          `json:"violated,omitempty"`
}

// readResults returns every result.json in a run folder by policy ID.
func readResults(t *testing.T, runDir string) map[string]core.PolicyResult {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(runDir, "policies", "*", "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no result.json under %s", runDir)
	}
	out := make(map[string]core.PolicyResult, len(files))
	for _, f := range files {
		var pr core.PolicyResult
		readJSON(t, f, &pr)
		out[pr.PolicyID] = pr
	}
	return out
}

// assertOutcomesGolden compares every policy result in runDir with
// testdata/e2e-outcomes/<name>.json.
func assertOutcomesGolden(t *testing.T, runDir, name string) {
	t.Helper()
	got := map[string]e2eOutcome{}
	results := readResults(t, runDir)
	for id := range results {
		r := results[id]
		o := e2eOutcome{Status: r.Status, ResourcesEvaluated: r.ResourcesEvaluated, ResourcesFailed: r.ResourcesFailed}
		for _, v := range r.Violations {
			o.Violated = append(o.Violated, v.ResourceID)
		}
		sort.Strings(o.Violated)
		got[id] = o
	}
	assertE2EGolden(t, name, got)
}

// assertE2EGolden writes got under -update, then names every key whose
// value differs from testdata/e2e-outcomes/<name>.json, and every key
// only one side has.
func assertE2EGolden[V any](t *testing.T, name string, got map[string]V) {
	t.Helper()
	path := filepath.Join("testdata", "e2e-outcomes", name+".json")
	buf, err := json.MarshalIndent(got, "", "  ") // map keys sort, so the file diffs by key
	if err != nil {
		t.Fatal(err)
	}
	buf = append(buf, '\n')
	if *updateE2EGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path) //nolint:gosec // #nosec G304 -- fixed testdata path
	if err != nil {
		t.Fatalf("%v (generate with -update)", err)
	}
	var want map[string]json.RawMessage
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	problems := goldenDiff(t, got, want)
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Errorf("%d entr(ies) differ from %s:\n  %s\nIf every change is intended, regenerate with -update and review the diff.",
			len(problems), path, strings.Join(problems, "\n  "))
		return
	}
	if !bytes.Equal(raw, buf) {
		t.Errorf("%s is not in canonical form; regenerate with -update", path)
	}
}

// goldenDiff lists, by key, every value that differs and every key only
// one side has.
func goldenDiff[V any](t *testing.T, got map[string]V, want map[string]json.RawMessage) []string {
	t.Helper()
	var problems []string
	for k, v := range got {
		gj, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		w, ok := want[k]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: not in the golden, got %s", k, gj))
			continue
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, w); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gj, compact.Bytes()) {
			problems = append(problems, fmt.Sprintf("%s:\n      got  %s\n      want %s", k, gj, compact.Bytes()))
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			problems = append(problems, k+": in the golden, missing from the run")
		}
	}
	return problems
}
