package scripts_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// diffContracts runs scripts/contracts/diff_contracts.py on two JSON
// documents and returns its report and whether it found breaking drift.
func diffContracts(t *testing.T, oldDoc, newDoc string) (report string, breaking bool) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	if out, err := exec.CommandContext(context.Background(), python, "-I", "-c", "import json").CombinedOutput(); err != nil { //nolint:gosec // fixed arguments
		t.Skipf("python3 does not run: %v\n%s", err, out)
	}
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	if err := os.WriteFile(oldPath, []byte(oldDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(newDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), python, "-I", "contracts/diff_contracts.py", oldPath, newPath, "label") //nolint:gosec // fixed script and temp files
	out, err := cmd.CombinedOutput()
	report = string(out)
	// Every report starts with the label line; anything else means the
	// script did not run (a broken interpreter also exits 1).
	if !strings.HasPrefix(report, "  label: ") {
		t.Fatalf("diff_contracts.py did not produce a report: %v\n%s", err, out)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(report, "BREAKING") {
			t.Fatalf("diff_contracts.py: %v\n%s", err, out)
		}
		return report, true
	}
	return report, false
}

// Endpoint-routing rules, documentation strings and relative $ref depth
// change upstream all the time without touching a shape a plugin reads.
// They must not raise a breaking-drift alert.
func TestDiffContracts_IgnoresNoise(t *testing.T) {
	oldDoc := `{"shapes":{"svc#Service":{"type":"service","traits":{
	    "smithy.rules#endpointBdd":{"nodeCount":28,"results":[{"a":1}]},
	    "smithy.api#documentation":"old words"}},
	  "svc#User":{"type":"structure","members":{"Name":{"target":"smithy.api#String"}}}},
	 "definitions":{"Account":{"allOf":[{"$ref":"../../../common-types/v5/types.json#/definitions/Resource"}],
	    "description":"old prose","properties":{"mode":{"type":"string","enumDescriptions":["a","b"]}}}}}`
	newDoc := `{"shapes":{"svc#Service":{"type":"service","traits":{
	    "smithy.rules#endpointBdd":{"nodeCount":43,"results":[{"b":2}]},
	    "smithy.api#documentation":"new words"}},
	  "svc#User":{"type":"structure","members":{"Name":{"target":"smithy.api#String"}}}},
	 "definitions":{"Account":{"allOf":[{"$ref":"../../../../common-types/v5/types.json#/definitions/Resource"}],
	    "description":"new prose","properties":{"mode":{"type":"string","enumDescriptions":["a"]}}}}}`
	report, breaking := diffContracts(t, oldDoc, newDoc)
	if breaking || !strings.Contains(report, "no change") {
		t.Errorf("noise reported as drift:\n%s", report)
	}
}

// The filters must not hide real drift: a removed member, a removed enum
// value, a $ref to a different target, or a removed field that happens
// to be named "description".
func TestDiffContracts_KeepsRealDrift(t *testing.T) {
	cases := map[string][2]string{
		"removed member": {
			`{"shapes":{"svc#User":{"members":{"Name":{},"Email":{}}}}}`,
			`{"shapes":{"svc#User":{"members":{"Name":{}}}}}`,
		},
		"removed enum value": {
			`{"definitions":{"Kind":{"enum":["a","b"]}}}`,
			`{"definitions":{"Kind":{"enum":["a"]}}}`,
		},
		"ref to another target": {
			`{"definitions":{"A":{"$ref":"../types.json#/definitions/Resource"}}}`,
			`{"definitions":{"A":{"$ref":"../../types.json#/definitions/TrackedResource"}}}`,
		},
		"removed description field": {
			`{"definitions":{"Rule":{"properties":{"description":{"type":"string"},"name":{"type":"string"}}}}}`,
			`{"definitions":{"Rule":{"properties":{"name":{"type":"string"}}}}}`,
		},
	}
	for name, docs := range cases {
		t.Run(name, func(t *testing.T) {
			report, breaking := diffContracts(t, docs[0], docs[1])
			if !breaking {
				t.Errorf("real drift not reported:\n%s", report)
			}
		})
	}
}
