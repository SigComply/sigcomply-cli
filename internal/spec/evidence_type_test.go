package spec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEvidenceType_Valid(t *testing.T) {
	data := readTestdata(t, "evidence_type/valid_user_record.json")

	et, err := LoadEvidenceType(data)
	if err != nil {
		t.Fatalf("LoadEvidenceType: %v", err)
	}
	if et.ID != "user_record" {
		t.Errorf("ID = %q; want %q", et.ID, "user_record")
	}
	if et.Version != 1 {
		t.Errorf("Version = %d; want 1", et.Version)
	}
	if len(et.Schema) == 0 {
		t.Error("Schema bytes were not preserved")
	}
	// The preserved Schema must round-trip as JSON identical to the
	// input (modulo whitespace) — confirms we did not mutate it.
	var got, want any
	if err := json.Unmarshal(et.Schema, &got); err != nil {
		t.Fatalf("Schema bytes are not valid JSON: %v", err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("input is not valid JSON: %v", err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("re-marshal got: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("re-marshal want: %v", err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Errorf("Schema round-trip differs:\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

func TestLoadEvidenceType_RejectsInvalid(t *testing.T) {
	cases := []struct {
		file    string
		wantSub string
	}{
		{"evidence_type/invalid_missing_title.json", "title"},
		{"evidence_type/invalid_zero_version.json", "version"},
		{"evidence_type/invalid_wrong_type.json", "type"},
		{"evidence_type/invalid_malformed.json", "parse"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data := readTestdata(t, tc.file)
			_, err := LoadEvidenceType(data)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q; want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadEvidenceType_EmptyInput(t *testing.T) {
	if _, err := LoadEvidenceType(nil); err == nil {
		t.Error("expected error on nil input")
	}
	if _, err := LoadEvidenceType([]byte("   \n  ")); err == nil {
		t.Error("expected error on whitespace input")
	}
}

// readTestdata reads a file under internal/spec/testdata/. Shared by
// every spec parser test in this package.
func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	path := filepath.Join("testdata", rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
