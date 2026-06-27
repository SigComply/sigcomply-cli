package sourcetest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// miniSpec is a minimal self-contained OpenAPI 3.0 doc: one component with a
// required integer and a nullable string, enough to exercise the validator.
const miniSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {},
  "components": {"schemas": {
    "widget": {
      "type": "object",
      "required": ["id"],
      "properties": {
        "id": {"type": "integer"},
        "name": {"type": "string", "nullable": true}
      }
    }
  }}
}`

func writeSpec(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(p, []byte(miniSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// jsonValue decodes a JSON literal the way a real response body is decoded
// (numbers → float64), so the validator sees production-shaped values.
func jsonValue(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return v
}

func TestSpecValidatorCheck(t *testing.T) {
	v := NewSpecValidator(t, writeSpec(t))

	cases := []struct {
		name      string
		component string
		body      string
		wantErr   bool
	}{
		{"valid", "widget", `{"id": 1, "name": "w"}`, false},
		{"nullable field null", "widget", `{"id": 2, "name": null}`, false},
		{"missing required", "widget", `{"name": "w"}`, true},
		{"wrong type", "widget", `{"id": "nope"}`, true},
		{"unknown component", "gadget", `{"id": 1}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Check(tc.component, jsonValue(t, tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("Check(%s) err=%v, wantErr=%v", tc.component, err, tc.wantErr)
			}
		})
	}
}

func TestSpecValidatorCheckArray(t *testing.T) {
	v := NewSpecValidator(t, writeSpec(t))

	if err := v.CheckArray("widget", jsonValue(t, `[{"id": 1}, {"id": 2}]`)); err != nil {
		t.Errorf("valid array should pass, got %v", err)
	}
	if err := v.CheckArray("widget", jsonValue(t, `[{"id": 1}, {"name": "x"}]`)); err == nil {
		t.Error("array with an off-spec element should fail")
	}
	if err := v.CheckArray("widget", jsonValue(t, `{"id": 1}`)); err == nil {
		t.Error("non-array value should fail CheckArray")
	}
}

func TestLoadCassetteInteractions(t *testing.T) {
	// Reuse the WU-1.2 sample cassette shipped in this package's testdata.
	interactions := LoadCassetteInteractions(t, "testdata/cassettes/sample")
	if len(interactions) == 0 {
		t.Fatal("expected interactions in sample cassette")
	}
	if interactions[0].Request.Method == "" || interactions[0].Request.URL == "" {
		t.Error("interaction missing method/URL")
	}
}

func TestDecodeJSONBody(t *testing.T) {
	if _, ok := DecodeJSONBody(t, "   "); ok {
		t.Error("blank body should decode to ok=false")
	}
	v, ok := DecodeJSONBody(t, `{"a": 1}`)
	if !ok {
		t.Fatal("non-empty body should decode to ok=true")
	}
	if m, isMap := v.(map[string]any); !isMap || m["a"] != float64(1) {
		t.Errorf("decoded value = %#v, want map with a=1", v)
	}
}
