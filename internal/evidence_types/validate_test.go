package evidencetypes

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestValidate_EnforcesDraft07Constraints proves the constraints the old
// hand-rolled validator silently ignored — enum, minimum, nested
// `properties`, and array `items` — are now enforced.
func TestValidate_EnforcesDraft07Constraints(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"required": ["id", "severity", "score", "owner", "tags"],
		"properties": {
			"id": {"type": "string"},
			"severity": {"type": "string", "enum": ["LOW", "HIGH"]},
			"score": {"type": "integer", "minimum": 0, "maximum": 10},
			"owner": {
				"type": "object",
				"required": ["email"],
				"properties": {"email": {"type": "string"}}
			},
			"tags": {"type": "array", "items": {"type": "string"}}
		}
	}`)

	cases := []struct {
		name    string
		payload string
		wantErr string // substring; "" means must pass
	}{
		{
			name:    "valid",
			payload: `{"id":"a","severity":"HIGH","score":7,"owner":{"email":"x@y.z"},"tags":["a","b"]}`,
		},
		{
			name:    "enum violation",
			payload: `{"id":"a","severity":"CRITICAL","score":7,"owner":{"email":"x@y.z"},"tags":[]}`,
			wantErr: "severity",
		},
		{
			name:    "minimum violation",
			payload: `{"id":"a","severity":"LOW","score":99,"owner":{"email":"x@y.z"},"tags":[]}`,
			wantErr: "score",
		},
		{
			name:    "nested required missing",
			payload: `{"id":"a","severity":"LOW","score":1,"owner":{},"tags":[]}`,
			wantErr: "email",
		},
		{
			name:    "array item wrong type",
			payload: `{"id":"a","severity":"LOW","score":1,"owner":{"email":"x@y.z"},"tags":[1,2]}`,
			wantErr: "tags",
		},
		{
			name:    "top-level required missing",
			payload: `{"severity":"LOW","score":1,"owner":{"email":"x@y.z"},"tags":[]}`,
			wantErr: "id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(schema, json.RawMessage(tc.payload))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestValidate_AllEmbeddedSchemasCompile ensures every shipped schema is
// a valid draft-07 document the validator can compile — a malformed
// schema would otherwise only surface at collection time.
func TestValidate_AllEmbeddedSchemasCompile(t *testing.T) {
	files, err := embeddedFiles()
	if err != nil {
		t.Fatalf("embeddedFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no embedded schemas found")
	}
	for _, name := range files {
		data, err := schemasFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := compileSchema(data); err != nil {
			t.Errorf("%s: does not compile as draft-07: %v", name, err)
		}
	}
}

func TestValidate_EmptyInputs(t *testing.T) {
	if err := Validate(nil, json.RawMessage(`{}`)); err == nil {
		t.Error("expected error for empty schema")
	}
	if err := Validate(json.RawMessage(`{"type":"object"}`), nil); err == nil {
		t.Error("expected error for empty payload")
	}
}
