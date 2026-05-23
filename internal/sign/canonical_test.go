package sign

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEncodeEmptyObject(t *testing.T) {
	got, err := Encode(map[string]any{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(got) != "{}" {
		t.Errorf("Encode({}) = %q; want {}", got)
	}
}

func TestEncodeSortsObjectKeys(t *testing.T) {
	got, err := Encode(map[string]any{"b": 1, "a": 2, "c": 3})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"a":2,"b":1,"c":3}`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}

func TestEncodeSortsNestedKeys(t *testing.T) {
	got, err := Encode(map[string]any{
		"outer": map[string]any{"z": 1, "a": 2},
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"outer":{"a":2,"z":1}}`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}

func TestEncodePreservesArrayOrder(t *testing.T) {
	got, err := Encode([]any{3, 1, 2})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `[3,1,2]`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}

func TestEncodeNoWhitespace(t *testing.T) {
	got, err := Encode(map[string]any{"a": []any{1, 2, 3}, "b": "x"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"a":[1,2,3],"b":"x"}`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}

func TestEncodePrimitives(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{true, "true"},
		{false, "false"},
		{"hello", `"hello"`},
		{int(42), "42"},
		{float64(1.5), "1.5"},
	}
	for _, c := range cases {
		got, err := Encode(c.in)
		if err != nil {
			t.Errorf("Encode(%v): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("Encode(%v) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestEncodeDoesNotEscapeHTMLChars(t *testing.T) {
	// encoding/json's default escapes '<', '>', '&'. We disable that
	// so output is byte-identical to producers that don't escape HTML
	// (the SPA verifier, anything signed in another language).
	got, err := Encode(map[string]any{"x": "<a href=\"y\">&amp;</a>"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"x":"<a href=\"y\">&amp;</a>"}`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}

func TestEncodeStringWithControlChars(t *testing.T) {
	// Control characters should be \u-escaped per RFC 8259 — Go's
	// encoding/json handles this.
	got, err := Encode("line1\nline2\ttab")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `"line1\nline2\ttab"`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	// Two separate Encode calls on logically identical inputs (with
	// different map iteration order in Go) must produce identical
	// bytes — the entire signing scheme depends on this.
	a := map[string]any{"z": 1, "a": 2, "m": 3, "b": 4}
	b := map[string]any{"a": 2, "z": 1, "b": 4, "m": 3}
	ab, err := Encode(a)
	if err != nil {
		t.Fatalf("Encode(a): %v", err)
	}
	bb, err := Encode(b)
	if err != nil {
		t.Fatalf("Encode(b): %v", err)
	}
	if !bytes.Equal(ab, bb) {
		t.Errorf("Encode is non-deterministic: %q vs %q", ab, bb)
	}
}

func TestEncodeStructMatchesEquivalentMap(t *testing.T) {
	type point struct {
		Y int `json:"y"`
		X int `json:"x"`
	}
	got, err := Encode(point{X: 1, Y: 2})
	if err != nil {
		t.Fatalf("Encode struct: %v", err)
	}
	gotMap, err := Encode(map[string]any{"x": 1, "y": 2})
	if err != nil {
		t.Fatalf("Encode map: %v", err)
	}
	if !bytes.Equal(got, gotMap) {
		t.Errorf("struct and map encodings differ: struct=%q map=%q", got, gotMap)
	}
	want := `{"x":1,"y":2}`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}

func TestEncodeHandlesRawMessage(t *testing.T) {
	// json.RawMessage is how Payload fields carry pre-encoded JSON.
	// The canonical encoder must re-canonicalize the contents (sort
	// keys, strip whitespace) so verification is stable.
	body := struct {
		Payload json.RawMessage `json:"payload"`
	}{
		Payload: json.RawMessage(`{ "b" : 1 , "a" : 2 }`),
	}
	got, err := Encode(body)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"payload":{"a":2,"b":1}}`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q", got, want)
	}
}
