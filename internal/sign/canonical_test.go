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

func TestEncodePreservesLargeIntegers(t *testing.T) {
	// EvidenceRecord payloads carry arbitrary vendor JSON, including
	// 64-bit IDs and epoch-nanosecond timestamps that exceed 2^53. These
	// are what gets signed and persisted as audit evidence — a float64
	// re-parse would silently round them. The canonical encoder must
	// preserve the exact digits.
	body := struct {
		Payload json.RawMessage `json:"payload"`
	}{
		// 9007199254740993 = 2^53 + 1 (first integer float64 cannot
		// represent); the second is near uint64 max.
		Payload: json.RawMessage(`{"big":18446744073709551615,"id":9007199254740993}`),
	}
	got, err := Encode(body)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"payload":{"big":18446744073709551615,"id":9007199254740993}}`
	if string(got) != want {
		t.Errorf("Encode = %q; want %q (large integers must not be rounded)", got, want)
	}
}
