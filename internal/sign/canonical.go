package sign

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Encode returns the RFC 8785-style canonical JSON encoding of v.
// Output is byte-identical for any Go input that represents the same
// logical JSON document — which is what makes Ed25519 signatures
// reproducible across processes, languages, and time.
//
// Canonicalization rules implemented:
//   - UTF-8 output (delegated to encoding/json).
//   - No insignificant whitespace.
//   - Object keys sorted lexicographically by Unicode code-point.
//   - String escaping follows encoding/json with SetEscapeHTML(false);
//     '<', '>', '&' are emitted verbatim, not as \u escapes.
//   - Numbers are preserved as their exact JSON source text via a
//     UseNumber re-parse, so arbitrary-precision integers (64-bit IDs,
//     epoch-nanosecond timestamps) survive canonicalization with no
//     precision loss. Floats are emitted verbatim from their source
//     text; signed payloads in this CLI are not expected to contain
//     floats, but if one appears it round-trips unchanged.
//   - Array order is preserved.
//
// The strategy is to leverage encoding/json for marshaling and string
// escaping (the parts most likely to go subtly wrong if hand-rolled),
// then re-emit the resulting generic tree with sorted keys and no
// whitespace.
func Encode(v any) ([]byte, error) {
	first, err := marshalNoHTMLEscape(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	// Re-parse with UseNumber so JSON numbers are preserved as json.Number
	// (their exact source text) rather than decoded to float64. A plain
	// json.Unmarshal into `any` rounds every integer above 2^53 — and
	// EvidenceRecord.Payload is arbitrary vendor JSON that routinely
	// carries 64-bit IDs and epoch-nanosecond timestamps. Rounding them
	// here would silently corrupt the bytes we sign and persist as audit
	// evidence. writeCanonical's json.Number branch emits the digits verbatim.
	dec := json.NewDecoder(bytes.NewReader(first))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical: re-parse: %w", err)
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		return writeBool(buf, t)
	case string:
		return writeString(buf, t)
	case float64:
		return writeNumber(buf, t)
	case json.Number:
		buf.WriteString(string(t))
		return nil
	case []any:
		return writeArray(buf, t)
	case map[string]any:
		return writeObject(buf, t)
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
}

func writeBool(buf *bytes.Buffer, b bool) error {
	if b {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	return nil
}

func writeArray(buf *bytes.Buffer, items []any) error {
	buf.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, item); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

func writeObject(buf *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeCanonical(buf, obj[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeString(buf *bytes.Buffer, s string) error {
	raw, err := marshalNoHTMLEscape(s)
	if err != nil {
		return fmt.Errorf("canonical: marshal string: %w", err)
	}
	buf.Write(raw)
	return nil
}

func writeNumber(buf *bytes.Buffer, n float64) error {
	raw, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("canonical: marshal number: %w", err)
	}
	buf.Write(raw)
	return nil
}

// marshalNoHTMLEscape emits v as JSON without escaping HTML-sensitive
// characters. encoding/json's default is to escape '<', '>', '&' as
// \u escapes for browser safety; we want byte-identical output to
// other JSON producers (the SPA verifier, etc.) so we disable it.
func marshalNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
