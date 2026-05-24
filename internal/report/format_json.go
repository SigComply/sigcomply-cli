package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// FormatJSON writes a structured JSON rendering of snap to w. The
// output is indented 2-space for readability and is fully deterministic
// — Snapshot's content is already sorted by Build, and json.Encoder
// emits map keys in lexicographic order for any embedded maps.
//
// No "generated_at" field is emitted from here; the CLI command stamps
// run-time metadata outside the snapshot body so tests can assert
// byte-identical content across invocations.
func FormatJSON(w io.Writer, snap *Snapshot) error {
	if snap == nil {
		return fmt.Errorf("format json: nil Snapshot")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(snap)
}
