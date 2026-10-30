package sign_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
)

// FuzzVerifyEnvelope decodes arbitrary bytes as an envelope and verifies
// it, the way `report --view integrity` and an auditor's tooling read a
// vault an attacker may have written to. Decoding and verifying must
// return an error for bad input, never panic, and a mutated envelope
// must never verify as a different one: if verification succeeds, the
// re-encoded envelope must verify too. Run in CI by the fuzz job;
// crashers live in testdata/fuzz/FuzzVerifyEnvelope and run under
// go test.
func FuzzVerifyEnvelope(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("testdata", "spa-golden", "*.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // fixed testdata paths
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	env := &core.Envelope{
		FormatVersion: "envelope.v1",
		ProducedAt:    time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC),
		Records:       []core.EvidenceRecord{{ID: "r1", Type: "t", SourceID: "s", Payload: json.RawMessage(`{"a":1.5,"b":[true,null,"x"]}`)}},
	}
	if err := sign.Envelope(env); err != nil {
		f.Fatal(err)
	}
	signed, err := sign.EncodeEnvelope(env)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(signed)

	f.Fuzz(func(t *testing.T, data []byte) {
		var e core.Envelope
		if err := json.Unmarshal(data, &e); err != nil {
			return
		}
		if err := sign.VerifyEnvelope(&e); err != nil {
			return
		}
		again, err := sign.EncodeEnvelope(&e)
		if err != nil {
			t.Fatalf("a verified envelope does not re-encode: %v", err)
		}
		var e2 core.Envelope
		if err := json.Unmarshal(again, &e2); err != nil {
			t.Fatalf("re-encoded envelope does not decode: %v", err)
		}
		if err := sign.VerifyEnvelope(&e2); err != nil {
			t.Fatalf("re-encoded envelope no longer verifies: %v", err)
		}
	})
}
