package sign

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func sampleEnvelope() *core.Envelope {
	return &core.Envelope{
		FormatVersion: "envelope.v1",
		ProducedAt:    time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
		Records: []core.EvidenceRecord{
			{
				Type:        "user_record",
				ID:          "AIDAEXAMPLE",
				Payload:     json.RawMessage(`{"mfa_enabled":false}`),
				SourceID:    "aws.iam",
				CollectedAt: time.Date(2026, 5, 23, 14, 0, 1, 0, time.UTC),
			},
		},
	}
}

func TestEnvelopePopulatesSignature(t *testing.T) {
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	if e.Signature.Algorithm != AlgorithmEd25519 {
		t.Errorf("Algorithm = %q; want %s", e.Signature.Algorithm, AlgorithmEd25519)
	}
	if len(e.Signature.PublicKey) != 32 {
		t.Errorf("PublicKey len = %d; want 32", len(e.Signature.PublicKey))
	}
	if len(e.Signature.Value) != 64 {
		t.Errorf("Value len = %d; want 64", len(e.Signature.Value))
	}
}

func TestSignVerifyEnvelopeRoundTrip(t *testing.T) {
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	if err := VerifyEnvelope(e); err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
}

func TestVerifyEnvelopeAfterJSONRoundTrip(t *testing.T) {
	// The end-to-end shape: sign → encode → unmarshal → verify. This
	// is what an auditor sees when reading a stored envelope.
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	body, err := EncodeEnvelope(e)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	var back core.Envelope
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := VerifyEnvelope(&back); err != nil {
		t.Fatalf("VerifyEnvelope after JSON round-trip: %v", err)
	}
}

func TestVerifyEnvelopeRejectsTamperedRecord(t *testing.T) {
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	e.Records[0].Payload = json.RawMessage(`{"mfa_enabled":true}`)
	if err := VerifyEnvelope(e); err == nil {
		t.Error("VerifyEnvelope accepted tampered record payload")
	}
}

func TestVerifyEnvelopeRejectsTamperedFormatVersion(t *testing.T) {
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	e.FormatVersion = "envelope.v2"
	if err := VerifyEnvelope(e); err == nil {
		t.Error("VerifyEnvelope accepted tampered format_version")
	}
}

func TestVerifyEnvelopeRejectsTamperedSignature(t *testing.T) {
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	e.Signature.Value[0] ^= 0xFF
	if err := VerifyEnvelope(e); err == nil {
		t.Error("VerifyEnvelope accepted tampered signature value")
	}
}

func TestEncodeEnvelopeRequiresSignature(t *testing.T) {
	e := sampleEnvelope()
	if _, err := EncodeEnvelope(e); err == nil {
		t.Error("EncodeEnvelope accepted unsigned envelope")
	}
}

func TestEncodeEnvelopeProducesCanonicalBytes(t *testing.T) {
	// The same logically-identical envelope encoded twice must
	// produce byte-identical output (modulo the random signature),
	// even with different map iteration order in the records'
	// payloads.
	e1 := sampleEnvelope()
	e1.Records[0].Payload = json.RawMessage(`{"a":1,"b":2,"c":3}`)
	e2 := sampleEnvelope()
	e2.Records[0].Payload = json.RawMessage(`{"c":3,"a":1,"b":2}`)
	// Use a fixed signature so we compare structural canonical form,
	// not the random ephemeral key.
	e1.Signature = core.EnvelopeSignature{Algorithm: AlgorithmEd25519, PublicKey: []byte("k"), Value: []byte("v")}
	e2.Signature = e1.Signature
	b1, err := EncodeEnvelope(e1)
	if err != nil {
		t.Fatalf("EncodeEnvelope e1: %v", err)
	}
	b2, err := EncodeEnvelope(e2)
	if err != nil {
		t.Fatalf("EncodeEnvelope e2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("canonical encoding differs between logically-identical envelopes:\n%s\n%s", b1, b2)
	}
}

func TestEnvelopeRejectsNil(t *testing.T) {
	if err := Envelope(nil); err == nil {
		t.Error("Envelope(nil) returned nil error")
	}
}

func TestVerifyEnvelopeRejectsNil(t *testing.T) {
	if err := VerifyEnvelope(nil); err == nil {
		t.Error("VerifyEnvelope(nil) returned nil error")
	}
}
