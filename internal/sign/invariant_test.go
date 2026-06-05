package sign

// invariant_test.go — targeted tests for Sacred Invariant #3:
//   (a) signature verifies against the embedded public key
//   (b) tampered evidence/timestamp FAILS verification
//   (c) canonical JSON is what's signed (not a hash)
//   (d) each file gets a DISTINCT keypair
//   (e) the manifest is signed and verifiable
//   (f) the Register panic paths are exercised
//   (g) writeNumber is reached via Encode(float64)

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// ---------------------------------------------------------------------------
// Invariant (a): signature verifies against the embedded public key
// ---------------------------------------------------------------------------

func TestInvariant_SignatureVerifiesAgainstEmbeddedPublicKey(t *testing.T) {
	payload := []byte(`{"timestamp":"2026-01-01T00:00:00Z","evidence":"something"}`)
	sig, err := Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Verify using the public key embedded in the returned Signature.
	if err := Verify(payload, sig); err != nil {
		t.Fatalf("Verify with embedded public key failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Invariant (b): tampered evidence OR timestamp must fail
// ---------------------------------------------------------------------------

func TestInvariant_TamperedTimestampFails(t *testing.T) {
	e := sampleEnvelope()
	e.ProducedAt = time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC)
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	// Mutate the timestamp — the signing payload embeds it, so verify must fail.
	e.ProducedAt = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := VerifyEnvelope(e); err == nil {
		t.Error("VerifyEnvelope accepted a tampered ProducedAt timestamp")
	}
}

func TestInvariant_TamperedRecordIDFails(t *testing.T) {
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	// Mutate the record ID — this changes the signed payload.
	e.Records[0].ID = "tampered-id"
	if err := VerifyEnvelope(e); err == nil {
		t.Error("VerifyEnvelope accepted a tampered record ID")
	}
}

// ---------------------------------------------------------------------------
// Invariant (c): canonical JSON — not a hash — is what's signed
// ---------------------------------------------------------------------------

func TestInvariant_CanonicalJSONIsWhatsSigned_NotAHash(t *testing.T) {
	// Reconstruct the exact payload Envelope uses and verify that Sign()
	// over that payload produces a Signature verifiable by VerifyEnvelope.
	// If Sign were signing a SHA-256 digest instead of the canonical JSON
	// bytes, reconstructing the raw JSON and calling Verify would fail.
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}

	// Manually reconstruct what envelopeSigningBytes produces and sign it.
	type envelopeForSigning struct {
		FormatVersion string                `json:"format_version"`
		ProducedAt    time.Time             `json:"produced_at"`
		Records       []core.EvidenceRecord `json:"records"`
	}
	raw := envelopeForSigning{
		FormatVersion: e.FormatVersion,
		ProducedAt:    e.ProducedAt,
		Records:       e.Records,
	}
	canonicalPayload, err := Encode(raw)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// VerifyEnvelope internally computes the same canonical bytes and calls
	// Verify(payload, sig). If the canonical bytes match what was signed,
	// verification must succeed — proving it's the raw canonical JSON, not
	// a hash, that's signed.
	if err := VerifyEnvelope(e); err != nil {
		t.Fatalf("VerifyEnvelope failed: %v — implies canonical payload mismatch", err)
	}

	// Cross-check: verify using the reconstructed bytes + embedded sig directly.
	sig := Signature{
		Algorithm: e.Signature.Algorithm,
		PublicKey: e.Signature.PublicKey,
		Value:     e.Signature.Value,
	}
	if err := Verify(canonicalPayload, sig); err != nil {
		t.Errorf("Direct Verify(canonicalPayload, sig) failed: %v — canonical JSON is not what was signed", err)
	}
}

func TestInvariant_ManifestCanonicalJSONIsSigned(t *testing.T) {
	m := sampleManifest()
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	// Reconstruct manifestForSigning manually.
	type manifestForSigning struct {
		SchemaVersion     string                  `json:"schema_version"`
		RunID             string                  `json:"run_id"`
		Framework         string                  `json:"framework,omitempty"`
		PeriodID          string                  `json:"period_id,omitempty"`
		StartedAt         time.Time               `json:"started_at"`
		CompletedAt       time.Time               `json:"completed_at"`
		FileHashes        map[string]string       `json:"file_hashes"`
		ExceptionsApplied []core.AppliedException `json:"exceptions_applied,omitempty"`
	}
	raw := manifestForSigning{
		SchemaVersion: m.SchemaVersion,
		RunID:         m.RunID,
		StartedAt:     m.StartedAt,
		CompletedAt:   m.CompletedAt,
		FileHashes:    m.FileHashes,
	}
	canonicalPayload, err := Encode(raw)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	sig := Signature{
		Algorithm: m.Signature.Algorithm,
		PublicKey: m.Signature.PublicKey,
		Value:     m.Signature.Value,
	}
	if err := Verify(canonicalPayload, sig); err != nil {
		t.Errorf("Direct Verify(manifestCanonical) failed: %v — manifest is not signing canonical JSON", err)
	}
}

// ---------------------------------------------------------------------------
// Invariant (d): each call produces a DISTINCT keypair
// ---------------------------------------------------------------------------

func TestInvariant_EachEnvelopeGetsDistinctKeypair(t *testing.T) {
	// Sign three different envelopes; all public keys must differ.
	var sigs [3]core.EnvelopeSignature
	for i := range sigs {
		e := sampleEnvelope()
		e.Records[0].ID = "rec-" + string(rune('A'+i))
		if err := Envelope(e); err != nil {
			t.Fatalf("Envelope %d: %v", i, err)
		}
		sigs[i] = e.Signature
	}
	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			if bytes.Equal(sigs[i].PublicKey, sigs[j].PublicKey) {
				t.Errorf("envelope %d and %d share public key — per-file ephemeral keypair violated", i, j)
			}
		}
	}
}

func TestInvariant_EnvelopeAndManifestHaveDistinctKeypairs(t *testing.T) {
	// A run has one envelope and one manifest. They must use different keys.
	e := sampleEnvelope()
	if err := Envelope(e); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	m := sampleManifest()
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if bytes.Equal(e.Signature.PublicKey, m.Signature.PublicKey) {
		t.Error("envelope and manifest share public key — each must get its own ephemeral keypair")
	}
}

// ---------------------------------------------------------------------------
// Invariant (e): manifest is signed and independently verifiable
// ---------------------------------------------------------------------------

func TestInvariant_ManifestIsSignedAndVerifiable(t *testing.T) {
	m := sampleManifest()
	// Before signing, VerifyManifest must fail (no signature yet).
	if err := VerifyManifest(m); err == nil {
		t.Error("VerifyManifest on unsigned manifest should fail; got nil")
	}
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if err := VerifyManifest(m); err != nil {
		t.Fatalf("VerifyManifest on signed manifest: %v", err)
	}
	// The manifest signature must be independently verifiable (auditor
	// spot-check use case — described in CLAUDE.md Invariant #3).
	if m.Signature.Algorithm != AlgorithmEd25519 {
		t.Errorf("Algorithm = %q; want ed25519", m.Signature.Algorithm)
	}
	if len(m.Signature.PublicKey) != 32 || len(m.Signature.Value) != 64 {
		t.Errorf("signature sizes wrong: pub=%d val=%d", len(m.Signature.PublicKey), len(m.Signature.Value))
	}
}

// ---------------------------------------------------------------------------
// Register panic paths (currently at 66% coverage)
// ---------------------------------------------------------------------------

func TestRegister_PanicOnEmptyName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on empty algorithm name")
		}
	}()
	Register("", fakeSigner{name: ""}, verifyFake)
}

func TestRegister_PanicOnNilSigner(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil signer")
		}
	}()
	Register("some.alg", nil, verifyFake)
}

func TestRegister_PanicOnNilVerify(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil verify")
		}
	}()
	Register("some.alg2", fakeSigner{name: "some.alg2"}, nil)
}

func TestRegister_PanicOnAlgorithmMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when signer.Algorithm() != name")
		}
	}()
	// fakeSigner{name: "x"}.Algorithm() returns "x", but we register as "y".
	Register("y", fakeSigner{name: "x"}, verifyFake)
}

// ---------------------------------------------------------------------------
// ed25519Signer.Algorithm() — currently 0% (direct call on concrete type)
// ---------------------------------------------------------------------------

func TestEd25519Signer_Algorithm(t *testing.T) {
	s := ed25519Signer{}
	if got := s.Algorithm(); got != AlgorithmEd25519 {
		t.Errorf("ed25519Signer.Algorithm() = %q; want %q", got, AlgorithmEd25519)
	}
}

// ---------------------------------------------------------------------------
// writeNumber — currently 0% (only reached if Encode sees a float64 that
// survived UseNumber re-parse, i.e. a Go float64 passed directly to Encode)
// ---------------------------------------------------------------------------

func TestEncode_Float64GoesToWriteNumber(t *testing.T) {
	// Passing a Go struct with a float64 field goes through marshalNoHTMLEscape
	// as a float64, then re-parsed as json.Number by UseNumber, so the
	// json.Number branch fires.  To reach the writeNumber (float64) branch we
	// need a type that json.NewDecoder can only produce as float64 — that
	// doesn't happen with UseNumber.  The float64 branch in writeCanonical
	// acts as a safety net for callers that feed a pre-decoded any value.
	// We exercise it by directly calling Encode on a value produced through
	// an intermediate json.Unmarshal without UseNumber.
	raw := `{"score":3.14}`
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// m["score"] is float64 here; Encode's writeCanonical must handle it.
	got, err := Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"score":3.14}`
	if string(got) != want {
		t.Errorf("Encode float64 = %q; want %q", got, want)
	}
}

func TestEncode_Float64ZeroIsValidNumber(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(`{"x":0.0}`), &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// json.Marshal(0.0) → "0" in Go's encoder
	if len(got) == 0 {
		t.Error("Encode returned empty output for {x:0.0}")
	}
}

// ---------------------------------------------------------------------------
// With() error path — unregistered algorithm
// ---------------------------------------------------------------------------

func TestWith_RejectsUnregisteredAlgorithm(t *testing.T) {
	_, err := With("totally.unknown.v99", []byte("payload"))
	if err == nil {
		t.Error("With: expected error for unregistered algorithm")
	}
}

// ---------------------------------------------------------------------------
// EncodeManifest/EncodeEnvelope nil guards
// ---------------------------------------------------------------------------

func TestEncodeManifest_RejectsNil(t *testing.T) {
	if _, err := EncodeManifest(nil); err == nil {
		t.Error("EncodeManifest(nil) returned nil error")
	}
}

func TestEncodeEnvelope_RejectsNil(t *testing.T) {
	if _, err := EncodeEnvelope(nil); err == nil {
		t.Error("EncodeEnvelope(nil) returned nil error")
	}
}
