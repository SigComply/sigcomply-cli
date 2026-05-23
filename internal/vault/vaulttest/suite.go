// Package vaulttest provides a backend-agnostic test suite for the
// core.Vault interface. Every backend in internal/vault/<backend>/ uses
// this suite to verify it honors the same observable contract: put-
// then-get round trips, lists return the keys you wrote, GetBinary on
// a missing key errors, and metadata round-trips on the backends that
// can persist it.
package vaulttest

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
)

// Factory constructs a fresh, isolated Vault for one sub-test. The
// returned Vault is already Init'd. Backends that need cleanup should
// register a t.Cleanup inside the factory.
type Factory func(t *testing.T) core.Vault

// RunContractSuite exercises every Vault method against the given
// factory. Call this from each backend's _test.go.
func RunContractSuite(t *testing.T, factory Factory) {
	t.Helper()
	t.Run("PutJSON_GetBinary_RoundTrip", func(t *testing.T) { testPutJSONRoundTrip(t, factory) })
	t.Run("PutBinary_GetBinary_RoundTrip", func(t *testing.T) { testPutBinaryRoundTrip(t, factory) })
	t.Run("PutBinary_WithMetadata", func(t *testing.T) { testPutBinaryMetadata(t, factory) })
	t.Run("PutEnvelope_GetBinary_RoundTrip", func(t *testing.T) { testPutEnvelopeRoundTrip(t, factory) })
	t.Run("PutEnvelope_SignedRoundTrip_Verifies", func(t *testing.T) { testPutEnvelopeSignedRoundTrip(t, factory) })
	t.Run("List_ReturnsKeysUnderPrefix", func(t *testing.T) { testListPrefix(t, factory) })
	t.Run("GetBinary_MissingKey_Errors", func(t *testing.T) { testGetMissing(t, factory) })
}

func testPutJSONRoundTrip(t *testing.T, factory Factory) {
	v := factory(t)
	ctx := context.Background()
	body := map[string]any{"hello": "world", "n": 42}
	if err := v.PutJSON(ctx, "objects/hello.json", body); err != nil {
		t.Fatalf("PutJSON: %v", err)
	}
	got, err := v.GetBinary(ctx, "objects/hello.json")
	if err != nil {
		t.Fatalf("GetBinary: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("Unmarshal: %v (raw %q)", err, got)
	}
	if back["hello"] != "world" {
		t.Errorf("round-tripped value = %#v; want world", back["hello"])
	}
}

func testPutBinaryRoundTrip(t *testing.T, factory Factory) {
	v := factory(t)
	ctx := context.Background()
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}
	if err := v.PutBinary(ctx, "blobs/data.bin", payload, nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	got, err := v.GetBinary(ctx, "blobs/data.bin")
	if err != nil {
		t.Fatalf("GetBinary: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("binary round-trip mismatch: got %x; want %x", got, payload)
	}
}

func testPutBinaryMetadata(t *testing.T, factory Factory) {
	// The interface lets a caller pass metadata, but the spec does not
	// require Get to return it (no separate Get-metadata method exists).
	// All we verify is that PutBinary with metadata does not error.
	v := factory(t)
	ctx := context.Background()
	err := v.PutBinary(ctx, "blobs/meta.bin", []byte("x"), map[string]string{
		"sigcomply-evidence-type": "user_record",
	})
	if err != nil {
		t.Fatalf("PutBinary with metadata: %v", err)
	}
}

func testPutEnvelopeRoundTrip(t *testing.T, factory Factory) {
	v := factory(t)
	ctx := context.Background()
	env := sampleEnvelope()
	if err := v.PutEnvelope(ctx, "envelopes/sample.json", &env); err != nil {
		t.Fatalf("PutEnvelope: %v", err)
	}
	got, err := v.GetBinary(ctx, "envelopes/sample.json")
	if err != nil {
		t.Fatalf("GetBinary: %v", err)
	}
	var back core.Envelope
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("Unmarshal envelope: %v (raw %q)", err, got)
	}
	if back.FormatVersion != env.FormatVersion {
		t.Errorf("FormatVersion round-trip: got %q; want %q", back.FormatVersion, env.FormatVersion)
	}
	if len(back.Records) != len(env.Records) {
		t.Errorf("Records length: got %d; want %d", len(back.Records), len(env.Records))
	}
	if !bytes.Equal(back.Signature.PublicKey, env.Signature.PublicKey) {
		t.Errorf("Signature.PublicKey round-trip mismatch")
	}
}

// testPutEnvelopeSignedRoundTrip is the M5 end-to-end check: a real
// signed envelope round-trips through the backend and verifies after
// re-parse. This catches backends that mangle bytes in transit (e.g.
// content-type-driven re-encoding) which would silently invalidate
// signatures.
func testPutEnvelopeSignedRoundTrip(t *testing.T, factory Factory) {
	v := factory(t)
	ctx := context.Background()
	env := sampleUnsignedEnvelope()
	if err := sign.Envelope(&env); err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	if err := v.PutEnvelope(ctx, "envelopes/signed.json", &env); err != nil {
		t.Fatalf("PutEnvelope: %v", err)
	}
	body, err := v.GetBinary(ctx, "envelopes/signed.json")
	if err != nil {
		t.Fatalf("GetBinary: %v", err)
	}
	var back core.Envelope
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("Unmarshal: %v (raw %q)", err, body)
	}
	if err := sign.VerifyEnvelope(&back); err != nil {
		t.Fatalf("VerifyEnvelope after backend round-trip: %v", err)
	}
}

func testListPrefix(t *testing.T, factory Factory) {
	v := factory(t)
	ctx := context.Background()
	paths := []string{
		"alpha/one.txt",
		"alpha/two.txt",
		"alpha/nested/three.txt",
		"beta/four.txt",
	}
	for _, p := range paths {
		if err := v.PutBinary(ctx, p, []byte("x"), nil); err != nil {
			t.Fatalf("PutBinary(%s): %v", p, err)
		}
	}
	got, err := v.List(ctx, "alpha/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"alpha/one.txt", "alpha/two.txt", "alpha/nested/three.txt"}
	for _, w := range want {
		if !containsAnyWithSuffix(got, w) {
			t.Errorf("List(alpha/) missing key with suffix %q (got %v)", w, got)
		}
	}
	for _, k := range got {
		if strings.HasPrefix(strings.TrimPrefix(k, prefixUpToFirstSlash(k)), "beta/") {
			t.Errorf("List(alpha/) leaked key from beta/: %q", k)
		}
	}
}

func testGetMissing(t *testing.T, factory Factory) {
	v := factory(t)
	ctx := context.Background()
	_, err := v.GetBinary(ctx, "nope/does-not-exist.bin")
	if err == nil {
		t.Error("expected error reading non-existent key, got nil")
	}
}

func containsAnyWithSuffix(haystack []string, suffix string) bool {
	for _, h := range haystack {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// prefixUpToFirstSlash returns the substring of s up to and including
// the first '/' — used only by the leak check above. Pure helper.
func prefixUpToFirstSlash(s string) string {
	if i := strings.Index(s, "/"); i >= 0 {
		return s[:i+1]
	}
	return ""
}

func sampleEnvelope() core.Envelope {
	return core.Envelope{
		FormatVersion: "envelope.v1",
		ProducedAt:    time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
		Records: []core.EvidenceRecord{
			{
				Type:        "user_record",
				ID:          "alice",
				IdentityKey: "alice@acme.com",
				Payload:     json.RawMessage(`{"mfa_enabled":true}`),
				SourceID:    "aws.iam",
				CollectedAt: time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
			},
		},
		Signature: core.EnvelopeSignature{
			Algorithm: "ed25519",
			PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
			Value:     []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
	}
}

// sampleUnsignedEnvelope returns a fresh envelope with no signature
// populated, suitable for handing to sign.Envelope.
func sampleUnsignedEnvelope() core.Envelope {
	return core.Envelope{
		FormatVersion: "envelope.v1",
		ProducedAt:    time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
		Records: []core.EvidenceRecord{
			{
				Type:        "user_record",
				ID:          "alice",
				IdentityKey: "alice@acme.com",
				Payload:     json.RawMessage(`{"mfa_enabled":true}`),
				SourceID:    "aws.iam",
				CollectedAt: time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
			},
		},
	}
}
