package sign

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func sampleManifest() *core.Manifest {
	return &core.Manifest{
		SchemaVersion: "run.v1",
		RunID:         "a3f8b2c1-9d4e-4b23-8f7a-1e5c2d8a9b0f",
		StartedAt:     time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
		CompletedAt:   time.Date(2026, 5, 23, 14, 1, 42, 0, time.UTC),
		FileHashes: map[string]string{
			"summary.json":     "sha256:7f3a9c8e",
			"diagnostics.json": "sha256:b2e15d4a",
			"policies/p1/envelopes/user_record__iam.json": "sha256:e3b0c442",
		},
	}
}

func TestManifestPopulatesSignature(t *testing.T) {
	m := sampleManifest()
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if m.Signature.Algorithm != AlgorithmEd25519 {
		t.Errorf("Algorithm = %q; want %s", m.Signature.Algorithm, AlgorithmEd25519)
	}
	if len(m.Signature.PublicKey) != 32 || len(m.Signature.Value) != 64 {
		t.Errorf("Signature sizes wrong: key=%d val=%d", len(m.Signature.PublicKey), len(m.Signature.Value))
	}
}

func TestSignVerifyManifestRoundTrip(t *testing.T) {
	m := sampleManifest()
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if err := VerifyManifest(m); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
}

func TestVerifyManifestAfterJSONRoundTrip(t *testing.T) {
	m := sampleManifest()
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	body, err := EncodeManifest(m)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	var back core.Manifest
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := VerifyManifest(&back); err != nil {
		t.Fatalf("VerifyManifest after JSON round-trip: %v", err)
	}
}

func TestVerifyManifestRejectsTamperedHash(t *testing.T) {
	// Flipping a single file_hashes entry must break verification —
	// that's the whole point of the Merkle root signature.
	m := sampleManifest()
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	m.FileHashes["summary.json"] = "sha256:tampered"
	if err := VerifyManifest(m); err == nil {
		t.Error("VerifyManifest accepted tampered FileHashes entry")
	}
}

func TestVerifyManifestRejectsAddedHash(t *testing.T) {
	// Adding a new entry to file_hashes after signing must also
	// fail — an attacker who sneaks in a new file shouldn't be able
	// to make the manifest cover it.
	m := sampleManifest()
	if err := Manifest(m); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	m.FileHashes["new_file.json"] = "sha256:00"
	if err := VerifyManifest(m); err == nil {
		t.Error("VerifyManifest accepted added FileHashes entry")
	}
}

func TestEncodeManifestRequiresSignature(t *testing.T) {
	if _, err := EncodeManifest(sampleManifest()); err == nil {
		t.Error("EncodeManifest accepted unsigned manifest")
	}
}

func TestManifestRejectsNil(t *testing.T) {
	if err := Manifest(nil); err == nil {
		t.Error("Manifest(nil) returned nil error")
	}
}

func TestVerifyManifestRejectsNil(t *testing.T) {
	if err := VerifyManifest(nil); err == nil {
		t.Error("VerifyManifest(nil) returned nil error")
	}
}
