package sign

import (
	"bytes"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	payload := []byte("hello world")
	sig, err := Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	sig, err := Sign([]byte("hello world"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify([]byte("hello WORLD"), sig); err == nil {
		t.Error("Verify accepted tampered payload")
	}
}

func TestVerifyRejectsTamperedSignatureValue(t *testing.T) {
	payload := []byte("hello world")
	sig, err := Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig.Value[0] ^= 0xFF
	if err := Verify(payload, sig); err == nil {
		t.Error("Verify accepted tampered signature value")
	}
}

func TestSignProducesFreshKeypair(t *testing.T) {
	// The per-file ephemeral-keypair invariant means consecutive
	// Sign() calls — even with identical payloads — must produce
	// distinct public keys.
	a, err := Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign a: %v", err)
	}
	b, err := Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign b: %v", err)
	}
	if bytes.Equal(a.PublicKey, b.PublicKey) {
		t.Error("two consecutive Sign() calls produced the same public key — keypair is not ephemeral")
	}
}

func TestVerifyRejectsWrongAlgorithm(t *testing.T) {
	sig, err := Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig.Algorithm = "rsa"
	if err := Verify([]byte("x"), sig); err == nil {
		t.Error("Verify accepted unknown algorithm")
	}
}

func TestVerifyRejectsTruncatedKey(t *testing.T) {
	sig, err := Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig.PublicKey = sig.PublicKey[:16]
	if err := Verify([]byte("x"), sig); err == nil {
		t.Error("Verify accepted truncated public key")
	}
}

func TestVerifyRejectsTruncatedSignature(t *testing.T) {
	sig, err := Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig.Value = sig.Value[:32]
	if err := Verify([]byte("x"), sig); err == nil {
		t.Error("Verify accepted truncated signature value")
	}
}

func TestSignReturnsCorrectAlgorithmAndSizes(t *testing.T) {
	sig, err := Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Algorithm != AlgorithmEd25519 {
		t.Errorf("Algorithm = %q; want %s", sig.Algorithm, AlgorithmEd25519)
	}
	if len(sig.PublicKey) != 32 {
		t.Errorf("PublicKey size = %d; want 32", len(sig.PublicKey))
	}
	if len(sig.Value) != 64 {
		t.Errorf("Value size = %d; want 64", len(sig.Value))
	}
}
