package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// AlgorithmEd25519 is the only signature algorithm this CLI currently
// emits or accepts. Recorded on every Signature so a future verifier
// can detect a payload signed under a different scheme.
const AlgorithmEd25519 = "ed25519"

// Signature is the on-the-wire shape of an Ed25519 signature: an
// algorithm identifier, the 32-byte public verification key, and the
// 64-byte signature value. Bytes are raw; envelopes encode them as
// base64 via JSON marshaling.
type Signature struct {
	Algorithm string
	PublicKey []byte
	Value     []byte
}

// Sign generates a fresh Ed25519 keypair, signs payload, zeros the
// private key, and returns the signature with its public verification
// key. The private key never leaves this function.
//
// Per-call keypair generation is intentional. A process that signs N
// envelopes generates N keypairs, so an attacker who compromises the
// running process can only forge envelopes whose private keys are
// alive in memory during the compromise window — they cannot forge
// envelopes signed earlier or later.
func Sign(payload []byte) (Signature, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Signature{}, fmt.Errorf("sign: generate keypair: %w", err)
	}
	value := ed25519.Sign(priv, payload)
	for i := range priv {
		priv[i] = 0
	}
	return Signature{
		Algorithm: AlgorithmEd25519,
		PublicKey: pub,
		Value:     value,
	}, nil
}

// Verify checks signature against payload using the embedded public
// key. Returns nil on valid, a non-nil error on any failure mode
// (wrong algorithm, malformed key/value lengths, or cryptographic
// mismatch).
//
// Verification answers "this payload was signed by whoever holds this
// key", not "this key is authorized". The caller is responsible for
// any trust-establishment beyond that.
func Verify(payload []byte, sig Signature) error {
	if sig.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("sign: unsupported algorithm %q", sig.Algorithm)
	}
	if len(sig.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("sign: public key length = %d; want %d", len(sig.PublicKey), ed25519.PublicKeySize)
	}
	if len(sig.Value) != ed25519.SignatureSize {
		return fmt.Errorf("sign: signature length = %d; want %d", len(sig.Value), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(sig.PublicKey), payload, sig.Value) {
		return errors.New("sign: signature does not verify")
	}
	return nil
}
