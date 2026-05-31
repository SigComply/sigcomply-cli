package sign

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// fakeSigner is a trivial deterministic algorithm used only to prove
// the registry seam: a new algorithm can be registered, signed with,
// and verified — without changing Sign/Verify callers or the wire
// shape. It is NOT cryptographically meaningful.
type fakeSigner struct{ name string }

func (f fakeSigner) Algorithm() string { return f.name }

func (f fakeSigner) Sign(payload []byte) (Signature, error) {
	sum := sha256.Sum256(payload)
	return Signature{Algorithm: f.name, PublicKey: []byte("fake-pub"), Value: sum[:]}, nil
}

func verifyFake(payload, _ /*publicKey*/, value []byte) error {
	sum := sha256.Sum256(payload)
	if !bytes.Equal(value, sum[:]) {
		return errSig
	}
	return nil
}

type sigErr struct{}

func (sigErr) Error() string { return "fake: signature does not verify" }

var errSig = sigErr{}

func TestRegistry_CustomAlgorithmRoundTrips(t *testing.T) {
	const alg = "test.fake.v1"
	Register(alg, fakeSigner{name: alg}, verifyFake)

	payload := []byte(`{"evidence":"x"}`)
	sig, err := With(alg, payload)
	if err != nil {
		t.Fatalf("With(%s): %v", alg, err)
	}
	if sig.Algorithm != alg {
		t.Errorf("Algorithm = %q; want %q", sig.Algorithm, alg)
	}
	// Verify dispatches on sig.Algorithm to the registered VerifyFunc —
	// the whole point: callers never name the algorithm.
	if err := Verify(payload, sig); err != nil {
		t.Errorf("Verify custom-algorithm signature: %v", err)
	}
	if err := Verify([]byte("tampered"), sig); err == nil {
		t.Error("expected verify to fail on tampered payload for custom algorithm")
	}
}

func TestRegistry_DefaultIsEd25519(t *testing.T) {
	if got := Algorithms(); len(got) == 0 {
		t.Fatal("expected at least the built-in ed25519 algorithm registered")
	}
	sig, err := Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Algorithm != AlgorithmEd25519 {
		t.Errorf("default Sign algorithm = %q; want %q", sig.Algorithm, AlgorithmEd25519)
	}
}

func TestRegistry_SetDefaultAlgorithm(t *testing.T) {
	const alg = "test.default.v1"
	Register(alg, fakeSigner{name: alg}, verifyFake)

	// Switching the default makes Sign() use it without any caller change
	// (the FIPS-build / customer-policy use case). Restore afterward so
	// other tests keep the ed25519 default.
	if err := SetDefaultAlgorithm(alg); err != nil {
		t.Fatalf("SetDefaultAlgorithm(%s): %v", alg, err)
	}
	t.Cleanup(func() {
		if err := SetDefaultAlgorithm(AlgorithmEd25519); err != nil {
			t.Errorf("restore default algorithm: %v", err)
		}
	})

	sig, err := Sign([]byte("y"))
	if err != nil {
		t.Fatalf("Sign after default switch: %v", err)
	}
	if sig.Algorithm != alg {
		t.Errorf("Sign algorithm = %q; want %q after SetDefaultAlgorithm", sig.Algorithm, alg)
	}

	if err := SetDefaultAlgorithm("does.not.exist"); err == nil {
		t.Error("expected SetDefaultAlgorithm to reject an unregistered algorithm")
	}
}
