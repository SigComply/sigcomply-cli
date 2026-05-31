package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// AlgorithmEd25519 is the built-in default signature algorithm. Its
// name travels in Signature.Algorithm (and thus in every envelope and
// manifest), so a verifier selects the right implementation from the
// signed artifact alone — adding a new algorithm never changes the
// wire format.
const AlgorithmEd25519 = "ed25519"

// Signature is the on-the-wire shape of a signature: an algorithm
// identifier, the public verification key, and the signature value.
// Bytes are raw; envelopes/manifests encode them as base64 via JSON
// marshaling. The shape is algorithm-agnostic — Ed25519, ECDSA, RSA,
// an HSM/KMS-backed signer, or a post-quantum scheme all populate the
// same three fields.
type Signature struct {
	Algorithm string
	PublicKey []byte
	Value     []byte
}

// Signer produces a Signature over a payload using one algorithm.
//
// The per-file ephemeral-keypair discipline (CLAUDE.md Invariant #3) is
// a property of the built-in ed25519Signer, NOT a requirement of this
// interface: an HSM/KMS-backed signer legitimately holds a long-lived
// key whose private half never leaves the device. What every Signer
// must guarantee is that the returned Signature carries enough to
// verify offline — for asymmetric schemes that means the public key in
// Signature.PublicKey; a future KMS signer that verifies by key
// reference would register a matching VerifyFunc.
type Signer interface {
	// Algorithm is the identifier stamped into Signature.Algorithm and
	// used by Verify to dispatch to the matching VerifyFunc.
	Algorithm() string
	// Sign returns a Signature over payload.
	Sign(payload []byte) (Signature, error)
}

// VerifyFunc checks a signature's raw public key + value against a
// payload for one algorithm. Registered alongside a Signer so Verify
// can dispatch on Signature.Algorithm.
type VerifyFunc func(payload, publicKey, value []byte) error

// algorithmEntry pairs a registered Signer with its VerifyFunc.
type algorithmEntry struct {
	signer Signer
	verify VerifyFunc
}

var (
	mu sync.RWMutex
	// algorithms is the registry of signing/verification implementations
	// keyed by algorithm name. Built-in ed25519 is registered eagerly
	// (no init() — the package's lint profile forbids it). Additional
	// algorithms (ECDSA/RSA for a FIPS build profile, an HSM/KMS-backed
	// signer, or a post-quantum scheme) register via Register, including
	// project-local ones compiled in by `sigcomply build`.
	algorithms = map[string]algorithmEntry{
		AlgorithmEd25519: {signer: ed25519Signer{}, verify: verifyEd25519},
	}
	// defaultAlgorithm is what Sign uses when no algorithm is specified.
	// Ed25519 by default; a FIPS build or a customer policy can switch
	// it via SetDefaultAlgorithm without touching callers.
	defaultAlgorithm = AlgorithmEd25519
)

// Register adds or replaces the Signer + VerifyFunc for an algorithm
// name. Intended for eager package-level registration by built-in
// algorithms and for project-local or HSM/KMS-backed signers compiled
// in via `sigcomply build`. Panics on an empty name or nil
// signer/verify — a misconfigured signer must fail loudly at startup,
// never silently produce unverifiable evidence.
//
// The registry is the sole coupling point between "how we sign" and
// "what we sign": Envelope/Manifest call Sign/Verify and never name an
// algorithm, mirroring how the source/vault/framework registries
// decouple policies from plugins.
func Register(name string, signer Signer, verify VerifyFunc) {
	if name == "" {
		panic("sign: Register: empty algorithm name")
	}
	if signer == nil || verify == nil {
		panic("sign: Register: nil signer or verify for " + name)
	}
	if signer.Algorithm() != name {
		panic(fmt.Sprintf("sign: Register: signer.Algorithm()=%q does not match name %q", signer.Algorithm(), name))
	}
	mu.Lock()
	defer mu.Unlock()
	algorithms[name] = algorithmEntry{signer: signer, verify: verify}
}

// SetDefaultAlgorithm changes the algorithm Sign uses. Returns an error
// if the algorithm is not registered. Used by a FIPS build profile or a
// project policy to make, e.g., ECDSA-P256 the default signer without
// changing any calling code.
func SetDefaultAlgorithm(name string) error {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := algorithms[name]; !ok {
		return fmt.Errorf("sign: unknown algorithm %q (registered: %v)", name, registeredNamesLocked())
	}
	defaultAlgorithm = name
	return nil
}

// Algorithms returns the sorted list of registered algorithm names.
func Algorithms() []string {
	mu.RLock()
	defer mu.RUnlock()
	return registeredNamesLocked()
}

func registeredNamesLocked() []string {
	out := make([]string, 0, len(algorithms))
	for name := range algorithms {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Sign signs payload with the default algorithm's Signer.
func Sign(payload []byte) (Signature, error) {
	mu.RLock()
	name := defaultAlgorithm
	entry, ok := algorithms[name]
	mu.RUnlock()
	if !ok {
		return Signature{}, fmt.Errorf("sign: default algorithm %q not registered", name)
	}
	return entry.signer.Sign(payload)
}

// With signs payload using the named algorithm's Signer. Returns an
// error if the algorithm is not registered. Named With (not SignWith)
// so callers read sign.With(alg, payload) without stutter.
func With(algorithm string, payload []byte) (Signature, error) {
	mu.RLock()
	entry, ok := algorithms[algorithm]
	mu.RUnlock()
	if !ok {
		return Signature{}, fmt.Errorf("sign: unknown algorithm %q", algorithm)
	}
	return entry.signer.Sign(payload)
}

// Verify checks signature against payload by dispatching on
// sig.Algorithm to the registered VerifyFunc. Returns a non-nil error
// on any failure mode (unregistered algorithm, malformed key/value, or
// cryptographic mismatch).
//
// Verification answers "this payload was signed by whoever holds this
// key", not "this key is authorized". The caller is responsible for any
// trust-establishment beyond that.
func Verify(payload []byte, sig Signature) error {
	mu.RLock()
	entry, ok := algorithms[sig.Algorithm]
	mu.RUnlock()
	if !ok {
		return fmt.Errorf("sign: unsupported algorithm %q", sig.Algorithm)
	}
	return entry.verify(payload, sig.PublicKey, sig.Value)
}

// --- built-in Ed25519 algorithm -------------------------------------

// ed25519Signer is the shipped default. Each Sign generates a fresh
// keypair, signs, and zeros the private key before returning.
//
// Per-call keypair generation is intentional. A process that signs N
// envelopes generates N keypairs, so an attacker who compromises the
// running process can only forge envelopes whose private keys are alive
// in memory during the compromise window — they cannot forge envelopes
// signed earlier or later.
type ed25519Signer struct{}

func (ed25519Signer) Algorithm() string { return AlgorithmEd25519 }

func (ed25519Signer) Sign(payload []byte) (Signature, error) {
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

func verifyEd25519(payload, publicKey, value []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("sign: public key length = %d; want %d", len(publicKey), ed25519.PublicKeySize)
	}
	if len(value) != ed25519.SignatureSize {
		return fmt.Errorf("sign: signature length = %d; want %d", len(value), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, value) {
		return errors.New("sign: signature does not verify")
	}
	return nil
}
