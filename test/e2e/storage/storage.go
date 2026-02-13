//go:build e2e

// Package e2estorage provides storage verification adapters for E2E tests.
package e2estorage

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/sigcomply/sigcomply-cli/test/e2e/config"
)

// Verifier defines the interface for storage verification in E2E tests.
type Verifier interface {
	// Backend returns the storage backend name (e.g. "s3", "gcs").
	Backend() string

	// Setup initializes the verifier with resolved storage config.
	Setup(t *testing.T, storage *config.ResolvedStorage, prefix string)

	// Verify checks that expected objects exist in storage.
	Verify(t *testing.T, ctx context.Context)

	// Cleanup removes test artifacts from storage.
	Cleanup(t *testing.T)
}

// VerifierFactory creates a new Verifier instance.
type VerifierFactory func() Verifier

var (
	verifierMu sync.RWMutex
	verifiers  = make(map[string]VerifierFactory)
)

// RegisterVerifier registers a verifier factory for a backend name.
func RegisterVerifier(backend string, factory VerifierFactory) {
	verifierMu.Lock()
	defer verifierMu.Unlock()

	if _, exists := verifiers[backend]; exists {
		panic(fmt.Sprintf("verifier already registered for backend %q", backend))
	}
	verifiers[backend] = factory
}

// GetVerifier returns a new verifier instance for the given backend.
func GetVerifier(backend string) (Verifier, error) {
	verifierMu.RLock()
	defer verifierMu.RUnlock()

	factory, ok := verifiers[backend]
	if !ok {
		return nil, fmt.Errorf("no verifier registered for backend %q", backend)
	}
	return factory(), nil
}

// TestPrefix generates an S3/storage key prefix for E2E tests.
// All scenarios share the same prefix; isolation comes from the run path (framework/date).
func TestPrefix(_ string) string {
	return "e2e/"
}
