//go:build e2e

// Package collectors provides evidence collection adapters and a registry for E2E tests.
package collectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/test/e2e/config"
)

// Collector defines the interface for E2E evidence collection adapters.
type Collector interface {
	// Provider returns the provider name (e.g. "aws", "github").
	Provider() string

	// Init initializes the collector with credentials.
	Init(ctx context.Context, t *testing.T, creds *config.ResolvedCredentials) error

	// Collect gathers evidence, optionally filtered by services.
	// If services is nil, all services are collected.
	Collect(ctx context.Context, t *testing.T, services []string) (*CollectorResult, error)
}

// CollectorResult holds evidence and errors from collection.
type CollectorResult struct {
	Evidence []evidence.Evidence
	Errors   []CollectorError
}

// HasErrors returns true if there were any collection errors.
func (r *CollectorResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// CollectorError represents an error during collection from a specific service.
type CollectorError struct {
	Service string
	Error   string
}

// CollectorFactory creates a new Collector instance.
type CollectorFactory func() Collector

var (
	registryMu sync.RWMutex
	registry   = make(map[string]CollectorFactory)
)

// Register registers a collector factory for a provider name.
// Typically called from init() in provider-specific files.
func Register(provider string, factory CollectorFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[provider]; exists {
		panic(fmt.Sprintf("collector already registered for provider %q", provider))
	}
	registry[provider] = factory
}

// Get returns a new collector instance for the given provider.
func Get(provider string) (Collector, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	factory, ok := registry[provider]
	if !ok {
		return nil, fmt.Errorf("no collector registered for provider %q", provider)
	}
	return factory(), nil
}

// Has returns true if a collector is registered for the given provider.
func Has(provider string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()

	_, ok := registry[provider]
	return ok
}

// FilterByServices filters evidence by resource type prefix for the given provider and services.
// Evidence resource types follow predictable prefixes: "aws:iam:user", "github:member", etc.
// If services is nil or empty, all evidence is returned (no filtering).
func FilterByServices(provider string, services []string, ev []evidence.Evidence) []evidence.Evidence {
	if len(services) == 0 {
		return ev
	}

	// Build prefix set: e.g. provider="aws", services=["iam"] -> "aws:iam:"
	prefixes := make([]string, len(services))
	for i, svc := range services {
		prefixes[i] = provider + ":" + svc + ":"
	}

	var filtered []evidence.Evidence
	for _, e := range ev {
		for _, prefix := range prefixes {
			if strings.HasPrefix(e.ResourceType, prefix) {
				filtered = append(filtered, e)
				break
			}
		}
	}
	return filtered
}
