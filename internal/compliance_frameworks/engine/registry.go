// Package engine provides the OPA policy evaluation engine.
package engine

import (
	"fmt"
	"sync"

	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// Framework defines the interface for compliance frameworks.
type Framework interface {
	// Name returns the framework identifier (e.g., "soc2", "hipaa").
	Name() string

	// DisplayName returns the human-readable name.
	DisplayName() string

	// Version returns the framework version.
	Version() string

	// Description returns a brief description of the framework.
	Description() string

	// Controls returns all controls defined in this framework.
	Controls() []Control

	// GetControl returns a specific control by ID, or nil if not found.
	GetControl(id string) *Control

	// Policies returns all Rego policy sources for this framework.
	// Each entry is a map with "name" and "source" keys.
	Policies() []PolicySource
}

// Control represents a compliance control within a framework.
type Control struct {
	ID          string            `json:"id"`          // e.g., "CC6.1"
	Name        string            `json:"name"`        // e.g., "Logical Access Control"
	Description string            `json:"description"` // Full description
	Category    string            `json:"category"`    // e.g., "Security"
	Severity    evidence.Severity `json:"severity"`    // Default severity for this control
}

// PolicySource represents a Rego policy source.
type PolicySource struct {
	Name   string // Policy name (used for error messages)
	Source string // Rego source code
}

// Registry manages registered compliance frameworks.
type Registry struct {
	mu         sync.RWMutex
	frameworks map[string]Framework
}

// NewRegistry creates a new framework registry.
func NewRegistry() *Registry {
	return &Registry{
		frameworks: make(map[string]Framework),
	}
}

// Register adds a framework to the registry.
func (r *Registry) Register(framework Framework) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := framework.Name()
	if _, exists := r.frameworks[name]; exists {
		return fmt.Errorf("framework %s already registered", name)
	}

	r.frameworks[name] = framework
	return nil
}

// Get retrieves a framework by name.
func (r *Registry) Get(name string) (Framework, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	framework, exists := r.frameworks[name]
	if !exists {
		return nil, fmt.Errorf("framework %s not found", name)
	}

	return framework, nil
}

// List returns all registered framework names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.frameworks))
	for name := range r.frameworks {
		names = append(names, name)
	}
	return names
}

// Has checks if a framework is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.frameworks[name]
	return exists
}

// DefaultRegistry is the global registry for frameworks.
var DefaultRegistry = NewRegistry()

// RegisterFramework registers a framework in the default registry.
func RegisterFramework(framework Framework) error {
	return DefaultRegistry.Register(framework)
}

// GetFramework retrieves a framework from the default registry.
func GetFramework(name string) (Framework, error) {
	return DefaultRegistry.Get(name)
}

// ListFrameworks returns all registered framework names from the default registry.
func ListFrameworks() []string {
	return DefaultRegistry.List()
}

// HasFramework checks if a framework is registered in the default registry.
func HasFramework(name string) bool {
	return DefaultRegistry.Has(name)
}
