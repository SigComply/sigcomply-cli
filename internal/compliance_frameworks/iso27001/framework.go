// Package iso27001 provides the ISO 27001 compliance framework implementation.
package iso27001

import (
	_ "embed"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
)

//go:embed policies/a_9_2_1_access.rego
var a921AccessPolicy string

//go:embed policies/a_12_4_1_logging.rego
var a1241LoggingPolicy string

// Framework implements the engine.Framework interface for ISO 27001.
type Framework struct{}

// New creates a new ISO 27001 framework instance.
func New() *Framework {
	return &Framework{}
}

// Name returns the framework identifier.
func (f *Framework) Name() string {
	return "iso27001"
}

// DisplayName returns the human-readable name.
func (f *Framework) DisplayName() string {
	return "ISO 27001:2022"
}

// Version returns the framework version.
func (f *Framework) Version() string {
	return "2022"
}

// Description returns a brief description of the framework.
func (f *Framework) Description() string {
	return "ISO/IEC 27001:2022 Information Security Management System (ISMS)"
}

// Controls returns all controls defined in this framework.
func (f *Framework) Controls() []engine.Control {
	iso27001Controls := GetControls()
	result := make([]engine.Control, len(iso27001Controls))
	for i, c := range iso27001Controls {
		result[i] = engine.Control{
			ID:          c.ID,
			Name:        c.Name,
			Description: c.Description,
			Category:    c.Category,
			Severity:    c.Severity,
		}
	}
	return result
}

// GetControl returns a specific control by ID.
func (f *Framework) GetControl(id string) *engine.Control {
	c := GetControl(id)
	if c == nil {
		return nil
	}
	return &engine.Control{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		Category:    c.Category,
		Severity:    c.Severity,
	}
}

// Policies returns all Rego policy sources for this framework.
func (f *Framework) Policies() []engine.PolicySource {
	return []engine.PolicySource{
		{Name: "a_9_2_1_access", Source: a921AccessPolicy},
		{Name: "a_12_4_1_logging", Source: a1241LoggingPolicy},
	}
}

// Register registers the ISO 27001 framework with the default registry.
func Register() error {
	return engine.RegisterFramework(New())
}

// Ensure Framework implements the Framework interface.
var _ engine.Framework = (*Framework)(nil)
