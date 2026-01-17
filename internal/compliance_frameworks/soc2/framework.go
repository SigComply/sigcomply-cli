// Package soc2 provides the SOC 2 compliance framework implementation.
package soc2

import (
	_ "embed"

	"github.com/tracevault/tracevault-cli/internal/compliance_frameworks/engine"
)

//go:embed policies/cc6_1_mfa.rego
var cc61MFAPolicy string

//go:embed policies/cc6_2_encryption.rego
var cc62EncryptionPolicy string

//go:embed policies/cc7_1_logging.rego
var cc71LoggingPolicy string

// Framework implements the engine.Framework interface for SOC 2.
type Framework struct{}

// New creates a new SOC 2 framework instance.
func New() *Framework {
	return &Framework{}
}

// Name returns the framework identifier.
func (f *Framework) Name() string {
	return "soc2"
}

// DisplayName returns the human-readable name.
func (f *Framework) DisplayName() string {
	return "SOC 2 Type II"
}

// Version returns the framework version.
func (f *Framework) Version() string {
	return "2017"
}

// Description returns a brief description of the framework.
func (f *Framework) Description() string {
	return "AICPA Trust Services Criteria for SOC 2 Type II compliance"
}

// Controls returns all controls defined in this framework.
func (f *Framework) Controls() []engine.Control {
	soc2Controls := GetControls()
	result := make([]engine.Control, len(soc2Controls))
	for i, c := range soc2Controls {
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
		{Name: "cc6_1_mfa", Source: cc61MFAPolicy},
		{Name: "cc6_2_encryption", Source: cc62EncryptionPolicy},
		{Name: "cc7_1_logging", Source: cc71LoggingPolicy},
	}
}

// Register registers the SOC 2 framework with the default registry.
func Register() error {
	return engine.RegisterFramework(New())
}

// Ensure Framework implements the Framework interface.
var _ engine.Framework = (*Framework)(nil)
