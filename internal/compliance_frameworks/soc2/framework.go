// Package soc2 provides the SOC 2 compliance framework implementation.
package soc2

import (
	"embed"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
)

//go:embed policies/*/*.rego
var policiesFS embed.FS

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
	var policies []engine.PolicySource
	if err := fs.WalkDir(policiesFS, "policies", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(path, "_test.rego") {
			return nil
		}
		if !strings.HasSuffix(path, ".rego") {
			return nil
		}
		data, err := policiesFS.ReadFile(path)
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(filepath.Base(path), ".rego")
		policies = append(policies, engine.PolicySource{
			Name:   name,
			Source: string(data),
		})
		return nil
	}); err != nil {
		return nil
	}
	return policies
}

// Register registers the SOC 2 framework with the default registry.
func Register() error {
	return engine.RegisterFramework(New())
}

// Ensure Framework implements the Framework interface.
var _ engine.Framework = (*Framework)(nil)
