// Package soc2 provides the SOC 2 compliance framework implementation.
package soc2

import (
	"embed"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/core/manual"
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
	// Two-pass approach: first collect all .rego file paths, then filter.
	// A file ending in _test.rego is only a test file if a corresponding
	// policy file exists (e.g., skip foo_test.rego only if foo.rego exists).
	// This avoids incorrectly filtering policies whose names contain "test"
	// (e.g., cc7_2_incident_response_test.rego).
	var allPaths []string
	allFiles := make(map[string]bool) // set of all .rego base names

	if walkErr := fs.WalkDir(policiesFS, "policies", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return err
		}
		allPaths = append(allPaths, path)
		allFiles[filepath.Base(path)] = true
		return nil
	}); walkErr != nil {
		return nil
	}

	var policies []engine.PolicySource
	for _, path := range allPaths {
		base := filepath.Base(path)
		// A _test.rego file is a test file only if its corresponding policy
		// file exists (e.g., skip foo_test.rego if foo.rego is present).
		// This avoids filtering out policies whose names contain "test"
		// (e.g., cc7_2_incident_response_test.rego).
		if strings.HasSuffix(base, "_test.rego") {
			nonTestBase := strings.TrimSuffix(base, "_test.rego") + ".rego"
			if allFiles[nonTestBase] {
				continue
			}
		}
		data, err := policiesFS.ReadFile(path)
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(base, ".rego")
		policies = append(policies, engine.PolicySource{
			Name:   name,
			Source: string(data),
		})
	}
	return policies
}

// Register registers the SOC 2 framework with the default registry.
func Register() error {
	return engine.RegisterFramework(New())
}

// ManualCatalog returns the manual evidence catalog for SOC 2.
func (f *Framework) ManualCatalog() (*manual.Catalog, error) {
	return manual.LoadCatalog("soc2")
}

// Ensure Framework implements the Framework interface.
var _ engine.Framework = (*Framework)(nil)

// Ensure Framework implements ManualEvidenceProvider.
var _ engine.ManualEvidenceProvider = (*Framework)(nil)
