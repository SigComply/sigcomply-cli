package spec

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// frameworkSchemaVersion is the only schema_version this loader
// accepts.
const frameworkSchemaVersion = "framework.v1"

// FrameworkSpec is the loaded representation of a framework.yaml file.
// It satisfies core.Framework so callers may register the value
// directly with the framework registry.
//
// A framework.yaml carries the framework's identity, the catalog of
// controls it certifies against, and the list of policy IDs that
// contribute evaluations. Policy specs themselves live in separate
// files (one directory per policy, per docs/architecture/03-policy-
// spec.md) — the framework spec only references them by ID.
type FrameworkSpec struct {
	SchemaVersion string          `yaml:"schema_version"`
	IDValue       string          `yaml:"id"`
	VersionValue  string          `yaml:"version"`
	DisplayName   string          `yaml:"display_name"`
	Description   string          `yaml:"description"`
	ControlsList  []ControlSpec   `yaml:"controls"`
	PoliciesList  []PolicyRefSpec `yaml:"policies"`
}

// ControlSpec mirrors core.Control for YAML decoding.
type ControlSpec struct {
	ID               string        `yaml:"id"`
	Name             string        `yaml:"name"`
	Description      string        `yaml:"description"`
	Category         string        `yaml:"category"`
	BaselineSeverity core.Severity `yaml:"baseline_severity"`
}

// PolicyRefSpec is one entry in the framework's policies list — a
// reference to a policy by ID. The actual policy.yaml lives elsewhere.
type PolicyRefSpec struct {
	ID string `yaml:"id"`
}

// ID implements core.Framework.
func (f *FrameworkSpec) ID() string { return f.IDValue }

// Version implements core.Framework.
func (f *FrameworkSpec) Version() string { return f.VersionValue }

// Controls implements core.Framework.
func (f *FrameworkSpec) Controls() []core.Control {
	out := make([]core.Control, len(f.ControlsList))
	for i, c := range f.ControlsList {
		out[i] = core.Control{
			ID:               c.ID,
			Name:             c.Name,
			Description:      c.Description,
			Category:         c.Category,
			BaselineSeverity: c.BaselineSeverity,
		}
	}
	return out
}

// Policies implements core.Framework.
func (f *FrameworkSpec) Policies() []core.PolicyRef {
	out := make([]core.PolicyRef, len(f.PoliciesList))
	for i, p := range f.PoliciesList {
		out[i] = core.PolicyRef{PolicyID: p.ID}
	}
	return out
}

// LoadFramework parses a framework.yaml document. The returned value
// satisfies core.Framework and may be registered directly.
func LoadFramework(data []byte) (*FrameworkSpec, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("framework spec: empty input")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var f FrameworkSpec
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("framework spec: parse: %w", err)
	}
	if err := validateFramework(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

func validateFramework(f *FrameworkSpec) error {
	if err := expectSchemaVersion(f.SchemaVersion, frameworkSchemaVersion, "framework spec"); err != nil {
		return err
	}
	if f.IDValue == "" {
		return fmt.Errorf("framework spec: missing required field \"id\"")
	}
	if f.VersionValue == "" {
		return fmt.Errorf("framework spec %q: missing required field \"version\"", f.IDValue)
	}
	if len(f.ControlsList) == 0 {
		return fmt.Errorf("framework spec %q: \"controls\" must list at least one control", f.IDValue)
	}
	seenControl := make(map[string]struct{}, len(f.ControlsList))
	for i, c := range f.ControlsList {
		if c.ID == "" {
			return fmt.Errorf("framework spec %q: controls[%d] missing required field \"id\"", f.IDValue, i)
		}
		if c.Name == "" {
			return fmt.Errorf("framework spec %q: controls[%d] (%q) missing required field \"name\"", f.IDValue, i, c.ID)
		}
		if _, dup := seenControl[c.ID]; dup {
			return fmt.Errorf("framework spec %q: duplicate control id %q", f.IDValue, c.ID)
		}
		seenControl[c.ID] = struct{}{}
		if c.BaselineSeverity != "" && !isValidSeverity(c.BaselineSeverity) {
			return fmt.Errorf("framework spec %q: controls[%d] (%q): invalid baseline_severity %q", f.IDValue, i, c.ID, c.BaselineSeverity)
		}
	}
	seenPolicy := make(map[string]struct{}, len(f.PoliciesList))
	for i, p := range f.PoliciesList {
		if p.ID == "" {
			return fmt.Errorf("framework spec %q: policies[%d] missing required field \"id\"", f.IDValue, i)
		}
		if _, dup := seenPolicy[p.ID]; dup {
			return fmt.Errorf("framework spec %q: duplicate policy id %q", f.IDValue, p.ID)
		}
		seenPolicy[p.ID] = struct{}{}
	}
	return nil
}

func isValidSeverity(s core.Severity) bool {
	switch s {
	case core.SeverityInfo, core.SeverityLow, core.SeverityMedium, core.SeverityHigh, core.SeverityCritical:
		return true
	}
	return false
}
