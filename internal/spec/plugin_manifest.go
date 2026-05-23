package spec

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// pluginManifestSchemaVersion is the only schema_version this loader
// accepts. A future plugin.v2 would need a parallel loader (or a
// version-dispatch wrapper).
const pluginManifestSchemaVersion = "plugin.v1"

// PluginManifest is the in-memory shape of a plugin's plugin.yaml. It
// declares the plugin's identity, the evidence types it emits, and the
// config_schema customers fill in under sources.<id> in
// .sigcomply.yaml. See docs/architecture/04-source-plugins.md.
//
// There is no L1 core type for plugin manifests — they are metadata
// the planner (L3) reads to validate project config and build
// SlotRequest values; nothing flows from a manifest into the evidence
// or aggregation paths.
type PluginManifest struct {
	SchemaVersion       string                        `yaml:"schema_version"`
	ID                  string                        `yaml:"id"`
	DisplayName         string                        `yaml:"display_name"`
	Version             string                        `yaml:"version"`
	Description         string                        `yaml:"description"`
	Emits               []string                      `yaml:"emits"`
	Singleton           bool                          `yaml:"singleton"`
	ConfigSchema        map[string]PluginConfigField  `yaml:"config_schema"`
	RequiresCredentials []PluginCredentialRequirement `yaml:"requires_credentials"`
}

// PluginConfigField describes one knob in the plugin's config_schema.
// Default is left as `any` because the static type is named by the
// Type field (`string`, `int`, `bool`, etc.).
type PluginConfigField struct {
	Type        string `yaml:"type"`
	Required    bool   `yaml:"required"`
	Default     any    `yaml:"default"`
	Enum        []any  `yaml:"enum"`
	Description string `yaml:"description"`
}

// PluginCredentialRequirement declares one credential the plugin needs.
// `Source` names the mechanism (e.g. env_or_default_chain, env, file).
type PluginCredentialRequirement struct {
	Source string `yaml:"source"`
	EnvVar string `yaml:"env_var,omitempty"`
}

// LoadPluginManifest parses a plugin manifest YAML document. Unknown
// fields are rejected (typo-safety); refer to the comment-doc on the
// PluginManifest struct for the field set.
func LoadPluginManifest(data []byte) (PluginManifest, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return PluginManifest{}, fmt.Errorf("plugin manifest: empty input")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var m PluginManifest
	if err := dec.Decode(&m); err != nil {
		return PluginManifest{}, fmt.Errorf("plugin manifest: parse: %w", err)
	}
	if err := validatePluginManifest(&m); err != nil {
		return PluginManifest{}, err
	}
	return m, nil
}

func validatePluginManifest(m *PluginManifest) error {
	if err := expectSchemaVersion(m.SchemaVersion, pluginManifestSchemaVersion, "plugin manifest"); err != nil {
		return err
	}
	if m.ID == "" {
		return fmt.Errorf("plugin manifest: missing required field \"id\"")
	}
	if len(m.Emits) == 0 {
		return fmt.Errorf("plugin manifest %q: \"emits\" must list at least one evidence type", m.ID)
	}
	for i, e := range m.Emits {
		if e == "" {
			return fmt.Errorf("plugin manifest %q: emits[%d] is empty", m.ID, i)
		}
	}
	for name, field := range m.ConfigSchema {
		if field.Type == "" {
			return fmt.Errorf("plugin manifest %q: config_schema[%q] missing required field \"type\"", m.ID, name)
		}
	}
	for i, cr := range m.RequiresCredentials {
		if cr.Source == "" {
			return fmt.Errorf("plugin manifest %q: requires_credentials[%d] missing required field \"source\"", m.ID, i)
		}
	}
	return nil
}
