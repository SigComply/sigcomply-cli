package spec

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// projectConfigSchemaVersion is the only schema_version this loader
// accepts.
const projectConfigSchemaVersion = "project.v1"

// ProjectConfig is the parsed shape of .sigcomply.yaml. See
// docs/architecture/08-project-config.md for the canonical field
// reference. Cross-spec resolution (does this binding's source exist?
// is this parameter declared on the named policy?) is the planner's
// job (L3 / M4) — this loader only validates what's expressible
// without the registries.
type ProjectConfig struct {
	SchemaVersion    string                               `yaml:"schema_version"`
	Framework        string                               `yaml:"framework"`
	Period           PeriodConfig                         `yaml:"period"`
	Vault            VaultConfig                          `yaml:"vault"`
	Sources          map[string]map[string]any            `yaml:"sources"`
	Bindings         map[string]map[string][]BindingEntry `yaml:"bindings"`
	PolicyParameters map[string]map[string]any            `yaml:"policy_parameters"`
	PolicyCadences   map[string]string                    `yaml:"policy_cadences"`
	PolicyOverrides  map[string]PolicyOverride            `yaml:"policy_overrides"`
	Exceptions       []ExceptionConfig                    `yaml:"exceptions"`
	Cloud            CloudConfig                          `yaml:"cloud"`
	CIEnvironment    map[string]any                       `yaml:"ci_environment"`
	Output           OutputConfig                         `yaml:"output"`
	CI               CIConfig                             `yaml:"ci"`
	Extensions       ExtensionsConfig                     `yaml:"extensions"`

	// ProjectLocalPolicies are PolicyRefs for policies discovered under
	// .sigcomply/policies/*/policy.yaml at bootstrap and registered into
	// the policy registry. The planner unions these with the active
	// framework's own Policies() so a customer-authored YAML policy is
	// actually planned and evaluated. yaml:"-" — populated by the
	// orchestrator's project-local loader, never decoded from the file.
	ProjectLocalPolicies []core.PolicyRef `yaml:"-"`
}

// PeriodConfig models the period section.
type PeriodConfig struct {
	FiscalCalendar FiscalCalendarConfig `yaml:"fiscal_calendar"`
	TimeBasis      string               `yaml:"time_basis"`
}

// FiscalCalendarConfig models the period.fiscal_calendar subsection.
type FiscalCalendarConfig struct {
	Type    string         `yaml:"type"`
	Starts  string         `yaml:"starts"`
	Periods []CustomPeriod `yaml:"periods"`
}

// CustomPeriod is one entry in a custom fiscal_calendar.periods list.
type CustomPeriod struct {
	ID    string `yaml:"id"`
	Start string `yaml:"start"`
	End   string `yaml:"end"`
}

// VaultConfig models the vault section. Backend-specific fields are
// all declared optional at the YAML level; per-backend required-field
// checks happen in validate.
type VaultConfig struct {
	Backend        string `yaml:"backend"`
	Bucket         string `yaml:"bucket"`
	Region         string `yaml:"region"`
	Prefix         string `yaml:"prefix"`
	Endpoint       string `yaml:"endpoint"`
	ForcePathStyle bool   `yaml:"force_path_style"`
	Profile        string `yaml:"profile"`
	RoleARN        string `yaml:"role_arn"`
	Path           string `yaml:"path"`
	Account        string `yaml:"account"`
	Container      string `yaml:"container"`
}

// BindingEntry is one element of a slot binding list. It accepts both
// the string shape ("aws.iam") and the object shape with optional
// slot_params ({source: aws.iam, slot_params: {...}}).
type BindingEntry struct {
	Source     string         `yaml:"source"`
	SlotParams map[string]any `yaml:"slot_params"`
}

// UnmarshalYAML accepts either a scalar string or a mapping; both are
// valid shapes in .sigcomply.yaml.
func (b *BindingEntry) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Decode(&b.Source)
	case yaml.MappingNode:
		// Use a local type without the custom unmarshaler to avoid
		// infinite recursion, and keep KnownFields-strict semantics.
		var raw struct {
			Source     string         `yaml:"source"`
			SlotParams map[string]any `yaml:"slot_params"`
		}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		b.Source = raw.Source
		b.SlotParams = raw.SlotParams
		if b.Source == "" {
			return fmt.Errorf("binding entry: mapping form requires non-empty \"source\"")
		}
		return nil
	default:
		return fmt.Errorf("binding entry: expected string or mapping (got node kind %d)", node.Kind)
	}
}

// ExceptionConfig is one declarative waiver or N/A entry.
type ExceptionConfig struct {
	Policy     string         `yaml:"policy"`
	Scope      ExceptionScope `yaml:"scope"`
	State      string         `yaml:"state"`
	Reason     string         `yaml:"reason"`
	ApprovedBy string         `yaml:"approved_by"`
	ApprovedAt string         `yaml:"approved_at"`
	ExpiresAt  string         `yaml:"expires_at"`
}

// ExceptionScope narrows an exception to specific resources.
type ExceptionScope struct {
	ResourceID      string `yaml:"resource_id"`
	ResourcePattern string `yaml:"resource_pattern"`
}

// PolicyOverride lets a project override the evidence_mode declared in a
// framework-shipped policy spec. The primary use case is flipping an
// automated policy to manual while API integrations are being built out,
// then reverting the override once the integration is ready.
//
// evidence_mode: "manual"     — requires catalog_entry
// evidence_mode: "automated"  — catalog_entry must be absent
type PolicyOverride struct {
	EvidenceMode string `yaml:"evidence_mode"`
	CatalogEntry string `yaml:"catalog_entry"`
}

// CloudConfig models the cloud submission section.
type CloudConfig struct {
	Enabled *bool  `yaml:"enabled"`
	BaseURL string `yaml:"base_url"`
}

// OutputConfig models output preferences.
type OutputConfig struct {
	Format   string `yaml:"format"`
	JSONPath string `yaml:"json_path"`
	Verbose  bool   `yaml:"verbose"`
}

// CIConfig models CI exit-code behavior knobs.
type CIConfig struct {
	FailOnViolation *bool         `yaml:"fail_on_violation"`
	FailSeverity    core.Severity `yaml:"fail_severity"`
}

// ExtensionsConfig overrides extension discovery paths.
type ExtensionsConfig struct {
	Path string `yaml:"path"`
}

// LoadProjectConfig parses a .sigcomply.yaml document. The file is the
// customer's source of truth, so all error messages name the field path
// to make corrections obvious.
func LoadProjectConfig(data []byte) (ProjectConfig, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return ProjectConfig{}, fmt.Errorf("project config: empty input")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg ProjectConfig
	if err := dec.Decode(&cfg); err != nil {
		return ProjectConfig{}, fmt.Errorf("project config: parse: %w", err)
	}
	if err := validateProjectConfig(&cfg); err != nil {
		return ProjectConfig{}, err
	}
	return cfg, nil
}

func validateProjectConfig(cfg *ProjectConfig) error {
	if err := expectSchemaVersion(cfg.SchemaVersion, projectConfigSchemaVersion, "project config"); err != nil {
		return err
	}
	if cfg.Framework == "" {
		return fmt.Errorf("project config: missing required field \"framework\"")
	}
	if err := validatePeriod(&cfg.Period); err != nil {
		return err
	}
	if err := validateVault(&cfg.Vault); err != nil {
		return err
	}
	if err := validateSources(cfg.Sources); err != nil {
		return err
	}
	if err := validatePolicyCadences(cfg.PolicyCadences); err != nil {
		return err
	}
	if err := validatePolicyOverrides(cfg.PolicyOverrides); err != nil {
		return err
	}
	if err := validateExceptions(cfg.Exceptions); err != nil {
		return err
	}
	if err := validateOutput(&cfg.Output); err != nil {
		return err
	}
	if err := validateCI(&cfg.CI); err != nil {
		return err
	}
	return nil
}

func validatePeriod(p *PeriodConfig) error {
	if p.FiscalCalendar.Type == "" {
		// Default applied at planner time; loader leaves blank.
		return nil
	}
	switch p.FiscalCalendar.Type {
	case "calendar_quarter", "fiscal_year", "custom":
	default:
		return fmt.Errorf("project config: period.fiscal_calendar.type: invalid value %q (want calendar_quarter|fiscal_year|custom)", p.FiscalCalendar.Type)
	}
	if p.FiscalCalendar.Type == "custom" && len(p.FiscalCalendar.Periods) == 0 {
		return fmt.Errorf("project config: period.fiscal_calendar.periods: required when type is \"custom\"")
	}
	for i, cp := range p.FiscalCalendar.Periods {
		if cp.ID == "" || cp.Start == "" || cp.End == "" {
			return fmt.Errorf("project config: period.fiscal_calendar.periods[%d]: id, start, end are all required", i)
		}
	}
	if p.TimeBasis != "" && p.TimeBasis != "commit" && p.TimeBasis != "wall_clock" {
		return fmt.Errorf("project config: period.time_basis: invalid value %q (want commit|wall_clock)", p.TimeBasis)
	}
	return nil
}

func validateVault(v *VaultConfig) error {
	if v.Backend == "" {
		return fmt.Errorf("project config: vault.backend: required")
	}
	switch v.Backend {
	case "local":
		if v.Path == "" {
			return fmt.Errorf("project config: vault.path: required for backend \"local\"")
		}
	case "s3":
		if v.Bucket == "" {
			return fmt.Errorf("project config: vault.bucket: required for backend \"s3\"")
		}
		if v.Region == "" {
			return fmt.Errorf("project config: vault.region: required for backend \"s3\"")
		}
	case "gcs":
		if v.Bucket == "" {
			return fmt.Errorf("project config: vault.bucket: required for backend \"gcs\"")
		}
	case "azure_blob":
		if v.Account == "" || v.Container == "" {
			return fmt.Errorf("project config: vault.account and vault.container: both required for backend \"azure_blob\"")
		}
	default:
		return fmt.Errorf("project config: vault.backend: invalid value %q (want local|s3|gcs|azure_blob)", v.Backend)
	}
	return nil
}

// bracketedManualPDF rejects any manual.pdf instance with a bracket
// suffix. The plugin is a project-level singleton (see docs/architecture
// /04-source-plugins.md §The manual.pdf plugin).
var bracketedManualPDF = regexp.MustCompile(`^manual\.pdf\[.*\]$`)

func validateSources(sources map[string]map[string]any) error {
	for id := range sources {
		if bracketedManualPDF.MatchString(id) {
			return fmt.Errorf("project config: sources[%q]: manual.pdf is a project-level singleton and does not accept bracket-suffix instances", id)
		}
	}
	return nil
}

func validatePolicyCadences(m map[string]string) error {
	for id, c := range m {
		if err := validateCadenceSpec(c); err != nil {
			return fmt.Errorf("project config: policy_cadences[%q]: %w", id, err)
		}
	}
	return nil
}

func validatePolicyOverrides(overrides map[string]PolicyOverride) error {
	for id, o := range overrides {
		switch o.EvidenceMode {
		case "automated":
			if o.CatalogEntry != "" {
				return fmt.Errorf("project config: policy_overrides[%q]: catalog_entry must not be set when evidence_mode is \"automated\"", id)
			}
		case "manual":
			if o.CatalogEntry == "" {
				return fmt.Errorf("project config: policy_overrides[%q]: catalog_entry is required when evidence_mode is \"manual\"", id)
			}
		case "":
			return fmt.Errorf("project config: policy_overrides[%q]: evidence_mode is required (want automated|manual)", id)
		default:
			return fmt.Errorf("project config: policy_overrides[%q]: evidence_mode: invalid value %q (want automated|manual)", id, o.EvidenceMode)
		}
	}
	return nil
}

var iso8601Date = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func validateExceptions(exs []ExceptionConfig) error {
	for i := range exs {
		e := &exs[i]
		if e.Policy == "" {
			return fmt.Errorf("project config: exceptions[%d]: missing required field \"policy\"", i)
		}
		switch e.State {
		case "waived", "na":
		case "":
			return fmt.Errorf("project config: exceptions[%d] (%s): missing required field \"state\"", i, e.Policy)
		default:
			return fmt.Errorf("project config: exceptions[%d] (%s): invalid state %q (want waived|na)", i, e.Policy, e.State)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("project config: exceptions[%d] (%s): missing required field \"reason\"", i, e.Policy)
		}
		if e.ApprovedAt != "" {
			if !iso8601Date.MatchString(e.ApprovedAt) {
				return fmt.Errorf("project config: exceptions[%d] (%s): approved_at %q is not an ISO 8601 date (YYYY-MM-DD)", i, e.Policy, e.ApprovedAt)
			}
			if _, err := time.Parse("2006-01-02", e.ApprovedAt); err != nil {
				return fmt.Errorf("project config: exceptions[%d] (%s): approved_at %q is not a valid date: %v", i, e.Policy, e.ApprovedAt, err)
			}
		}
		if e.ExpiresAt != "" {
			if !iso8601Date.MatchString(e.ExpiresAt) {
				return fmt.Errorf("project config: exceptions[%d] (%s): expires_at %q is not an ISO 8601 date (YYYY-MM-DD)", i, e.Policy, e.ExpiresAt)
			}
			if _, err := time.Parse("2006-01-02", e.ExpiresAt); err != nil {
				return fmt.Errorf("project config: exceptions[%d] (%s): expires_at %q is not a valid date: %v", i, e.Policy, e.ExpiresAt, err)
			}
		}
	}
	return nil
}

func validateOutput(o *OutputConfig) error {
	if o.Format == "" {
		return nil
	}
	switch o.Format {
	case "text", "json", "junit", "sarif":
		return nil
	default:
		return fmt.Errorf("project config: output.format: invalid value %q (want text|json|junit|sarif)", o.Format)
	}
}

func validateCI(c *CIConfig) error {
	if c.FailSeverity == "" {
		return nil
	}
	if !isValidSeverity(c.FailSeverity) {
		return fmt.Errorf("project config: ci.fail_severity: invalid value %q (want info|low|medium|high|critical)", c.FailSeverity)
	}
	return nil
}
