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
	SchemaVersion string                    `yaml:"schema_version"`
	Framework     string                    `yaml:"framework"`
	Period        PeriodConfig              `yaml:"period"`
	Vault         VaultConfig               `yaml:"vault"`
	Sources       map[string]map[string]any `yaml:"sources"`

	// Policies holds all per-policy configuration as one object per
	// policy ID — bindings, parameter overrides, cadence override,
	// evidence_mode override, and scoped exceptions co-located in a single
	// place. This replaces the former family of parallel policy-ID-keyed
	// maps (bindings/policy_parameters/policy_cadences/policy_overrides/
	// exceptions). The shape is what makes the config extensible without a
	// schema bump: a new per-policy dimension (severity, scope, owner) is a
	// new optional field on PolicyConfig — additive, never a new top-level
	// section. See docs/architecture/08-project-config.md §The binding model.
	Policies map[string]PolicyConfig `yaml:"policies"`

	// Controls holds control-level decisions — the coarse, governance
	// axis that is naturally per-control, not per-check: applicability
	// (the ISO Statement of Applicability), and room for ownership and
	// inheritance. A control marked not_applicable cascades to every
	// policy that maps to it (planner sets status=na). Fine-grained,
	// resource-scoped waivers stay under Policies[id].exceptions.
	Controls map[string]ControlConfig `yaml:"controls"`

	Cloud         CloudConfig      `yaml:"cloud"`
	CIEnvironment map[string]any   `yaml:"ci_environment"`
	Output        OutputConfig     `yaml:"output"`
	CI            CIConfig         `yaml:"ci"`
	Extensions    ExtensionsConfig `yaml:"extensions"`

	// Experimental is the forward-compatibility escape hatch. The loader
	// runs with KnownFields(true) so a typo in a recognized key is a loud
	// error — but that strictness would also make any *new* top-level key
	// break older CLIs that predate it. New, not-yet-stable fields are
	// introduced under `experimental:` first: every CLI version that has
	// this field tolerates (and ignores) experimental subkeys it does not
	// understand, so a newer config never hard-fails an older pinned CLI.
	// A field graduates from `experimental.<name>` to a first-class
	// top-level key in a later release. The loader does not interpret
	// anything in here; individual features opt in by reading their own
	// key. See docs/architecture/08-project-config.md §Config evolution.
	Experimental map[string]any `yaml:"experimental"`

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

// VaultConfig selects an output vault backend and carries its
// backend-specific settings as an open bag — symmetric with the
// `sources:` config, where each plugin reads the keys it needs. Only
// `backend` is interpreted by the spec layer; every other key flows
// through to the backend's factory untouched. This is what makes a new
// destination backend additive: it reads its own keys from Config, with
// no typed struct field and no central validation switch to edit (see
// docs/architecture/05-vault-layout.md §Adding a backend).
//
// The YAML stays flat for ergonomics — `vault: {backend: s3, bucket: x,
// region: y}` — via the custom UnmarshalYAML below: `backend` is lifted
// out and the remaining keys become Config.
type VaultConfig struct {
	Backend string
	Config  map[string]any
}

// UnmarshalYAML accepts the flat `vault:` mapping, lifting `backend` into
// its own field and passing all other keys through as Config. Decoding
// into a map deliberately bypasses the parent decoder's KnownFields
// strictness for vault keys — the bag is open, exactly like `sources:`.
func (v *VaultConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("vault: expected a mapping (got node kind %d)", node.Kind)
	}
	raw := map[string]any{}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if b, ok := raw["backend"]; ok {
		s, ok := b.(string)
		if !ok {
			return fmt.Errorf("vault.backend: must be a string (got %T)", b)
		}
		v.Backend = s
		delete(raw, "backend")
	}
	v.Config = raw
	return nil
}

// Str returns the string value of a Config key, or "" if absent/non-string.
func (v VaultConfig) Str(key string) string {
	s, _ := v.Config[key].(string)
	return s
}

// Bool returns the bool value of a Config key, or false if absent/non-bool.
func (v VaultConfig) Bool(key string) bool {
	b, _ := v.Config[key].(bool)
	return b
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

// PolicyConfig is the per-policy configuration object — everything a
// project can override or declare about one policy, co-located under its
// ID in the policies: map. Every field is optional; an absent policy
// entry means "framework defaults, auto-bound sources, no exceptions."
//
//	policies:
//	  soc2.cc6.1.mfa_enforced:
//	    cadence: hourly
//	    bindings: { user_directory: [okta, acme.internal_iam] }
//	    parameters: { exempt_service_accounts: false }
//	    exceptions:
//	      - scope: { resource_id: "okta_user:bot@acme.com" }
//	        state: waived
//	        reason: "Legacy deploy bot; retired by Q3."
//	        expires_at: 2026-09-30
//
// New per-policy dimensions (severity, scope, owner, enabled) are added
// here as new optional fields — additive, no schema bump.
type PolicyConfig struct {
	Bindings     map[string][]BindingEntry `yaml:"bindings"`
	Parameters   map[string]any            `yaml:"parameters"`
	Cadence      string                    `yaml:"cadence"`
	EvidenceMode string                    `yaml:"evidence_mode"`
	CatalogEntry string                    `yaml:"catalog_entry"`
	Exceptions   []PolicyException         `yaml:"exceptions"`
}

// PolicyException is one declarative waiver or N/A entry on a policy. The
// owning policy is the map key in PolicyConfig — there is no policy
// field. Multiple entries on one policy support distinct resource scopes.
type PolicyException struct {
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

// ControlConfig is a control-level decision — the coarse governance axis
// authored per control (the unit auditors and the ISO Statement of
// Applicability think in), not per check. applicability: not_applicable
// cascades to every policy mapping to this control. Reason/ApprovedBy
// give the audit trail; Owner/InheritedFrom are reserved for later.
type ControlConfig struct {
	Applicability string `yaml:"applicability"` // "" | applicable | not_applicable
	Reason        string `yaml:"reason"`
	ApprovedBy    string `yaml:"approved_by"`
}

// BindingsFor returns the slot→entries map a project declared for a
// policy, or nil if the policy has no entry. nil means "auto-bind every
// configured source whose Emits() intersects the slot" — the planner's
// substitutability default.
func (c *ProjectConfig) BindingsFor(policyID string) map[string][]BindingEntry {
	return c.Policies[policyID].Bindings
}

// ParametersFor returns the parameter overrides a project declared for a
// policy, or nil.
func (c *ProjectConfig) ParametersFor(policyID string) map[string]any {
	return c.Policies[policyID].Parameters
}

// CadenceFor returns the cadence override for a policy, or "" (use the
// framework default).
func (c *ProjectConfig) CadenceFor(policyID string) string {
	return c.Policies[policyID].Cadence
}

// EvidenceModeOverrideFor returns the (mode, catalog_entry) override for a
// policy. mode is "" when the project does not override the framework's
// evidence_mode for this policy.
func (c *ProjectConfig) EvidenceModeOverrideFor(policyID string) (mode, catalogEntry string) {
	p := c.Policies[policyID]
	return p.EvidenceMode, p.CatalogEntry
}

// ExceptionsFor returns the scoped waiver/NA entries a project declared
// for a policy, or nil.
func (c *ProjectConfig) ExceptionsFor(policyID string) []PolicyException {
	return c.Policies[policyID].Exceptions
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
	if err := validatePolicies(cfg.Policies); err != nil {
		return err
	}
	if err := validateControls(cfg.Controls); err != nil {
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

// fiscalTypeCustom is the fiscal-calendar type that requires explicit periods.
const fiscalTypeCustom = "custom"

func validatePeriod(p *PeriodConfig) error {
	if p.FiscalCalendar.Type == "" {
		// Default applied at planner time; loader leaves blank.
		return nil
	}
	switch p.FiscalCalendar.Type {
	case "calendar_quarter", "fiscal_year", fiscalTypeCustom:
	default:
		return fmt.Errorf("project config: period.fiscal_calendar.type: invalid value %q (want calendar_quarter|fiscal_year|custom)", p.FiscalCalendar.Type)
	}
	if p.FiscalCalendar.Type == fiscalTypeCustom && len(p.FiscalCalendar.Periods) == 0 {
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

// backendLocal is the local-filesystem vault backend identifier.
const backendLocal = "local"

// DefaultLocalVaultPath is where a backend-less project stores signed
// evidence by default. It keeps a first run zero-config: no vault: block
// is required to get going. Production deployments override with an
// s3/gcs/azure_blob backend (which must be write-once / versioned for
// real tamper-resistance — see Invariant #3).
const DefaultLocalVaultPath = "./.sigcomply/vault"

func validateVault(v *VaultConfig) error {
	// Sensible default: an omitted vault: block means a local vault under
	// the project. Mutating the struct here means the default flows through
	// to vault.FromConfig unchanged — callers never see an empty backend.
	if v.Config == nil {
		v.Config = map[string]any{}
	}
	if v.Backend == "" {
		v.Backend = backendLocal
	}
	if v.Backend == backendLocal && v.Str("path") == "" {
		v.Config["path"] = DefaultLocalVaultPath
	}
	// No per-backend switch here by design. The spec layer cannot know any
	// given backend's required fields without importing the vault package
	// (an import cycle), and re-listing the backends here would be a second
	// source of truth that drifts from the registry — the exact coupling
	// that made adding a backend a central edit. Per-backend required-field
	// validation is therefore the backend's own job, surfaced clearly at
	// vault.FromConfig (still at startup, before any work). Adding a
	// destination backend touches no file in internal/spec.
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

// validatePolicies validates every per-policy config object: cadence
// override, evidence_mode override (with its catalog_entry rule), and
// each scoped exception. Cross-reference checks — does this policy ID
// exist in the framework? does the named source exist? — are NOT done
// here (the loader has no registries by design); they belong to the
// planner / the P1.1 bootstrap validation pass.
func validatePolicies(policies map[string]PolicyConfig) error {
	for id := range policies {
		pc := policies[id]
		if pc.Cadence != "" {
			if err := validateCadenceSpec(pc.Cadence); err != nil {
				return fmt.Errorf("project config: policies[%q].cadence: %w", id, err)
			}
		}
		switch pc.EvidenceMode {
		case "", "automated":
			if pc.CatalogEntry != "" {
				return fmt.Errorf("project config: policies[%q]: catalog_entry must not be set unless evidence_mode is \"manual\"", id)
			}
		case "manual":
			if pc.CatalogEntry == "" {
				return fmt.Errorf("project config: policies[%q]: catalog_entry is required when evidence_mode is \"manual\"", id)
			}
		default:
			return fmt.Errorf("project config: policies[%q].evidence_mode: invalid value %q (want automated|manual)", id, pc.EvidenceMode)
		}
		for i := range pc.Exceptions {
			if err := validatePolicyException(id, i, &pc.Exceptions[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

var iso8601Date = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func validatePolicyException(policyID string, idx int, e *PolicyException) error {
	switch e.State {
	case "waived", "na":
	case "":
		return fmt.Errorf("project config: policies[%q].exceptions[%d]: missing required field \"state\"", policyID, idx)
	default:
		return fmt.Errorf("project config: policies[%q].exceptions[%d]: invalid state %q (want waived|na)", policyID, idx, e.State)
	}
	if strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("project config: policies[%q].exceptions[%d]: missing required field \"reason\"", policyID, idx)
	}
	if err := validateOptionalDate(e.ApprovedAt); err != nil {
		return fmt.Errorf("project config: policies[%q].exceptions[%d]: approved_at %w", policyID, idx, err)
	}
	if err := validateOptionalDate(e.ExpiresAt); err != nil {
		return fmt.Errorf("project config: policies[%q].exceptions[%d]: expires_at %w", policyID, idx, err)
	}
	return nil
}

// validateControls validates the control-level decisions: applicability
// must be a known value, and not_applicable requires a reason (the audit
// trail for a Statement-of-Applicability exclusion).
func validateControls(controls map[string]ControlConfig) error {
	for id := range controls {
		c := controls[id]
		switch c.Applicability {
		case "", "applicable":
		case "not_applicable":
			if strings.TrimSpace(c.Reason) == "" {
				return fmt.Errorf("project config: controls[%q]: reason is required when applicability is \"not_applicable\"", id)
			}
		default:
			return fmt.Errorf("project config: controls[%q].applicability: invalid value %q (want applicable|not_applicable)", id, c.Applicability)
		}
	}
	return nil
}

// validateOptionalDate returns nil for an empty string, else verifies the
// value is an ISO 8601 calendar date (YYYY-MM-DD). The returned error is
// phrased to be wrapped after a field-path prefix.
func validateOptionalDate(s string) error {
	if s == "" {
		return nil
	}
	if !iso8601Date.MatchString(s) {
		return fmt.Errorf("%q is not an ISO 8601 date (YYYY-MM-DD)", s)
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return fmt.Errorf("%q is not a valid date: %v", s, err)
	}
	return nil
}

func validateOutput(o *OutputConfig) error {
	if o.Format == "" {
		return nil
	}
	// "sarif" is intentionally NOT accepted: no SARIF formatter is wired
	// (only the report command emits json/csv; check emits a fixed text
	// summary). Accepting it would pass validation and then produce no
	// SARIF output — a silent contradiction. Re-add when a formatter ships.
	switch o.Format {
	case "text", "json", "junit":
		return nil
	default:
		return fmt.Errorf("project config: output.format: invalid value %q (want text|json|junit)", o.Format)
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
