package spec

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// VendorsKey is the subkey under `experimental:` that carries the
// third-party register. It lives under the escape hatch rather than at
// the top level for the same reason ScopeKey does: the loader runs with
// KnownFields(true), so a brand-new top-level key would hard-fail every
// older pinned CLI that predates it. See
// docs/architecture/08-project-config.md §Config evolution policy.
const VendorsKey = "vendors"

// Risk tiers. The tier is the organization's own assessment of how much
// a third party matters, and it is mechanical rather than decorative —
// but it changes *which artifact* a vendor owes, never *whether* it owes
// one.
//
// That distinction is load-bearing. An earlier draft let the lower tiers
// carry no obligation at all, which would have reproduced the failure
// mode this codebase already names as the worst one available: an
// operator-chosen value that silently removes a requirement, leaves the
// compliance score untouched, and so makes under-declaring the estate
// *raise* the score. It is the same defect as declaring an ISO clause
// not_applicable, which the planner refuses outright.
//
// So TierLow does not mean "no obligation". It means the obligation is
// discharged by a signed-off written justification instead of an
// uploaded artifact, and the register must carry TierRationale and
// ApprovedBy to claim it — exactly what the Statement of Applicability
// already demands of an excluded Annex A control.
const (
	// TierCritical and TierHigh owe independent assurance: a SOC 2
	// Type II, an ISO 27001 certificate, or a penetration-test report.
	TierCritical = "critical"
	TierHigh     = "high"
	// TierModerate owes a lighter artifact — a completed security
	// questionnaire, a trust-page snapshot, or a data-processing
	// agreement — but still owes a folder.
	TierModerate = "moderate"
	// TierLow owes no upload, but owes a rationale and an approver.
	TierLow = "low"
)

// vendorIDPattern bounds a vendor ID to a short, lowercase, path-safe
// slug. The 40-character cap is not cosmetic: the slug is appended to a
// policy ID, and the cloud's policy_code column is finite. Keeping the
// worst case well inside it is cheaper than discovering the limit in
// production.
var vendorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// VendorRegister is the operator's declaration of the third parties this
// project depends on — the inventory SOC 2 CC9.1/CC9.2 and ISO 27001
// A.5.19–A.5.23 expect an organization to maintain, expressed as
// reviewable configuration rather than as a PDF nobody can diff.
//
// It is the set that the per-vendor assurance policies fan out over.
// Without it the vendor policies behave exactly as they did before this
// existed: one flat entry, one folder, one document.
//
// Nothing in here crosses the aggregation boundary. Vendor names are
// third-party identifiers and DeclaredBy is an email address; both stay
// vault-side. The aggregator collapses the per-vendor results back onto
// their template policy before anything is submitted, so the cloud
// learns how many vendors lack evidence and never which ones exist.
type VendorRegister struct {
	// DeclaredBy and DeclaredAt are the audit trail for the assertion,
	// matching the approved_by/approved_at idiom used by exceptions,
	// control applicability and the scope declaration. Both optional.
	DeclaredBy string
	DeclaredAt string

	// Vendors is the register itself, sorted by ID on load so every
	// derived artifact is deterministic (Core Principle #7 — auditors
	// diff runs).
	Vendors []Vendor

	// UnknownKeys are subkeys of experimental.vendors this CLI does not
	// understand. Tolerated, never fatal — that tolerance is the point
	// of the experimental: hatch — but surfaced so a typo is loud
	// without breaking the run.
	UnknownKeys []string
}

// Vendor is one third party in the register.
type Vendor struct {
	// ID is the stable slug used to derive this vendor's policy ID and
	// evidence folder. Changing it re-files the vendor's evidence, so it
	// is deliberately separate from Name.
	ID string

	// Name is the third party as a human names it, used in policy
	// descriptions and the `evidence due` listing.
	Name string

	// Tier is the organization's risk assessment. See the tier
	// constants for what it obliges.
	Tier string

	// Subservice marks a vendor that performs part of the service
	// itself — a SOC 2 subservice organization — rather than merely
	// supplying the organization. It is what makes the complementary
	// user entity controls (CUECs) in the vendor's own report relevant,
	// so the CUEC mapping entry is the place those are reconciled.
	Subservice bool

	// Services is a free-text note on what the vendor does for the
	// organization. Optional, advisory, never evaluated.
	Services string

	// AssurancePeriodEnd is the last day the vendor's own assurance
	// report actually covers — the end of the SOC 2 Type II period, or
	// the certificate's expiry.
	//
	// This is what closes the single most common CC9.2 finding. The
	// temporal window only proves *when the file was uploaded*, so
	// without this a FY2023 Type II uploaded this morning passes, and
	// goes on passing every year forever. Comparing a declared coverage
	// date against the audit period catches that arithmetically.
	//
	// It is DECLARED, never parsed: the CLI does not open the PDF and
	// will not claim to. What it gives an auditor is an assertion
	// recorded in version control, checked for currency on every run.
	// Optional — absent means the freshness check does not run, and the
	// guide says so in those words.
	AssurancePeriodEnd string

	// TierRationale and ApprovedBy are why this vendor sits at this
	// tier, and who signed that off. Required for TierLow, which is the
	// only tier that discharges its obligation with words instead of an
	// artifact. Optional (but encouraged) elsewhere.
	TierRationale string
	ApprovedBy    string

	// Providers names the configured sources this vendor supplies —
	// either a provider token ("aws", "github") or a full source ID
	// ("aws.iam"). It exists for one purpose: to let the planner check
	// the register against something observable.
	//
	// Nothing else can. A vendor the operator simply leaves out is
	// invisible, because the register is a declaration with no
	// counterpart to diff. But every *configured source* is itself a
	// vendor the project demonstrably depends on, so the sources block
	// is a baseline the register must at least cover. Joining the two
	// needs a field, and this is it.
	//
	// Advisory, never fatal, and it discovers nothing: it cross-checks
	// the register against sources the operator already declared, so it
	// stays inside the operator-chosen estate. Optional — a vendor that
	// supplies no configured source (a payroll processor, a law firm)
	// leaves it empty, and that is the normal case.
	Providers []string
}

// RequiresEvidence reports whether this vendor must have a document on
// file each period. Every tier but TierLow does; see the tier constants
// for why TierLow is an approved exemption rather than an absence.
func (v *Vendor) RequiresEvidence() bool {
	return v.Tier != TierLow
}

// EvidencedVendors returns the vendors that owe an uploaded artifact,
// in load order (already sorted by ID).
func (r *VendorRegister) EvidencedVendors() []Vendor {
	if r == nil {
		return nil
	}
	out := make([]Vendor, 0, len(r.Vendors))
	for i := range r.Vendors {
		if r.Vendors[i].RequiresEvidence() {
			out = append(out, r.Vendors[i])
		}
	}
	return out
}

// SubserviceVendors returns the vendors marked as subservice
// organizations — the ones whose own reports carry complementary user
// entity controls the organization must operate itself.
func (r *VendorRegister) SubserviceVendors() []Vendor {
	if r == nil {
		return nil
	}
	out := make([]Vendor, 0, len(r.Vendors))
	for i := range r.Vendors {
		if r.Vendors[i].Subservice {
			out = append(out, r.Vendors[i])
		}
	}
	return out
}

// vendorsRaw mirrors the YAML shape. Decoded leniently (no KnownFields):
// unknown subkeys are reported, not rejected.
type vendorsRaw struct {
	DeclaredBy string      `yaml:"declared_by"`
	DeclaredAt string      `yaml:"declared_at"`
	Register   []vendorRaw `yaml:"register"`
}

type vendorRaw struct {
	ID                 string   `yaml:"id"`
	Name               string   `yaml:"name"`
	Tier               string   `yaml:"tier"`
	Subservice         bool     `yaml:"subservice"`
	Services           string   `yaml:"services"`
	AssurancePeriodEnd string   `yaml:"assurance_period_end"`
	TierRationale      string   `yaml:"tier_rationale"`
	ApprovedBy         string   `yaml:"approved_by"`
	Providers          []string `yaml:"providers"`
}

// knownVendorsKeys is the set vendorsRaw understands, used to report the
// rest rather than to reject them.
var knownVendorsKeys = map[string]struct{}{
	"declared_by": {},
	"declared_at": {},
	"register":    {},
}

// LoadVendorRegister projects the experimental.vendors block out of a
// loaded project config. It returns (nil, nil) when the block is absent —
// the undeclared case, which leaves every existing behavior untouched.
//
// Validation here is shape-only, matching LoadScopeConfig: whether a
// declared vendor has anything to do with a configured source is not a
// question this layer can answer.
// project one optional block out of experimental:, and the shared
// shape — tolerate unknown subkeys, round-trip through the marshaller,
// name the YAML key in every error — is the contract for that hatch.
// Factoring the two together would hide it behind a generic helper and
// make the next experimental block harder to write, not easier.
//
// This shares its shape with LoadScopeConfig line for line, deliberately.
// Both project one optional block out of experimental:, and the shared
// shape — tolerate unknown subkeys, round-trip through the marshaller,
// name the YAML key in every error — is the contract for that hatch.
// Factoring the two together would hide it behind a generic helper and
// make the next experimental block harder to write, not easier.
//
//nolint:dupl // see the note above
func LoadVendorRegister(cfg *ProjectConfig) (*VendorRegister, error) {
	if cfg == nil || cfg.Experimental == nil {
		return nil, nil
	}
	raw, ok := cfg.Experimental[VendorsKey]
	if !ok || raw == nil {
		return nil, nil
	}

	// experimental: decodes into map[string]any, so the original
	// yaml.Node is gone by the time we get here. Round-tripping through
	// the marshaller is what gives us a typed decode; the cost is that
	// error messages carry no line numbers, which is acceptable for a
	// block this small.
	asMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("project config: experimental.vendors must be a mapping of register settings")
	}

	// Check the one non-scalar field's shape up front, for the same
	// reason scope.go does: yaml's own type error names the Go type
	// rather than the YAML key, which is not a message a hand-editing
	// operator can act on.
	if v, present := asMap["register"]; present {
		if _, isList := v.([]any); !isList {
			return nil, fmt.Errorf("project config: experimental.vendors.register must be a list of vendors, e.g. [{id: acme_cloud, name: Acme Cloud, tier: critical}]")
		}
	}

	buf, err := yaml.Marshal(asMap)
	if err != nil {
		return nil, fmt.Errorf("project config: experimental.vendors: %w", err)
	}
	var rawVendors vendorsRaw
	if err := yaml.Unmarshal(buf, &rawVendors); err != nil {
		return nil, fmt.Errorf("project config: experimental.vendors: %w", err)
	}

	out := &VendorRegister{
		DeclaredBy: rawVendors.DeclaredBy,
		DeclaredAt: rawVendors.DeclaredAt,
	}
	for k := range asMap {
		if _, known := knownVendorsKeys[k]; !known {
			out.UnknownKeys = append(out.UnknownKeys, k)
		}
	}
	sort.Strings(out.UnknownKeys)

	if err := validateOptionalDate(rawVendors.DeclaredAt); err != nil {
		return nil, fmt.Errorf("project config: experimental.vendors.declared_at: %w", err)
	}

	vendors, err := validateVendorRegister(rawVendors.Register)
	if err != nil {
		return nil, err
	}
	out.Vendors = vendors

	return out, nil
}

// validateVendorRegister checks the declared register is non-empty and
// every vendor is well-formed and uniquely identified, and returns them
// sorted by ID.
func validateVendorRegister(raw []vendorRaw) ([]Vendor, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("project config: experimental.vendors: register must list at least one vendor (remove the vendors block entirely to leave the register undeclared)")
	}
	out := make([]Vendor, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for i := range raw {
		v := &raw[i]
		if v.ID == "" {
			return nil, fmt.Errorf("project config: experimental.vendors.register[%d]: missing required field \"id\"", i)
		}
		if !vendorIDPattern.MatchString(v.ID) {
			return nil, fmt.Errorf("project config: experimental.vendors.register[%d]: id %q must be 1-40 characters of lowercase letters, digits, underscore or hyphen, starting with a letter or digit", i, v.ID)
		}
		if _, dup := seen[v.ID]; dup {
			return nil, fmt.Errorf("project config: experimental.vendors.register: duplicate vendor id %q", v.ID)
		}
		seen[v.ID] = struct{}{}
		if v.Name == "" {
			return nil, fmt.Errorf("project config: experimental.vendors.register[%d] (%s): missing required field \"name\"", i, v.ID)
		}
		switch v.Tier {
		case TierCritical, TierHigh, TierModerate, TierLow:
		default:
			return nil, fmt.Errorf("project config: experimental.vendors.register[%d] (%s): tier: invalid value %q (want %s|%s|%s|%s)",
				i, v.ID, v.Tier, TierCritical, TierHigh, TierModerate, TierLow)
		}
		// TierLow is the one tier that discharges its obligation with a
		// justification rather than an artifact, so the justification is
		// mandatory. Without this, "low" would be a silent opt-out —
		// see the tier constants.
		if v.Tier == TierLow {
			if v.TierRationale == "" {
				return nil, fmt.Errorf("project config: experimental.vendors.register[%d] (%s): tier %q requires \"tier_rationale\" (a low-tier vendor files no evidence, so the justification is the evidence)", i, v.ID, TierLow)
			}
			if v.ApprovedBy == "" {
				return nil, fmt.Errorf("project config: experimental.vendors.register[%d] (%s): tier %q requires \"approved_by\" (who signed off on this exemption)", i, v.ID, TierLow)
			}
		}
		if err := validateOptionalDate(v.AssurancePeriodEnd); err != nil {
			return nil, fmt.Errorf("project config: experimental.vendors.register[%d] (%s): assurance_period_end: %w", i, v.ID, err)
		}
		for j, p := range v.Providers {
			if strings.TrimSpace(p) == "" {
				return nil, fmt.Errorf("project config: experimental.vendors.register[%d] (%s): providers[%d] is empty (name a configured source, e.g. \"aws\" or \"aws.iam\")", i, v.ID, j)
			}
		}
		// vendorRaw and Vendor are field-identical by construction:
		// the YAML shape and the loaded shape are the same data, and
		// keeping them as separate types is about which layer owns the
		// tags, not about the fields diverging.
		out = append(out, Vendor(*v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
