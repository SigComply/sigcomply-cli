package core

// Framework is a shipped or extension compliance framework — the
// catalog of controls plus the set of policies that contribute to
// each control.
type Framework interface {
	ID() string
	Version() string
	Controls() []Control
	Policies() []PolicyRef
}

// Control is one item in a framework's control catalog.
type Control struct {
	ID               string
	Name             string
	Description      string
	Category         string
	BaselineSeverity Severity
}

// PolicyRef points from a framework to a registered policy by ID.
// The PolicyRegistry resolves the ID to the full Policy spec.
type PolicyRef struct {
	PolicyID string
}

// ControlRelationship records how completely a check satisfies a
// control, using the NIST IR 8477 (Set Theory Relationship Mapping) /
// OSCAL control-mapping vocabulary. A single check can satisfy controls
// across multiple frameworks with different relationships — e.g. fully
// satisfy SOC 2 CC6.1 while only partially covering PCI DSS 8.3. The
// zero value is treated as RelationshipEqual.
type ControlRelationship string

const (
	// RelationshipEqual means the check fully satisfies the control.
	RelationshipEqual ControlRelationship = "equal"
	// RelationshipSubsetOf means the check is narrower than the control
	// (satisfies part of it; other checks cover the rest).
	RelationshipSubsetOf ControlRelationship = "subset_of"
	// RelationshipSupersetOf means the check is broader than the control.
	RelationshipSupersetOf ControlRelationship = "superset_of"
	// RelationshipIntersects means partial overlap, neither subset nor superset.
	RelationshipIntersects ControlRelationship = "intersects"
)

// ControlRef is a versioned pointer from a policy (or a result) to one
// control in one framework. Framework + FrameworkVersion namespace the
// ControlID so that, e.g., iso27001:2022 A.8.9 and iso27001:2013
// A.12.1.2 can coexist during a standard's transition window, and a
// crosswalk link can point at a specific versioned control node.
//
// A policy carrying more than one ControlRef is how one check satisfies
// controls across multiple frameworks without being authored, evaluated,
// or stored more than once (the SOC 2 / ISO 27001 ~70% overlap case).
type ControlRef struct {
	Framework        string              `json:"framework,omitempty"`
	FrameworkVersion string              `json:"framework_version,omitempty"`
	ControlID        string              `json:"control_id"`
	Relationship     ControlRelationship `json:"relationship,omitempty"`
}

// PrimaryControlID returns the first ControlRef's ControlID, or "" when
// there are none. Used for single-string display surfaces (text/CSV
// report rows, status output) that show one control per policy.
func PrimaryControlID(refs []ControlRef) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0].ControlID
}
