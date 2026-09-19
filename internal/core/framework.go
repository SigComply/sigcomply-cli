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

// ControlKind separates the two things a framework calls a "control".
//
// Most are catalog controls: an organization selects from them and may
// declare one inapplicable with a justification. ISO 27001 Annex A and
// the SOC 2 Trust Services Criteria are both this.
//
// ISO 27001 clauses 4-10 are not. They are requirements of the
// management system itself — the thing certification is granted
// against — and an organization cannot decline one. Recording the
// difference on the control is what lets a surface that knows nothing
// about any particular framework still get two things right: a
// Statement of Applicability lists the necessary controls and never the
// management-system clauses (ISO 27001:2022 6.1.3 d), and an
// applicability exclusion against a management-system requirement is a
// config error rather than a silently honored N/A.
//
// Note that "the necessary controls" is wider than Annex A: 6.1.3 b)
// NOTE 1 lets an organization design controls from any source, and
// Annex A is the cross-check list rather than the menu. So the
// distinction that belongs on a control is selectable-or-not, never
// came-from-Annex-A — a project-local extension's own controls belong
// in the SoA too.
type ControlKind string

// ControlKind values. The zero value is ControlKindCatalog, so a
// framework that has only catalog controls declares nothing.
const (
	// ControlKindCatalog is a control an organization includes or
	// excludes, with a justification either way.
	ControlKindCatalog ControlKind = "catalog"
	// ControlKindManagementSystem is a requirement of the management
	// system itself. It cannot be excluded and never appears in a
	// Statement of Applicability.
	ControlKindManagementSystem ControlKind = "management_system"
)

// Control is one item in a framework's control catalog.
type Control struct {
	ID               string
	Name             string
	Description      string
	Category         string
	BaselineSeverity Severity
	// Kind says whether this control is selectable. Empty means
	// ControlKindCatalog — see ControlKind.
	Kind ControlKind
}

// IsManagementSystem reports whether the control is a management-system
// requirement rather than a selectable catalog control.
func (c *Control) IsManagementSystem() bool {
	return c.Kind == ControlKindManagementSystem
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
