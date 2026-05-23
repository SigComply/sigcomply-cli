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
