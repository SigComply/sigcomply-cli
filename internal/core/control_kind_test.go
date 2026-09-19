package core_test

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// TestControlKind_ZeroValueIsCatalog pins the default. Every framework
// that predates the distinction declares nothing, and must keep
// behaving as a catalog of selectable controls.
func TestControlKind_ZeroValueIsCatalog(t *testing.T) {
	var c core.Control
	if c.IsManagementSystem() {
		t.Error("a control that declares no Kind must default to the selectable catalog")
	}
	if c.Kind != "" {
		t.Errorf("zero value Kind = %q, want empty", c.Kind)
	}
}

func TestControlKind_ManagementSystemIsRecognised(t *testing.T) {
	c := core.Control{ID: "C.9.2", Kind: core.ControlKindManagementSystem}
	if !c.IsManagementSystem() {
		t.Error("a ControlKindManagementSystem control must report itself as one")
	}
	if explicit := (core.Control{Kind: core.ControlKindCatalog}); explicit.IsManagementSystem() {
		t.Error("an explicitly-catalog control must not report as management-system")
	}
}
