package iso27001

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Built-in policies are Go values that never pass through the YAML
// loader, so the pass_when and slot-role rules it enforces are asserted
// here instead.
func TestPolicies_PassWhenValidates(t *testing.T) {
	for _, p := range Policies() {
		if err := spec.ValidatePassWhen(p); err != nil {
			t.Errorf("policy %q: %v", p.ID, err)
		}
	}
}
