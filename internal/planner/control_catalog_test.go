package planner

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

const catalogControl = "CC6.1"

type catalogFramework struct {
	controls []core.Control
	policies []core.PolicyRef
}

func (*catalogFramework) ID() string                   { return testFrameworkID }
func (*catalogFramework) Version() string              { return "test" }
func (f *catalogFramework) Controls() []core.Control   { return f.controls }
func (f *catalogFramework) Policies() []core.PolicyRef { return f.policies }

// catalogFixture registers one project-local policy mapped to refs.
func catalogFixture(t *testing.T, refs []core.ControlRef) (*spec.ProjectConfig, core.Framework, *registry.Set) {
	t.Helper()
	set := registry.NewSet()
	pol := core.Policy{ID: "acme.custom_check", Controls: refs}
	if err := set.Policies.Register(pol); err != nil {
		t.Fatalf("register policy: %v", err)
	}
	fw := &catalogFramework{controls: []core.Control{{ID: catalogControl, Name: "Logical access"}}}
	cfg := &spec.ProjectConfig{
		Framework:            testFrameworkID,
		ProjectLocalPolicies: []core.PolicyRef{{PolicyID: pol.ID}},
	}
	return cfg, fw, set
}

// A control ID that is not in the framework's catalog drops the policy
// out of every per-control surface (coverage, the SoA) while it still
// runs and scores, so the mapping looks fine and is not. Refuse it.
func TestValidatePolicyControls_RejectsUnknownControl(t *testing.T) {
	cfg, fw, set := catalogFixture(t, []core.ControlRef{{ControlID: "CC6.01"}})
	err := validatePolicyControls(cfg, fw, set)
	if err == nil {
		t.Fatal("want an error for an unknown control, got nil")
	}
	for _, want := range []string{`"acme.custom_check"`, `"CC6.01"`, `did you mean "CC6.1"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q; want it to contain %s", err, want)
		}
	}
}

// Plan surfaces it, which is what makes it exit 3.
func TestPlan_RejectsProjectLocalPolicyWithUnknownControl(t *testing.T) {
	cfg, fw, set := catalogFixture(t, []core.ControlRef{{ControlID: "CC9.9"}})
	if err := set.Frameworks.Register(fw); err != nil {
		t.Fatalf("register framework: %v", err)
	}
	_, err := Plan(&Input{Config: cfg, Registries: set})
	if err == nil || !strings.Contains(err.Error(), `control "CC9.9" is not in the soc2 control catalog`) {
		t.Fatalf("Plan error = %v; want the unknown control named", err)
	}
}

func TestValidatePolicyControls_AcceptsKnownControl(t *testing.T) {
	cfg, fw, set := catalogFixture(t, []core.ControlRef{{ControlID: catalogControl}})
	if err := validatePolicyControls(cfg, fw, set); err != nil {
		t.Fatalf("validatePolicyControls: %v", err)
	}
}

// A mapping into another framework's taxonomy cannot be checked against
// this framework's catalog, so it is left alone.
func TestValidatePolicyControls_SkipsOtherFrameworksRefs(t *testing.T) {
	cfg, fw, set := catalogFixture(t, []core.ControlRef{
		{ControlID: catalogControl},
		{Framework: riskFramework, ControlID: "A.5.15"},
	})
	if err := validatePolicyControls(cfg, fw, set); err != nil {
		t.Fatalf("validatePolicyControls: %v", err)
	}
}

// Every shipped policy of every built-in framework maps only to controls
// that framework's catalog declares. This is the build-time half of the
// rule: a mistyped control in a policy builder fails here, not in a
// customer's run.
func TestValidatePolicyControls_ShippedFrameworksPass(t *testing.T) {
	ids := frameworks.IDs()
	if len(ids) == 0 {
		t.Fatal("no built-in frameworks registered")
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			factory, _ := frameworks.Lookup(id)
			set := registry.NewSet()
			if err := factory.Register(set); err != nil {
				t.Fatalf("register: %v", err)
			}
			fw, ok := set.Frameworks.Lookup(id)
			if !ok {
				t.Fatalf("framework %q not registered", id)
			}
			catalog := map[string]struct{}{}
			for _, c := range fw.Controls() {
				catalog[c.ID] = struct{}{}
			}
			if err := checkPolicyControls(fw.Policies(), id, catalog, set); err != nil {
				t.Fatalf("shipped policy maps to an unknown control: %v", err)
			}
		})
	}
}
