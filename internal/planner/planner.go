package planner

import (
	"fmt"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Input collects everything the planner needs to compute a Plan.
// CommitTime is the basis for period derivation; pass commit time
// when time_basis == "commit" (the default) and wall-clock when
// the project opts into wall_clock.
type Input struct {
	Config     *spec.ProjectConfig
	Registries *registry.Set
	CommitTime time.Time
	Now        time.Time
	Filter     Filter
}

// Filter narrows the set of policies the plan covers. The four
// fields are mutually exclusive — passing more than one yields an
// error. Filter{} means "every policy in the framework."
type Filter struct {
	Policies []string
	Controls []string
	Cadence  string
	OnPush   bool
}

// Plan computes the run plan. Errors surface back to the orchestrator
// as exit-code-3 conditions. No I/O happens here.
func Plan(in *Input) (*RunPlan, error) {
	if err := validateFilter(&in.Filter); err != nil {
		return nil, err
	}
	framework, ok := in.Registries.Frameworks.Lookup(in.Config.Framework)
	if !ok {
		return nil, fmt.Errorf("planner: framework %q not registered", in.Config.Framework)
	}
	period, err := DerivePeriod(&in.Config.Period, in.CommitTime)
	if err != nil {
		return nil, err
	}
	policies, err := planPolicies(framework, in)
	if err != nil {
		return nil, err
	}
	return &RunPlan{
		Framework: framework.ID(),
		Period:    period,
		Policies:  policies,
	}, nil
}

func validateFilter(f *Filter) error {
	count := 0
	if len(f.Policies) > 0 {
		count++
	}
	if len(f.Controls) > 0 {
		count++
	}
	if f.Cadence != "" {
		count++
	}
	if f.OnPush {
		count++
	}
	if count > 1 {
		return fmt.Errorf("planner: --policies, --controls, --cadence, --on-push are mutually exclusive (set %d of them)", count)
	}
	return nil
}

func planPolicies(framework core.Framework, in *Input) ([]PlannedPolicy, error) {
	planned := make([]PlannedPolicy, 0, len(framework.Policies()))
	for _, ref := range framework.Policies() {
		policy, ok := in.Registries.Policies.Lookup(ref.PolicyID)
		if !ok {
			return nil, fmt.Errorf("planner: framework %q references unknown policy %q", framework.ID(), ref.PolicyID)
		}
		if !filterAccepts(&policy, &in.Filter, in.Config.PolicyCadences) {
			continue
		}
		pp, err := planOne(&policy, in)
		if err != nil {
			return nil, err
		}
		planned = append(planned, pp)
	}
	return planned, nil
}

func planOne(policy *core.Policy, in *Input) (PlannedPolicy, error) {
	overrides := in.Config.PolicyParameters[policy.ID]
	params, err := resolveParameters(policy, overrides)
	if err != nil {
		return PlannedPolicy{}, err
	}
	bindings, err := resolveBindings(policy, in.Config.Bindings[policy.ID], in.Registries.Sources)
	if err != nil {
		return PlannedPolicy{}, err
	}
	exception := resolveException(policy.ID, in.Config.Exceptions, in.Now)
	cadence := resolveCadence(policy.ID, policy.Cadence, in.Config.PolicyCadences)
	return PlannedPolicy{
		Spec:       *policy,
		Cadence:    cadence,
		Parameters: params,
		Bindings:   bindings,
		Exception:  exception,
	}, nil
}

func filterAccepts(policy *core.Policy, f *Filter, cadenceOverrides map[string]string) bool {
	if len(f.Policies) > 0 {
		return containsString(f.Policies, policy.ID)
	}
	if len(f.Controls) > 0 {
		return containsString(f.Controls, policy.Control)
	}
	if f.Cadence != "" {
		effective := resolveCadence(policy.ID, policy.Cadence, cadenceOverrides)
		return effective == f.Cadence
	}
	if f.OnPush {
		return policy.OnPush
	}
	return true
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

// SplitCommaList is a small helper for the orchestrator: turn a
// comma-separated CLI flag value into a trimmed list.
func SplitCommaList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
