package planner_test

import (
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

const (
	vendorAssurancePolicy = "soc2.cc9.2.vendor_assurance"
	vendorContractsPolicy = "soc2.cc9.2.vendor_contracts_reviewed"
	cuecMappingPolicy     = "soc2.cc9.2.cuec_mapping"
	acmeCritical          = "      - {id: acme_cloud, name: Acme Cloud, tier: critical}\n"
)

// soc2VendorConfig is a SOC 2 project with a manual source and, when
// register is not empty, an experimental.vendors register of those lines.
func soc2VendorConfig(t *testing.T, register string) *spec.ProjectConfig {
	t.Helper()
	body := "schema_version: project.v1\nframework: soc2\n" +
		"sources:\n  manual.pdf:\n    backend: local\n    path: ./evidence\n"
	if register != "" {
		body += "experimental:\n  vendors:\n    declared_by: ciso@acme.example\n    declared_at: \"2026-01-05\"\n    register:\n" + register
	}
	cfg, err := spec.LoadProjectConfig([]byte(body))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	return &cfg
}

func soc2Registries(t *testing.T) *registry.Set {
	t.Helper()
	factory, ok := frameworks.Lookup("soc2")
	if !ok {
		t.Fatal("soc2 not registered")
	}
	set := registry.NewSet()
	if err := factory.Register(set); err != nil {
		t.Fatal(err)
	}
	return set
}

func stateHashes(plan *planner.RunPlan) map[string]string {
	out := make(map[string]string, len(plan.Policies))
	for i := range plan.Policies {
		out[plan.Policies[i].Spec.ID] = plan.Policies[i].StateHash
	}
	return out
}

// The vendor register decides which per-vendor folders a fan-out policy
// reads. Editing it mid-cycle must re-evaluate that policy under
// --scheduled instead of carrying forward a pass earned before the new
// vendor existed, while every policy the register does not feed keeps
// its hash and its carry-forward.
func TestPlan_CadenceGate_VendorRegisterChangeForcesEvaluate(t *testing.T) {
	set := soc2Registries(t)
	jan := time.Date(2026, 1, 10, 6, 0, 0, 0, time.UTC)
	feb := time.Date(2026, 2, 1, 6, 0, 0, 0, time.UTC)
	plan := func(register string, now time.Time, states map[string]*core.PolicyState) *planner.RunPlan {
		return mustPlan(t, &planner.Input{Config: soc2VendorConfig(t, register), Registries: set, CommitTime: now, Now: now, PolicyStates: states})
	}
	base := stateHashes(plan(acmeCritical, jan, nil))
	if base[vendorAssurancePolicy] == "" {
		t.Fatalf("%s not planned", vendorAssurancePolicy)
	}
	passedInJanuary := func(pid string) map[string]*core.PolicyState {
		return map[string]*core.PolicyState{pid: {
			Framework: fwSOC2, PolicyID: pid,
			LastRunAt: jan, LastPassAt: jan, LastRunStatus: core.StatusPass,
			LastPolicyHash: base[pid],
		}}
	}

	cases := []struct {
		name     string
		register string
		changed  []string // the policies whose hash must change; every other one must not
	}{
		{"unchanged", acmeCritical, nil},
		{"vendor added", acmeCritical + "      - {id: initech_pay, name: Initech Payments, tier: critical}\n",
			[]string{vendorAssurancePolicy, vendorContractsPolicy}},
		{"assurance period end declared", "      - {id: acme_cloud, name: Acme Cloud, tier: critical, assurance_period_end: \"2026-06-30\"}\n",
			[]string{vendorAssurancePolicy, vendorContractsPolicy}},
		{"marked subservice", "      - {id: acme_cloud, name: Acme Cloud, tier: critical, subservice: true}\n",
			[]string{cuecMappingPolicy}},
		{"register removed", "", []string{vendorAssurancePolicy, vendorContractsPolicy}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stateHashes(plan(tc.register, feb, nil))
			for pid, h := range base {
				want := !containsID(tc.changed, pid)
				if (got[pid] == h) != want {
					t.Errorf("%s: hash unchanged = %v; want %v", pid, got[pid] == h, want)
				}
			}
			for _, pid := range tc.changed {
				pp := policyByID(t, plan(tc.register, feb, passedInJanuary(pid)), pid)
				if !pp.ShouldEvaluate {
					t.Errorf("%s carried forward after the register edit (skip reason %q); want re-evaluation", pid, pp.SkipReason)
				}
			}
		})
	}

	t.Run("raised out of the low tier", func(t *testing.T) {
		low := acmeCritical + "      - {id: initech_pay, name: Initech Payments, tier: low, tier_rationale: no data access, approved_by: ciso@acme.example}\n"
		raised := acmeCritical + "      - {id: initech_pay, name: Initech Payments, tier: critical}\n"
		if stateHashes(plan(low, jan, nil))[vendorAssurancePolicy] == stateHashes(plan(raised, jan, nil))[vendorAssurancePolicy] {
			t.Error("raising a vendor out of the low tier left the state hash unchanged; its folder becomes required")
		}
	})

	t.Run("unchanged register carries forward", func(t *testing.T) {
		pp := policyByID(t, plan(acmeCritical, feb, passedInJanuary(vendorAssurancePolicy)), vendorAssurancePolicy)
		if pp.ShouldEvaluate {
			t.Errorf("unchanged register: ShouldEvaluate = true (%q); want a carry-forward", pp.SkipReason)
		}
	})
}

// Adopting a register must not rotate the hash of a policy it does not
// feed, or the release would re-evaluate every policy once for nothing.
func TestPlan_StateHash_RegisterLeavesOtherPoliciesStable(t *testing.T) {
	set := soc2Registries(t)
	now := time.Date(2026, 1, 10, 6, 0, 0, 0, time.UTC)
	without := stateHashes(mustPlan(t, &planner.Input{Config: soc2VendorConfig(t, ""), Registries: set, CommitTime: now, Now: now}))
	with := stateHashes(mustPlan(t, &planner.Input{Config: soc2VendorConfig(t, acmeCritical), Registries: set, CommitTime: now, Now: now}))
	// cuec_mapping fans out over subservice vendors only, and this
	// register has none.
	fanOut := map[string]bool{vendorAssurancePolicy: true, vendorContractsPolicy: true}
	for pid, h := range without {
		if changed := with[pid] != h; changed != fanOut[pid] {
			t.Errorf("%s: hash changed = %v when a register was adopted; want %v", pid, changed, fanOut[pid])
		}
	}
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func policyByID(t *testing.T, plan *planner.RunPlan, pid string) *planner.PlannedPolicy {
	t.Helper()
	for i := range plan.Policies {
		if plan.Policies[i].Spec.ID == pid {
			return &plan.Policies[i]
		}
	}
	t.Fatalf("%s not planned", pid)
	return nil
}
