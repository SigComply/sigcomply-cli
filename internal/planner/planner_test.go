package planner_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Identifiers repeated across the planner_test package.
const (
	fwSOC2          = "soc2"
	schemaProjectV1 = "project.v1"
	ctrlSOC2CC61    = "SOC2.CC6.1"

	slotUserDirectory = "user_directory"
	evDirectoryUser   = "directory_user"
	evRosterEntry     = "roster_entry"

	catalogMFAAttestation = "mfa_attestation"
)

// fakeFramework + fakeSource keep the test self-contained; the real
// loaders are exercised in their own packages.
type fakeFramework struct {
	id, version string
	controls    []core.Control
	policies    []core.PolicyRef
}

func (f *fakeFramework) ID() string                 { return f.id }
func (f *fakeFramework) Version() string            { return f.version }
func (f *fakeFramework) Controls() []core.Control   { return f.controls }
func (f *fakeFramework) Policies() []core.PolicyRef { return f.policies }

type fakeSource struct {
	id    string
	emits []string
}

func (s *fakeSource) ID() string                                 { return s.id }
func (s *fakeSource) Emits() []string                            { return s.emits }
func (s *fakeSource) Init(context.Context, map[string]any) error { return nil }
func (s *fakeSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

// commitFixture returns a canonical test commit time. Reused across
// tests so the period stays predictable (2026-Q1).
func commitFixture(t *testing.T) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, "2026-02-15T13:55:00Z")
	if err != nil {
		t.Fatalf("time.Parse fixture: %v", err)
	}
	return v
}

func setUp(t *testing.T) *registry.Set {
	t.Helper()
	set := registry.NewSet()
	policy := core.Policy{
		ID:          ordinaryPolicyID,
		Controls:    []core.ControlRef{{ControlID: ctrlSOC2CC61}},
		Description: "MFA",
		Severity:    core.SeverityHigh,
		Cadence:     cadenceDaily,
		OnPush:      true,
		RuleRef:     "rules.mfa_enforced.v1",
		Slots: map[string]core.Slot{
			slotUserDirectory: {
				Accepts:     []string{evDirectoryUser},
				Cardinality: core.SlotOneOrMore,
				Required:    true,
			},
		},
		Parameters: map[string]core.ParameterSpec{
			"exempt_service_accounts": {Type: "bool", Default: true},
		},
	}
	if err := set.Policies.Register(policy); err != nil {
		t.Fatalf("register policy: %v", err)
	}
	fw := &fakeFramework{
		id: fwSOC2, version: "2017",
		policies: []core.PolicyRef{{PolicyID: policy.ID}},
		controls: []core.Control{{ID: ctrlSOC2CC61, Name: "Logical Access"}},
	}
	if err := set.Frameworks.Register(fw); err != nil {
		t.Fatalf("register framework: %v", err)
	}
	if err := set.Sources.Register(&fakeSource{id: srcAWSIAMID, emits: []string{evDirectoryUser}}); err != nil {
		t.Fatalf("register aws.iam: %v", err)
	}
	if err := set.Sources.Register(&fakeSource{id: srcOktaID, emits: []string{evDirectoryUser}}); err != nil {
		t.Fatalf("register okta: %v", err)
	}
	return set
}

// TestPlan_PopulatesCoverageGaps wires a policy whose required slot
// accepts only directory_user.v2 while the project configures an okta
// source emitting directory_user (v1) and supplies no binding. The plan
// must surface the version-skew coverage gap rather than silently
// planning the policy for a guaranteed skip.
func TestPlan_PopulatesCoverageGaps(t *testing.T) {
	set := registry.NewSet()
	policy := core.Policy{
		ID:           "soc2.cc6.1.mfa_enforced_admins",
		Controls:     []core.ControlRef{{ControlID: ctrlSOC2CC61}},
		Description:  "MFA on admins",
		Severity:     core.SeverityHigh,
		Cadence:      cadenceDaily,
		EvidenceMode: core.EvidenceModeAutomated,
		RuleRef:      "rules.mfa_enforced_admins.v1",
		Slots: map[string]core.Slot{
			slotUserDirectory: {
				Accepts:     []string{"directory_user.v2"},
				Cardinality: core.SlotOneOrMore,
				Required:    true,
			},
		},
	}
	if err := set.Policies.Register(policy); err != nil {
		t.Fatalf("register policy: %v", err)
	}
	fw := &fakeFramework{
		id: fwSOC2, version: "2017",
		policies: []core.PolicyRef{{PolicyID: policy.ID}},
		controls: []core.Control{{ID: ctrlSOC2CC61, Name: "Logical Access"}},
	}
	if err := set.Frameworks.Register(fw); err != nil {
		t.Fatalf("register framework: %v", err)
	}
	if err := set.Sources.Register(&fakeSource{id: srcOktaID, emits: []string{evDirectoryUser, "okta_app"}}); err != nil {
		t.Fatalf("register okta: %v", err)
	}

	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1,
		Framework:     fwSOC2,
		Period:        spec.PeriodConfig{FiscalCalendar: spec.FiscalCalendarConfig{Type: fiscalCalendarQuarter}},
		Sources:       map[string]map[string]any{srcOktaID: {}},
		// No bindings: the slot cannot bind okta (v1) and stays empty.
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{Config: cfg, Registries: set, CommitTime: commit, Now: commit})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 1 {
		t.Fatalf("Policies = %d; want 1", len(plan.Policies))
	}
	gaps := plan.Policies[0].CoverageGaps
	if len(gaps) != 1 {
		t.Fatalf("CoverageGaps = %d; want 1 (%+v)", len(gaps), gaps)
	}
	if gaps[0].Source != srcOktaID || gaps[0].Slot != slotUserDirectory {
		t.Errorf("gap = %+v; want source=okta slot=user_directory", gaps[0])
	}
}

func TestPlan_HappyPath(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1,
		Framework:     fwSOC2,
		Period: spec.PeriodConfig{
			FiscalCalendar: spec.FiscalCalendarConfig{Type: fiscalCalendarQuarter},
		},
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {
				Bindings:   map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}, {Source: srcOktaID}}},
				Parameters: map[string]any{"exempt_service_accounts": false},
				Cadence:    cadenceHourly,
			},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config:     cfg,
		Registries: set,
		CommitTime: commit,
		Now:        commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Period.ID != period2026Q1 {
		t.Errorf("Period.ID = %q; want 2026-Q1", plan.Period.ID)
	}
	if len(plan.Policies) != 1 {
		t.Fatalf("Policies length = %d; want 1", len(plan.Policies))
	}
	pp := plan.Policies[0]
	if pp.Cadence != cadenceHourly {
		t.Errorf("Cadence = %q; want hourly", pp.Cadence)
	}
	exempt, ok := pp.Parameters["exempt_service_accounts"].(bool)
	if !ok || exempt {
		t.Errorf("override not applied: %v", pp.Parameters["exempt_service_accounts"])
	}
	bs := pp.Bindings[slotUserDirectory]
	if len(bs) != 2 {
		t.Fatalf("bindings count = %d; want 2", len(bs))
	}
	if bs[0].SourceID != srcAWSIAMID || bs[1].SourceID != srcOktaID {
		t.Errorf("binding order/sources mismatched: %+v", bs)
	}
}

func TestPlan_RejectsUnknownSource(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Vault: spec.VaultConfig{Backend: "local", Config: map[string]any{"path": "."}},
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {Bindings: map[string][]spec.BindingEntry{
				slotUserDirectory: {{Source: "mystery.source"}},
			}},
		},
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "mystery.source") {
		t.Errorf("expected unknown-source error; got %v", err)
	}
}

func TestPlan_RejectsSourceWrongEvidenceType(t *testing.T) {
	set := setUp(t)
	if err := set.Sources.Register(&fakeSource{id: "gcs.storage", emits: []string{"storage_bucket"}}); err != nil {
		t.Fatalf("register gcs.storage: %v", err)
	}
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Vault: spec.VaultConfig{Backend: "local", Config: map[string]any{"path": "."}},
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {Bindings: map[string][]spec.BindingEntry{
				slotUserDirectory: {{Source: "gcs.storage"}},
			}},
		},
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "none of which is in slot Accepts") {
		t.Errorf("expected slot/source evidence-type mismatch error; got %v", err)
	}
}

func TestPlan_RejectsUnknownPolicyKey(t *testing.T) {
	// A typo'd policy ID under policies: would otherwise silently no-op
	// (the override never applies). It must be a loud error with a
	// did-you-mean suggestion. (P1.1 cross-reference validation.)
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			"soc2.cc6.1.mfa_enforce": {Cadence: cadenceHourly}, // missing trailing 'd'
		},
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
	})
	if err == nil {
		t.Fatal("expected error for unknown policy key; got nil")
	}
	if !strings.Contains(err.Error(), "no such policy") || !strings.Contains(err.Error(), "did you mean") {
		t.Errorf("error = %q; want 'no such policy' with a did-you-mean suggestion", err.Error())
	}
	if !strings.Contains(err.Error(), ordinaryPolicyID) {
		t.Errorf("error = %q; want it to suggest the correct policy ID", err.Error())
	}
}

func TestPlan_RejectsUnknownControlKey(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Controls: map[string]spec.ControlConfig{
			"CC99.9": {Applicability: "not_applicable", Reason: "typo'd control"},
		},
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "no such control") {
		t.Errorf("expected 'no such control' error; got %v", err)
	}
}

func TestPlan_FilterByPolicy(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {Bindings: map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}}},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Policies: []string{"nope.no-such-policy"}},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 0 {
		t.Errorf("Policies = %d; want 0 (filter should reject)", len(plan.Policies))
	}
}

func TestPlan_FilterByCadence(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {Bindings: map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}}},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadence: cadenceDaily},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 1 {
		t.Errorf("cadence=daily should match (policy's cadence is daily); got %d", len(plan.Policies))
	}
	plan, err = planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadence: cadenceWeekly},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 0 {
		t.Errorf("cadence=weekly should not match (policy's cadence is daily); got %d", len(plan.Policies))
	}
}

func TestPlan_FilterByCadences_SetIntersection(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {Bindings: map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}}},
		},
	}
	commit := commitFixture(t)

	// Policy is cadence=daily + on_push=true (see setUp). Effective cadences = {daily, on_push}.
	cases := []struct {
		name     string
		cadences []string
		want     int
	}{
		{"matches daily via Cadences", []string{cadenceDaily}, 1},
		{"matches on_push via Cadences", []string{core.CadenceOnPush}, 1},
		{"matches when at least one element intersects", []string{cadenceWeekly, cadenceDaily}, 1},
		{"no match when set disjoint", []string{cadenceWeekly, cadenceMonthly}, 0},
		{"matches on_push even when scheduled-only cadences listed", []string{cadenceWeekly, core.CadenceOnPush}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planner.Plan(&planner.Input{
				Config: cfg, Registries: set, CommitTime: commit, Now: commit,
				Filter: planner.Filter{Cadences: tc.cadences},
			})
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			if len(plan.Policies) != tc.want {
				t.Errorf("Cadences=%v: got %d policies; want %d", tc.cadences, len(plan.Policies), tc.want)
			}
		})
	}
}

func TestPlan_FilterByCadences_RespectsOverride(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			// Override base cadence from daily → hourly.
			ordinaryPolicyID: {
				Bindings: map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}},
				Cadence:  cadenceHourly,
			},
		},
	}
	commit := commitFixture(t)

	// With the override, {daily} no longer matches but {hourly} does.
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadences: []string{cadenceDaily}},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 0 {
		t.Errorf("override should hide daily; got %d policies", len(plan.Policies))
	}
	plan, err = planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
		Filter: planner.Filter{Cadences: []string{cadenceHourly}},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 1 {
		t.Errorf("override should expose hourly; got %d policies", len(plan.Policies))
	}
}

func TestPlan_FilterMutualExclusionEnforced(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
		Filter: planner.Filter{
			Policies: []string{"x"},
			Cadence:  cadenceDaily,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual-exclusion error; got %v", err)
	}
}

func TestPlan_ExceptionApplied(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {
				Bindings:   map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}},
				Exceptions: []spec.PolicyException{{State: "waived", Reason: "Legacy."}},
			},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Policies[0].Exception == nil {
		t.Fatal("expected exception applied; got nil")
	}
	if plan.Policies[0].Exception.State != core.StatusWaived {
		t.Errorf("Exception.State = %q; want waived", plan.Policies[0].Exception.State)
	}
}

func TestPlan_PolicyOverride_AutomatedToManual(t *testing.T) {
	// Flip an automated policy (mfa_enforced, has slots) to manual.
	// The planner should produce a synthetic _manual binding and set
	// EvidenceModeOverridden=true, without requiring any bindings in the
	// project config.
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1,
		Framework:     fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {
				EvidenceMode: "manual",
				CatalogEntry: catalogMFAAttestation,
			},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Policies) != 1 {
		t.Fatalf("Policies length = %d; want 1", len(plan.Policies))
	}
	pp := plan.Policies[0]
	if pp.Spec.EvidenceMode != core.EvidenceModeManual {
		t.Errorf("Spec.EvidenceMode = %q; want manual", pp.Spec.EvidenceMode)
	}
	if pp.Spec.CatalogEntry != catalogMFAAttestation {
		t.Errorf("Spec.CatalogEntry = %q; want mfa_attestation", pp.Spec.CatalogEntry)
	}
	if !pp.EvidenceModeOverridden {
		t.Error("EvidenceModeOverridden = false; want true")
	}
	manualBindings, ok := pp.Bindings[spec.ManualSlotName]
	if !ok || len(manualBindings) != 1 {
		t.Fatalf("expected 1 binding under %q; got %v", spec.ManualSlotName, pp.Bindings)
	}
	if manualBindings[0].SourceID != "manual.pdf" {
		t.Errorf("Binding.SourceID = %q; want manual.pdf", manualBindings[0].SourceID)
	}
	if manualBindings[0].CatalogID != catalogMFAAttestation {
		t.Errorf("Binding.CatalogID = %q; want mfa_attestation", manualBindings[0].CatalogID)
	}
}

func TestPlan_PolicyOverride_AutomatedToManual_RejectsExplicitBindings(t *testing.T) {
	// Binding entries for a manually-overridden policy are a configuration
	// error — the planner creates the synthetic _manual binding itself.
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1,
		Framework:     fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {
				EvidenceMode: "manual",
				CatalogEntry: catalogMFAAttestation,
				Bindings:     map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}},
			},
		},
	}
	_, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: time.Now(), Now: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "must not declare bindings") {
		t.Errorf("expected 'must not declare bindings' error; got %v", err)
	}
}

func TestPlan_PolicyOverride_ManualToAutomated(t *testing.T) {
	// Flip a manual policy to automated. The planner should use the
	// automated binding-resolution path and clear CatalogEntry.
	set := setUp(t)
	manualPolicy := core.Policy{
		ID:           "soc2.cc6.1.access_review",
		Controls:     []core.ControlRef{{ControlID: ctrlSOC2CC61}},
		EvidenceMode: core.EvidenceModeManual,
		CatalogEntry: "access_review_quarterly",
		Cadence:      cadenceQuarterly,
		Slots: map[string]core.Slot{
			"review_doc": {
				Accepts:     []string{evDirectoryUser},
				Cardinality: core.SlotOneOrMore,
				Required:    true,
			},
		},
	}
	if err := set.Policies.Register(manualPolicy); err != nil {
		t.Fatalf("register manual policy: %v", err)
	}
	fw := &fakeFramework{
		id: fwSOC2, version: "2017",
		policies: []core.PolicyRef{{PolicyID: manualPolicy.ID}},
	}
	// Replace the framework so only the manual policy is exercised.
	set2 := registry.NewSet()
	if err := set2.Policies.Register(manualPolicy); err != nil {
		t.Fatalf("register policy: %v", err)
	}
	if err := set2.Frameworks.Register(fw); err != nil {
		t.Fatalf("register framework: %v", err)
	}
	if err := set2.Sources.Register(&fakeSource{id: srcAWSIAMID, emits: []string{evDirectoryUser}}); err != nil {
		t.Fatalf("register source: %v", err)
	}

	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1,
		Framework:     fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			"soc2.cc6.1.access_review": {
				EvidenceMode: "automated",
				Bindings:     map[string][]spec.BindingEntry{"review_doc": {{Source: srcAWSIAMID}}},
			},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set2, CommitTime: commit, Now: commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	pp := plan.Policies[0]
	if pp.Spec.EvidenceMode != core.EvidenceModeAutomated {
		t.Errorf("Spec.EvidenceMode = %q; want automated", pp.Spec.EvidenceMode)
	}
	if pp.Spec.CatalogEntry != "" {
		t.Errorf("Spec.CatalogEntry = %q; want empty", pp.Spec.CatalogEntry)
	}
	if !pp.EvidenceModeOverridden {
		t.Error("EvidenceModeOverridden = false; want true")
	}
	if _, ok := pp.Bindings["review_doc"]; !ok {
		t.Error("expected automated bindings under review_doc slot")
	}
}

func TestPlan_PolicyOverride_NotOverridden_WhenNoEntry(t *testing.T) {
	// Policies with no override entry should have EvidenceModeOverridden=false.
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1,
		Framework:     fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {Bindings: map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}}},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Policies[0].EvidenceModeOverridden {
		t.Error("EvidenceModeOverridden = true; want false when no override declared")
	}
}

func TestPlan_ExpiredExceptionSkipped(t *testing.T) {
	set := setUp(t)
	cfg := &spec.ProjectConfig{
		SchemaVersion: schemaProjectV1, Framework: fwSOC2,
		Policies: map[string]spec.PolicyConfig{
			ordinaryPolicyID: {
				Bindings:   map[string][]spec.BindingEntry{slotUserDirectory: {{Source: srcAWSIAMID}}},
				Exceptions: []spec.PolicyException{{State: "waived", Reason: "Expired.", ExpiresAt: "2025-01-01"}},
			},
		},
	}
	commit := commitFixture(t)
	plan, err := planner.Plan(&planner.Input{
		Config: cfg, Registries: set, CommitTime: commit, Now: commit,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Policies[0].Exception != nil {
		t.Errorf("expired exception should not apply; got %+v", plan.Policies[0].Exception)
	}
}
