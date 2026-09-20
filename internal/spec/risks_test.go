package spec_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// loadRisks is the common path under test: parse a full project config,
// then project its experimental.risks block.
func loadRisks(t *testing.T, body string) (*spec.RiskRegister, error) {
	t.Helper()
	cfg, err := spec.LoadProjectConfig([]byte(body))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	return spec.LoadRiskRegister(&cfg)
}

const (
	riskIDOne     = "r-001"
	riskIDTwo     = "r-002"
	riskOwnerCISO = "ciso@example.com"

	// Shared with vendors_test.go / scope_test.go: the same two
	// validations are asserted against all three registers.
	wantBadIDLength   = "must be 1-40 characters"
	caseBadDeclaredAt = "bad declared_at"
)

const risksBase = `schema_version: project.v1
framework: iso27001
sources:
  aws.iam: {}
`

// A well-formed register with one risk of each interesting shape.
const risksFull = `experimental:
  risks:
    declared_by: ciso@example.com
    declared_at: "2026-09-20"
    register:
      - id: r-002
        description: Laptop theft exposes unencrypted customer data.
        owner: ciso@example.com
        level: high
        treatment: modify
        controls: [A.8.1, A.8.24]
        residual_level: low
        assessed_at: "2026-06-01"
      - id: r-001
        description: Residual risk of a supplier outage.
        owner: cto@example.com
        level: moderate
        treatment: retain
        accepted_by: ceo@example.com
        acceptance_rationale: Outage tolerance is within the agreed RTO.
        residual_level: moderate
        assessed_at: "2026-06-01"
`

func TestLoadRiskRegister_AbsentIsUndeclared(t *testing.T) {
	reg, err := loadRisks(t, risksBase)
	if err != nil {
		t.Fatalf("LoadRiskRegister: %v", err)
	}
	if reg != nil {
		t.Fatalf("register = %+v; want nil when experimental.risks is absent", reg)
	}
	// The nil register must be safe to use without a guard at every site.
	if reg.Declared() || reg.ControlRisks() != nil || len(reg.DeclaredControls()) != 0 {
		t.Error("nil register must read as undeclared with no control edges")
	}
}

func TestLoadRiskRegister_Full(t *testing.T) {
	reg, err := loadRisks(t, risksBase+risksFull)
	if err != nil {
		t.Fatalf("LoadRiskRegister: %v", err)
	}
	if !reg.Declared() || len(reg.Risks) != 2 {
		t.Fatalf("register = %+v; want 2 risks", reg)
	}
	// Sorted by ID, like the vendor register.
	if reg.Risks[0].ID != riskIDOne || reg.Risks[1].ID != riskIDTwo {
		t.Errorf("risks not sorted by id: %s, %s", reg.Risks[0].ID, reg.Risks[1].ID)
	}
	if reg.DeclaredBy != riskOwnerCISO || reg.DeclaredAt != "2026-09-20" {
		t.Errorf("audit trail = %q/%q", reg.DeclaredBy, reg.DeclaredAt)
	}
	if reg.Risks[0].AcceptedBy != "ceo@example.com" {
		t.Errorf("accepted_by = %q", reg.Risks[0].AcceptedBy)
	}
}

// The edge the Statement of Applicability joins on.
func TestRiskRegister_ControlRisks(t *testing.T) {
	reg, err := loadRisks(t, risksBase+risksFull)
	if err != nil {
		t.Fatalf("LoadRiskRegister: %v", err)
	}
	got := reg.ControlRisks()
	want := map[string][]string{"A.8.1": {riskIDTwo}, "A.8.24": {riskIDTwo}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ControlRisks() = %v; want %v", got, want)
	}
	if ctrls := reg.DeclaredControls(); !reflect.DeepEqual(ctrls, []string{"A.8.1", "A.8.24"}) {
		t.Errorf("DeclaredControls() = %v", ctrls)
	}
}

// Two risks treated by the same control must both be cited, sorted.
func TestRiskRegister_ControlRisks_ManyRisksOneControl(t *testing.T) {
	reg, err := loadRisks(t, risksBase+`experimental:
  risks:
    register:
      - id: r-zeta
        description: A
        owner: a@example.com
        level: low
        treatment: modify
        controls: [A.8.1]
        residual_level: low
        assessed_at: "2026-01-01"
      - id: r-alpha
        description: B
        owner: b@example.com
        level: low
        treatment: modify
        controls: [A.8.1]
        residual_level: low
        assessed_at: "2026-01-01"
`)
	if err != nil {
		t.Fatalf("LoadRiskRegister: %v", err)
	}
	if got := reg.ControlRisks()["A.8.1"]; !reflect.DeepEqual(got, []string{"r-alpha", "r-zeta"}) {
		t.Errorf("A.8.1 risks = %v; want both, sorted", got)
	}
}

func TestLoadRiskRegister_UnknownSubkeysTolerated(t *testing.T) {
	reg, err := loadRisks(t, risksBase+`experimental:
  risks:
    registry:
      - id: typo
    register:
      - id: r-001
        description: A
        owner: a@example.com
        level: low
        treatment: avoid
        residual_level: low
        assessed_at: "2026-01-01"
`)
	if err != nil {
		t.Fatalf("LoadRiskRegister: %v", err)
	}
	if !reflect.DeepEqual(reg.UnknownKeys, []string{"registry"}) {
		t.Errorf("UnknownKeys = %v; want [registry] — a typo must be reported, not silently ignored", reg.UnknownKeys)
	}
}

func TestLoadRiskRegister_Errors(t *testing.T) {
	const risk = `
      - id: r-001
        description: A risk.
        owner: a@example.com
        level: high
        treatment: modify
        controls: [A.8.1]
        residual_level: low
        assessed_at: "2026-01-01"`

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty register",
			body: "experimental:\n  risks:\n    register: []\n",
			want: "must list at least one risk",
		},
		{
			name: "register is not a list",
			body: "experimental:\n  risks:\n    register: nope\n",
			want: "must be a list of risks",
		},
		{
			name: "missing id",
			body: "experimental:\n  risks:\n    register:\n      - description: A\n",
			want: `missing required field "id"`,
		},
		{
			name: "bad id",
			body: "experimental:\n  risks:\n    register:\n      - id: 'Not A Slug'\n",
			want: wantBadIDLength,
		},
		{
			name: "duplicate id",
			body: "experimental:\n  risks:\n    register:" + risk + risk,
			want: `duplicate risk id "r-001"`,
		},
		{
			name: "missing description",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n",
			want: `missing required field "description"`,
		},
		{
			name: "missing owner",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n",
			want: "6.1.2 requires every risk to have an identified owner",
		},
		{
			name: "bad level",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: spicy\n",
			want: `level: invalid value "spicy"`,
		},
		{
			name: "bad residual level",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: mild\n",
			want: `residual_level: invalid value "mild"`,
		},
		{
			name: "bad treatment",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: low\n        treatment: ignore\n",
			want: `treatment: invalid value "ignore"`,
		},
		{
			// "Modify" means "apply controls". Without any, the risk
			// names no treatment and joins to nothing in the SoA.
			name: "modify with no controls",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: low\n        treatment: modify\n",
			want: `requires at least one entry in "controls"`,
		},
		{
			// Retain is the one option that files no control, so the
			// signature is the evidence — the same asymmetry a low-tier
			// vendor carries.
			name: "retain without accepted_by",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: high\n        treatment: retain\n",
			want: `requires "accepted_by"`,
		},
		{
			name: "retain without acceptance_rationale",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: high\n        treatment: retain\n        accepted_by: ceo@example.com\n",
			want: `requires "acceptance_rationale"`,
		},
		{
			name: "empty control entry",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: low\n        treatment: modify\n        controls: [\"\"]\n",
			want: "controls[0] is empty",
		},
		{
			name: "missing assessed_at",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: low\n        treatment: avoid\n",
			want: `missing required field "assessed_at"`,
		},
		{
			name: "bad assessed_at",
			body: "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        owner: a@example.com\n        level: high\n        residual_level: low\n        treatment: avoid\n        assessed_at: yesterday\n",
			want: "is not an ISO 8601 date",
		},
		{
			name: caseBadDeclaredAt,
			body: "experimental:\n  risks:\n    declared_at: soon\n    register:" + risk,
			want: "declared_at:",
		},
		{
			name: "risks is not a mapping",
			body: "experimental:\n  risks: nope\n",
			want: "must be a mapping",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadRisks(t, risksBase+tc.body)
			if err == nil {
				t.Fatalf("expected an error containing %q; got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v; want it to contain %q", err, tc.want)
			}
		})
	}
}

// A level must never decide whether an obligation exists — only which
// one. Every level must demand the same required fields, or the register
// becomes an opt-out: declare everything "low" and the checks go away.
func TestLoadRiskRegister_LevelNeverShedsAnObligation(t *testing.T) {
	for _, level := range []string{
		spec.RiskLevelCritical, spec.RiskLevelHigh, spec.RiskLevelModerate, spec.RiskLevelLow,
	} {
		t.Run(level, func(t *testing.T) {
			// Same risk, only the level differs: owner still required.
			body := "experimental:\n  risks:\n    register:\n      - id: r-001\n        description: A\n        level: " + level + "\n"
			if _, err := loadRisks(t, risksBase+body); err == nil ||
				!strings.Contains(err.Error(), "owner") {
				t.Errorf("level %q: error = %v; want owner still required at every level", level, err)
			}
		})
	}
}
