package spec_test

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// loadVendors is the common path under test: parse a full project
// config, then project its experimental.vendors block.
func loadVendors(t *testing.T, body string) (*spec.VendorRegister, error) {
	t.Helper()
	cfg, err := spec.LoadProjectConfig([]byte(body))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	return spec.LoadVendorRegister(&cfg)
}

const vendorsBase = `schema_version: project.v1
framework: soc2
sources:
  aws.iam: {}
`

func TestLoadVendorRegister_AbsentIsUndeclared(t *testing.T) {
	reg, err := loadVendors(t, vendorsBase)
	if err != nil {
		t.Fatalf("LoadVendorRegister: %v", err)
	}
	if reg != nil {
		t.Fatalf("register = %+v; want nil when experimental.vendors is absent", reg)
	}
}

func TestLoadVendorRegister_ExperimentalWithoutVendorsIsUndeclared(t *testing.T) {
	reg, err := loadVendors(t, vendorsBase+`experimental:
  scope:
    required_sources: [aws.iam]
`)
	if err != nil {
		t.Fatalf("LoadVendorRegister: %v", err)
	}
	if reg != nil {
		t.Fatalf("register = %+v; want nil", reg)
	}
}

func TestLoadVendorRegister_Full(t *testing.T) {
	reg, err := loadVendors(t, vendorsBase+`experimental:
  vendors:
    declared_by: ciso@example.com
    declared_at: "2026-09-19"
    register:
      - id: zeta_analytics
        name: Zeta Analytics
        tier: low
        tier_rationale: Marketing newsletter tool; no customer data.
        approved_by: ciso@example.com
      - id: acme_cloud
        name: Acme Cloud
        tier: critical
        subservice: true
        services: Production hosting
        assurance_period_end: "2026-06-30"
`)
	if err != nil {
		t.Fatalf("LoadVendorRegister: %v", err)
	}
	if reg.DeclaredBy != "ciso@example.com" || reg.DeclaredAt != "2026-09-19" {
		t.Fatalf("declared_by/at = %q/%q", reg.DeclaredBy, reg.DeclaredAt)
	}
	// Sorted by ID on load, not in file order.
	if len(reg.Vendors) != 2 {
		t.Fatalf("len(Vendors) = %d; want 2", len(reg.Vendors))
	}
	if reg.Vendors[0].ID != "acme_cloud" || reg.Vendors[1].ID != "zeta_analytics" {
		t.Fatalf("vendors not sorted by id: %q, %q", reg.Vendors[0].ID, reg.Vendors[1].ID)
	}
	acme := reg.Vendors[0]
	if acme.Name != "Acme Cloud" || acme.Tier != spec.TierCritical || !acme.Subservice || acme.Services != "Production hosting" {
		t.Fatalf("acme_cloud = %+v", acme)
	}
	if acme.AssurancePeriodEnd != "2026-06-30" {
		t.Fatalf("acme_cloud.AssurancePeriodEnd = %q", acme.AssurancePeriodEnd)
	}
	if reg.Vendors[1].Subservice {
		t.Fatalf("zeta_analytics.Subservice = true; want false by default")
	}
}

// Every tier but low owes an uploaded artifact. Low is an approved
// exemption, not an absence — see the tier constants.
func TestLoadVendorRegister_EvidencedVendorsExcludesOnlyLow(t *testing.T) {
	reg, err := loadVendors(t, vendorsBase+`experimental:
  vendors:
    register:
      - {id: a_crit, name: A, tier: critical}
      - {id: b_high, name: B, tier: high}
      - {id: c_mod, name: C, tier: moderate}
      - {id: d_low, name: D, tier: low, tier_rationale: No data access., approved_by: a@b.com}
`)
	if err != nil {
		t.Fatalf("LoadVendorRegister: %v", err)
	}
	got := reg.EvidencedVendors()
	if len(got) != 3 {
		t.Fatalf("EvidencedVendors() = %d entries; want 3 (all but low)", len(got))
	}
	if got[0].ID != "a_crit" || got[1].ID != "b_high" || got[2].ID != "c_mod" {
		t.Fatalf("EvidencedVendors() = %q, %q, %q", got[0].ID, got[1].ID, got[2].ID)
	}
}

func TestLoadVendorRegister_SubserviceVendors(t *testing.T) {
	reg, err := loadVendors(t, vendorsBase+`experimental:
  vendors:
    register:
      - {id: a_crit, name: A, tier: critical, subservice: true}
      - {id: b_high, name: B, tier: high}
`)
	if err != nil {
		t.Fatalf("LoadVendorRegister: %v", err)
	}
	got := reg.SubserviceVendors()
	if len(got) != 1 || got[0].ID != "a_crit" {
		t.Fatalf("SubserviceVendors() = %+v; want just a_crit", got)
	}
}

// A nil register must be safe to call through — the undeclared case
// reaches these on every run that has no vendors block.
func TestVendorRegister_NilAccessors(t *testing.T) {
	var reg *spec.VendorRegister
	if got := reg.EvidencedVendors(); got != nil {
		t.Fatalf("EvidencedVendors() on nil = %v; want nil", got)
	}
	if got := reg.SubserviceVendors(); got != nil {
		t.Fatalf("SubserviceVendors() on nil = %v; want nil", got)
	}
}

func TestLoadVendorRegister_UnknownSubkeysTolerated(t *testing.T) {
	reg, err := loadVendors(t, vendorsBase+`experimental:
  vendors:
    register:
      - {id: acme_cloud, name: Acme Cloud, tier: high}
    reminder_lead_days: 30
`)
	if err != nil {
		t.Fatalf("LoadVendorRegister: %v", err)
	}
	if len(reg.UnknownKeys) != 1 || reg.UnknownKeys[0] != "reminder_lead_days" {
		t.Fatalf("UnknownKeys = %v; want [reminder_lead_days]", reg.UnknownKeys)
	}
}

func TestLoadVendorRegister_Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "not a mapping",
			body: "experimental:\n  vendors: [a, b]\n",
			want: "must be a mapping",
		},
		{
			name: "register not a list",
			body: "experimental:\n  vendors:\n    register: acme\n",
			want: "must be a list of vendors",
		},
		{
			name: "empty register",
			body: "experimental:\n  vendors:\n    declared_by: a@b.com\n",
			want: "must list at least one vendor",
		},
		{
			name: "missing id",
			body: "experimental:\n  vendors:\n    register:\n      - {name: Acme, tier: high}\n",
			want: `missing required field "id"`,
		},
		{
			name: "bad id characters",
			body: "experimental:\n  vendors:\n    register:\n      - {id: Acme Cloud, name: Acme, tier: high}\n",
			want: wantBadIDLength,
		},
		{
			name: "id too long",
			body: "experimental:\n  vendors:\n    register:\n      - {id: " + strings.Repeat("a", 41) + ", name: Acme, tier: high}\n",
			want: wantBadIDLength,
		},
		{
			name: "duplicate id",
			body: "experimental:\n  vendors:\n    register:\n      - {id: acme, name: Acme, tier: high}\n      - {id: acme, name: Acme Two, tier: low}\n",
			want: "duplicate vendor id",
		},
		{
			name: "missing name",
			body: "experimental:\n  vendors:\n    register:\n      - {id: acme, tier: high}\n",
			want: `missing required field "name"`,
		},
		{
			name: "missing tier",
			body: "experimental:\n  vendors:\n    register:\n      - {id: acme, name: Acme}\n",
			want: "tier: invalid value",
		},
		{
			name: "bad tier",
			body: "experimental:\n  vendors:\n    register:\n      - {id: acme, name: Acme, tier: severe}\n",
			want: "tier: invalid value",
		},
		{
			name: "low tier without rationale",
			body: "experimental:\n  vendors:\n    register:\n      - {id: acme, name: Acme, tier: low}\n",
			want: `requires "tier_rationale"`,
		},
		{
			name: "low tier without approver",
			body: "experimental:\n  vendors:\n    register:\n      - {id: acme, name: Acme, tier: low, tier_rationale: No data.}\n",
			want: `requires "approved_by"`,
		},
		{
			name: "bad assurance_period_end",
			body: "experimental:\n  vendors:\n    register:\n      - {id: acme, name: Acme, tier: high, assurance_period_end: last June}\n",
			want: "assurance_period_end",
		},
		{
			name: caseBadDeclaredAt,
			body: "experimental:\n  vendors:\n    declared_at: yesterday\n    register:\n      - {id: acme, name: Acme, tier: high}\n",
			want: "declared_at",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadVendors(t, vendorsBase+tc.body)
			if err == nil {
				t.Fatalf("LoadVendorRegister: want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v; want it to contain %q", err, tc.want)
			}
		})
	}
}
