package planner

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

const testFrameworkID = "soc2"

func vendorCfg(sources map[string]map[string]any, register []any, extra map[string]any) *spec.ProjectConfig {
	vendors := map[string]any{"register": register}
	for k, v := range extra {
		vendors[k] = v
	}
	return &spec.ProjectConfig{
		Framework:    testFrameworkID,
		Sources:      sources,
		Experimental: map[string]any{spec.VendorsKey: vendors},
	}
}

func entry(id string, providers ...string) map[string]any { //nolint:unparam // one vendor id is enough for every case here
	e := map[string]any{"id": id, "name": strings.ToUpper(id), "tier": spec.TierCritical}
	if len(providers) > 0 {
		ps := make([]any, 0, len(providers))
		for _, p := range providers {
			ps = append(ps, p)
		}
		e["providers"] = ps
	}
	return e
}

// An undeclared register means the feature was never adopted — nothing
// to be incomplete about.
func TestVendorWarnings_SilentWithoutRegister(t *testing.T) {
	cfg := &spec.ProjectConfig{Framework: testFrameworkID, Sources: map[string]map[string]any{"aws.iam": {}}}
	if got := VendorWarnings(cfg); got != nil {
		t.Errorf("VendorWarnings = %v; want nil", got)
	}
}

// The gap the check exists to close: a configured source nobody declared.
func TestVendorWarnings_NamesUnclaimedSource(t *testing.T) {
	cfg := vendorCfg(
		map[string]map[string]any{"aws.iam": {}, "github": {}},
		[]any{entry("acme_cloud", "aws")},
		nil,
	)
	got := strings.Join(VendorWarnings(cfg), "\n")
	if !strings.Contains(got, `source "github" is configured but no register entry claims it`) {
		t.Errorf("warnings = %q; want github named", got)
	}
	if strings.Contains(got, `source "aws.iam"`) {
		t.Errorf("warnings = %q; aws.iam is claimed via the aws provider token", got)
	}
}

// A full source ID is as good a claim as the provider token, and a
// bracketed instance joins on its base.
func TestVendorWarnings_MatchesFullIDAndInstances(t *testing.T) {
	cfg := vendorCfg(
		map[string]map[string]any{"aws.iam[prod]": {}, "aws.s3[prod]": {}},
		[]any{entry("acme_cloud", "aws.iam")},
		nil,
	)
	got := strings.Join(VendorWarnings(cfg), "\n")
	if strings.Contains(got, "aws.iam[prod]") {
		t.Errorf("warnings = %q; aws.iam[prod] joins on its base", got)
	}
	if !strings.Contains(got, "aws.s3[prod]") {
		t.Errorf("warnings = %q; want aws.s3[prod] unclaimed", got)
	}
}

// The evidence bucket is not a supplier.
func TestVendorWarnings_ExemptsManualAndTest(t *testing.T) {
	cfg := vendorCfg(
		map[string]map[string]any{"manual.pdf": {}, "test": {}},
		[]any{entry("acme_cloud")},
		nil,
	)
	if got := VendorWarnings(cfg); len(got) != 0 {
		t.Errorf("VendorWarnings = %v; want none", got)
	}
}

// UnknownKeys were loaded but never read before this.
func TestVendorWarnings_ReportsUnknownSubkey(t *testing.T) {
	cfg := vendorCfg(
		map[string]map[string]any{},
		[]any{entry("acme_cloud")},
		map[string]any{"declaredby": "someone@example.com"},
	)
	got := strings.Join(VendorWarnings(cfg), "\n")
	if !strings.Contains(got, "ignoring unrecognized key experimental.vendors.declaredby") {
		t.Errorf("warnings = %q; want the unrecognized-key warning", got)
	}
}
