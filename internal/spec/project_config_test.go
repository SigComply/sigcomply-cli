package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const (
	testFrameworkSOC2 = "soc2"
	testSourceAWSIAM  = "aws.iam"
)

func TestLoadProjectConfig_Minimal(t *testing.T) {
	data := readTestdata(t, "project_config/valid_minimal.yaml")

	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	if cfg.Framework != testFrameworkSOC2 {
		t.Errorf("Framework = %q; want %q", cfg.Framework, testFrameworkSOC2)
	}
	if cfg.Vault.Backend != backendLocal || cfg.Vault.Str("path") != "./vault" {
		t.Errorf("Vault = %+v; want backend=local path=./vault", cfg.Vault)
	}
	bind := cfg.BindingsFor("soc2.cc6.1.mfa_enforced")
	if bind == nil {
		t.Fatal("missing binding for soc2.cc6.1.mfa_enforced")
	}
	if len(bind["user_directory"]) != 1 || bind["user_directory"][0].Source != testSourceAWSIAM {
		t.Errorf("binding user_directory = %+v; want [%s]", bind["user_directory"], testSourceAWSIAM)
	}
}

// TestLoadProjectConfig_ExperimentalEscapeHatch verifies the
// forward-compatibility contract: arbitrary subkeys under `experimental:`
// load without error (so a newer config never hard-fails an older pinned
// CLI), while an unrecognized *top-level* key is still a loud error.
func TestLoadProjectConfig_ExperimentalEscapeHatch(t *testing.T) {
	data := readTestdata(t, "project_config/valid_experimental.yaml")

	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	if got, ok := cfg.Experimental["quarantine_policy_population"]; !ok || got != true {
		t.Errorf("Experimental[quarantine_policy_population] = %v (ok=%v); want true", got, ok)
	}
	if _, ok := cfg.Experimental["some_future_knob"]; !ok {
		t.Error("Experimental[some_future_knob] missing; nested experimental subkeys must survive the loader")
	}

	// An unknown key OUTSIDE the experimental bag must still be rejected —
	// the escape hatch must not weaken typo detection on real sections.
	stray := strings.Replace(string(data), "\nexperimental:", "\nexperimentl:", 1)
	if _, err := LoadProjectConfig([]byte(stray)); err == nil {
		t.Error("misspelled top-level key was accepted; KnownFields strictness must hold outside experimental:")
	}
}

// TestLoadProjectConfig_VaultDefaults verifies the zero-config first-run
// shape: an omitted vault: block defaults to a local vault under the
// project, so a brand-new config needs neither vault nor bindings.
func TestLoadProjectConfig_VaultDefaults(t *testing.T) {
	data := readTestdata(t, "project_config/valid_vault_defaults.yaml")
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	if cfg.Vault.Backend != backendLocal {
		t.Errorf("Vault.Backend = %q; want local (defaulted)", cfg.Vault.Backend)
	}
	if cfg.Vault.Str("path") != DefaultLocalVaultPath {
		t.Errorf("Vault path = %q; want %q (defaulted)", cfg.Vault.Str("path"), DefaultLocalVaultPath)
	}
}

// TestLoadProjectConfig_LocalBackendNoPathDefaults verifies that an
// explicit backend: local with no path: still defaults the path rather
// than erroring (it used to be a hard validation error).
func TestLoadProjectConfig_LocalBackendNoPathDefaults(t *testing.T) {
	data := readTestdata(t, "project_config/valid_vault_local_no_path.yaml")
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig: backend:local without path should default, got %v", err)
	}
	if cfg.Vault.Str("path") != DefaultLocalVaultPath {
		t.Errorf("Vault path = %q; want %q (defaulted)", cfg.Vault.Str("path"), DefaultLocalVaultPath)
	}
}

func TestLoadProjectConfig_AcmeCorpExample(t *testing.T) {
	data := readTestdata(t, "project_config/valid_acmecorp.yaml")

	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig(acmecorp): %v", err)
	}
	if cfg.Framework != testFrameworkSOC2 {
		t.Errorf("Framework = %q; want %q", cfg.Framework, testFrameworkSOC2)
	}
	if cfg.Vault.Backend != "s3" || cfg.Vault.Str("bucket") != "acme-evidence" {
		t.Errorf("Vault = %+v; want s3 / acme-evidence", cfg.Vault)
	}
	if _, ok := cfg.Sources["manual.pdf"]; !ok {
		t.Error("expected manual.pdf in sources")
	}
	if _, ok := cfg.Sources["acme.internal_iam"]; !ok {
		t.Error("expected acme.internal_iam in sources")
	}
	if cad := cfg.CadenceFor("soc2.cc6.1.mfa_enforced"); cad != "hourly" {
		t.Errorf("cadence mfa_enforced = %q; want hourly", cad)
	}
	if got := cfg.ParametersFor("soc2.cc6.1.mfa_enforced")["exempt_service_accounts"]; got != false {
		t.Errorf("parameters exempt_service_accounts = %#v; want false", got)
	}
	// Exceptions are now co-located under each policy: one scoped waiver on
	// mfa_enforced, one whole-policy na on the WAF policy.
	if n := len(cfg.ExceptionsFor("soc2.cc6.1.mfa_enforced")); n != 1 {
		t.Errorf("mfa_enforced exceptions = %d; want 1", n)
	}
	if n := len(cfg.ExceptionsFor("soc2.cc6.7.waf_in_front_of_web_app")); n != 1 {
		t.Errorf("waf exceptions = %d; want 1", n)
	}
	// Control-level applicability: CC6.4 is not_applicable (inherited).
	if cc := cfg.Controls["CC6.4"]; cc.Applicability != "not_applicable" {
		t.Errorf("controls[CC6.4].applicability = %q; want not_applicable", cc.Applicability)
	}
	if cfg.CI.FailSeverity != core.SeverityHigh {
		t.Errorf("CI.FailSeverity = %q; want high", cfg.CI.FailSeverity)
	}
}

func TestLoadProjectConfig_BindingWithSlotParams(t *testing.T) {
	data := readTestdata(t, "project_config/valid_binding_with_slot_params.yaml")

	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	entries := cfg.BindingsFor("soc2.cc6.1.admin_mfa_enforced")["user_directory"]
	if len(entries) != 1 {
		t.Fatalf("expected 1 binding entry; got %d", len(entries))
	}
	if entries[0].Source != testSourceAWSIAM {
		t.Errorf("entry.Source = %q; want %q", entries[0].Source, testSourceAWSIAM)
	}
	got, ok := entries[0].SlotParams["filter_admins_only"].(bool)
	if !ok || !got {
		t.Errorf("entry.SlotParams[filter_admins_only] = %#v; want true", entries[0].SlotParams["filter_admins_only"])
	}
}

func TestLoadProjectConfig_PolicyOverrides(t *testing.T) {
	data := readTestdata(t, "project_config/valid_policy_overrides.yaml")

	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	mode, catalog := cfg.EvidenceModeOverrideFor("soc2.cc6.1.mfa_enforced")
	if mode != "manual" {
		t.Errorf("evidence_mode override = %q; want \"manual\"", mode)
	}
	if catalog != "mfa_attestation" {
		t.Errorf("catalog_entry = %q; want \"mfa_attestation\"", catalog)
	}
}

func TestLoadProjectConfig_RejectsInvalid(t *testing.T) {
	cases := []struct {
		file    string
		wantSub string
	}{
		{"project_config/invalid_missing_framework.yaml", "framework"},
		{"project_config/invalid_manual_pdf_bracket.yaml", "singleton"},
		{"project_config/invalid_bad_cadence.yaml", "invalid cadence"},
		{"project_config/invalid_exception_no_reason.yaml", "reason"},
		{"project_config/invalid_exception_bad_state.yaml", "state"},
		{"project_config/invalid_exception_bad_date.yaml", "ISO 8601"},
		{"project_config/invalid_bad_output_format.yaml", "output.format"},
		{"project_config/invalid_unknown_top_level.yaml", "mystery_section"},
		{"project_config/invalid_policy_override_no_catalog.yaml", "catalog_entry"},
		{"project_config/invalid_policy_override_bad_mode.yaml", "invalid value"},
		{"project_config/invalid_policy_override_automated_with_catalog.yaml", "catalog_entry"},
		{"project_config/invalid_policy_override_empty_mode.yaml", "catalog_entry must not be set"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data := readTestdata(t, tc.file)
			_, err := LoadProjectConfig(data)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q; want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestLoadProjectConfig_GitLabExample parses the documented GitLab example
// config so the example in docs/ can never drift out of the strict loader's
// accepted shape (unknown keys are a hard error).
func TestLoadProjectConfig_GitLabExample(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "architecture", "examples", "gitlab-selfmanaged.sigcomply.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig(gitlab example): %v", err)
	}
	if cfg.Framework != testFrameworkSOC2 {
		t.Errorf("Framework = %q; want %q", cfg.Framework, testFrameworkSOC2)
	}
	if _, ok := cfg.Sources["gitlab"]; !ok {
		t.Error("expected gitlab in sources")
	}
	// gitlab is bound to both a directory_user and a git_repository policy.
	if b := cfg.BindingsFor("soc2.cc6.1.mfa_enforced_admins")["evidence"]; len(b) != 1 || b[0].Source != "gitlab" {
		t.Errorf("mfa_enforced_admins evidence binding = %v; want [gitlab]", b)
	}
	if b := cfg.BindingsFor("soc2.cc8.1.default_branch_protected")["evidence"]; len(b) != 1 || b[0].Source != "gitlab" {
		t.Errorf("default_branch_protected evidence binding = %v; want [gitlab]", b)
	}
}

// TestLoadProjectConfig_GCPExample parses the documented GCP example config
// so the example in docs/ can never drift out of the strict loader's accepted
// shape (unknown keys are a hard error). It also pins the two GCP-scope
// exceptions (org-scoped gcp.scc, customer-scoped gcp.directory) and the
// password-policy not-applicable deferral.
func TestLoadProjectConfig_GCPExample(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "architecture", "examples", "gcp-project.sigcomply.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("LoadProjectConfig(gcp example): %v", err)
	}
	if cfg.Framework != testFrameworkSOC2 {
		t.Errorf("Framework = %q; want %q", cfg.Framework, testFrameworkSOC2)
	}
	for _, src := range []string{"gcp.directory", "gcp.firewall", "gcp.scc", "manual.pdf"} {
		if _, ok := cfg.Sources[src]; !ok {
			t.Errorf("expected %q in sources", src)
		}
	}
	// gcp.directory supplies the identity (directory_user) evidence.
	if b := cfg.BindingsFor("soc2.cc6.1.mfa_enforced_admins")["evidence"]; len(b) != 1 || b[0].Source != "gcp.directory" {
		t.Errorf("mfa_enforced_admins evidence binding = %v; want [gcp.directory]", b)
	}
	// The org-scoped gcp.scc source emits three types; one binding shown here.
	if b := cfg.BindingsFor("soc2.cc7.4.no_critical_vulns_active")["evidence"]; len(b) != 1 || b[0].Source != "gcp.scc" {
		t.Errorf("no_critical_vulns_active evidence binding = %v; want [gcp.scc]", b)
	}
}

func TestLoadProjectConfig_EmptyInput(t *testing.T) {
	if _, err := LoadProjectConfig(nil); err == nil {
		t.Error("expected error on nil input")
	}
}
