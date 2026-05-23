package spec

import (
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
	if cfg.Vault.Backend != "local" || cfg.Vault.Path != "./vault" {
		t.Errorf("Vault = %+v; want backend=local path=./vault", cfg.Vault)
	}
	bind, ok := cfg.Bindings["soc2.cc6.1.mfa_enforced"]
	if !ok {
		t.Fatal("missing binding for soc2.cc6.1.mfa_enforced")
	}
	if len(bind["user_directory"]) != 1 || bind["user_directory"][0].Source != testSourceAWSIAM {
		t.Errorf("binding user_directory = %+v; want [%s]", bind["user_directory"], testSourceAWSIAM)
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
	if cfg.Vault.Backend != "s3" || cfg.Vault.Bucket != "acme-evidence" {
		t.Errorf("Vault = %+v; want s3 / acme-evidence", cfg.Vault)
	}
	if _, ok := cfg.Sources["manual.pdf"]; !ok {
		t.Error("expected manual.pdf in sources")
	}
	if _, ok := cfg.Sources["acme.internal_iam"]; !ok {
		t.Error("expected acme.internal_iam in sources")
	}
	if cad := cfg.PolicyCadences["soc2.cc6.1.mfa_enforced"]; cad != "hourly" {
		t.Errorf("policy_cadences mfa_enforced = %q; want hourly", cad)
	}
	if got := cfg.PolicyParameters["soc2.cc6.1.mfa_enforced"]["exempt_service_accounts"]; got != false {
		t.Errorf("policy_parameters exempt_service_accounts = %#v; want false", got)
	}
	if n := len(cfg.Exceptions); n != 2 {
		t.Errorf("Exceptions length = %d; want 2", n)
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
	entries := cfg.Bindings["soc2.cc6.1.admin_mfa_enforced"]["user_directory"]
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

func TestLoadProjectConfig_RejectsInvalid(t *testing.T) {
	cases := []struct {
		file    string
		wantSub string
	}{
		{"project_config/invalid_missing_framework.yaml", "framework"},
		{"project_config/invalid_vault_local_no_path.yaml", "vault.path"},
		{"project_config/invalid_vault_s3_no_bucket.yaml", "vault.bucket"},
		{"project_config/invalid_manual_pdf_bracket.yaml", "singleton"},
		{"project_config/invalid_bad_cadence.yaml", "invalid cadence"},
		{"project_config/invalid_exception_no_reason.yaml", "reason"},
		{"project_config/invalid_exception_bad_state.yaml", "state"},
		{"project_config/invalid_exception_bad_date.yaml", "ISO 8601"},
		{"project_config/invalid_bad_output_format.yaml", "output.format"},
		{"project_config/invalid_unknown_top_level.yaml", "mystery_section"},
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

func TestLoadProjectConfig_EmptyInput(t *testing.T) {
	if _, err := LoadProjectConfig(nil); err == nil {
		t.Error("expected error on nil input")
	}
}
