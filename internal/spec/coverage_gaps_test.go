package spec

// coverage_gaps_test.go — exercises the uncovered branches identified by
// go tool cover: validateCadenceSpec (29%), validatePolicyRequiredScalars,
// validatePassWhenClause, validateVault, validatePeriod, and several other
// validator branches that affect compliance correctness.

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// validateCadenceSpec — currently 29% covered
// ---------------------------------------------------------------------------

func TestValidateCadenceSpec_Named(t *testing.T) {
	for _, c := range []string{"continuous", "hourly", "daily", "weekly", "monthly", "quarterly", "annual"} {
		if err := validateCadenceSpec(c); err != nil {
			t.Errorf("validateCadenceSpec(%q) unexpected error: %v", c, err)
		}
	}
}

func TestValidateCadenceSpec_EveryDuration(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"every:1h", ""},
		{"every:24h", ""},
		{"every:7d", "invalid duration"}, // Go doesn't parse "d"
		{"every:5m", ""},
		{"every:4m", "floor"},     // below 5-minute floor
		{"every:-1h", "positive"}, // negative
		{"every:0s", "positive"},  // zero
		{"every:", "missing"},     // missing duration
	}
	for _, tc := range cases {
		err := validateCadenceSpec(tc.in)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("validateCadenceSpec(%q) = %v; want nil", tc.in, err)
			}
		} else {
			if err == nil {
				t.Errorf("validateCadenceSpec(%q) = nil; want error containing %q", tc.in, tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("validateCadenceSpec(%q) = %v; want %q in error", tc.in, err, tc.wantErr)
			}
		}
	}
}

func TestValidateCadenceSpec_PlainDurationHint(t *testing.T) {
	// "24h" looks like a duration but lacks the "every:" prefix — the validator
	// provides a hint. This exercises the "did you mean" branch.
	err := validateCadenceSpec("24h")
	if err == nil {
		t.Error("expected error for bare duration without every: prefix")
	}
	if !strings.Contains(err.Error(), "every:") {
		t.Errorf("error should suggest every: prefix; got %v", err)
	}
}

func TestValidateCadenceSpec_TotallyUnknown(t *testing.T) {
	err := validateCadenceSpec("fortnightly")
	if err == nil {
		t.Error("expected error for unknown cadence string")
	}
}

// ---------------------------------------------------------------------------
// validatePolicyRequiredScalars — 61% covered
// The missing branches are the early returns for empty ID, control,
// description, cadence (some not tested when evidence_mode comes first).
// ---------------------------------------------------------------------------

func TestLoadPolicy_MissingID(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "id") {
		t.Errorf("expected error mentioning 'id'; got %v", err)
	}
}

func TestLoadPolicy_MissingControl(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.missing_control
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "control") {
		t.Errorf("expected error mentioning 'control'; got %v", err)
	}
}

func TestLoadPolicy_MissingDescription(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.missing_desc
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "description") {
		t.Errorf("expected error mentioning 'description'; got %v", err)
	}
}

func TestLoadPolicy_MissingCadence(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.missing_cadence
control: SOC2.CC6.1
severity: high
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "cadence") {
		t.Errorf("expected error mentioning 'cadence'; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// validatePassWhenClause — 62.5% covered
// Missing: missing slot, missing quantifier, invalid quantifier,
// count without min_percentage, min_percentage without count.
// ---------------------------------------------------------------------------

func TestLoadPolicy_PassWhenMissingSlot(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.no_slot
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "slot") {
		t.Errorf("expected error mentioning 'slot'; got %v", err)
	}
}

func TestLoadPolicy_PassWhenMissingQuantifier(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.no_quantifier
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "quantifier") {
		t.Errorf("expected error mentioning 'quantifier'; got %v", err)
	}
}

func TestLoadPolicy_PassWhenInvalidQuantifier(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.bad_quantifier
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: most
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "quantifier") {
		t.Errorf("expected error mentioning 'quantifier'; got %v", err)
	}
}

func TestLoadPolicy_PassWhenCountWithoutMinPercentage(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.count_no_min_pct
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: count
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "min_percentage") {
		t.Errorf("expected error mentioning 'min_percentage'; got %v", err)
	}
}

func TestLoadPolicy_PassWhenMinPercentageWithoutCount(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.min_pct_no_count
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  min_percentage: 80.0
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "min_percentage") {
		t.Errorf("expected error mentioning 'min_percentage'; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// validatePassWhenCondition — 66.7% covered
// Missing: op requires field (already tested); is_set with no value; all_of
// with empty conditions list; conditions[i] sub-validation.
// ---------------------------------------------------------------------------

func TestLoadPolicy_PassWhenIsSetNoValue(t *testing.T) {
	// is_set does NOT require a value — verify it passes.
	data := []byte(`
schema_version: policy.v1
id: test.is_set_ok
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: is_set
    field: payload.last_login_at
`)
	_, err := LoadPolicy(data)
	if err != nil {
		t.Errorf("is_set without value should be valid; got %v", err)
	}
}

func TestLoadPolicy_PassWhenConditionMissingField(t *testing.T) {
	// Non-is_set op without a field.
	data := []byte(`
schema_version: policy.v1
id: test.missing_field
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "field") {
		t.Errorf("expected error mentioning 'field'; got %v", err)
	}
}

func TestLoadPolicy_PassWhenConditionMissingValue(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.missing_value
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "value") {
		t.Errorf("expected error mentioning 'value'; got %v", err)
	}
}

func TestLoadPolicy_PassWhenAllOfEmptyConditions(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.all_of_empty
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: all_of
    conditions: []
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "sub-condition") {
		t.Errorf("expected error about sub-conditions; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// validatePolicySlots — slot accepts contains empty string
// ---------------------------------------------------------------------------

func TestLoadPolicy_SlotAcceptsContainsEmptyString(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: test.empty_accepts_entry
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: ["directory_user", ""]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "accepts") {
		t.Errorf("expected error about empty accepts entry; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateVault — missing branches: gcs, azure_blob, invalid backend,
// s3 missing region, s3 on-prem path
// ---------------------------------------------------------------------------

func TestLoadProjectConfig_VaultGCS(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
vault:
  backend: gcs
  bucket: my-gcs-bucket
`)
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("gcs vault should be valid; got %v", err)
	}
	if cfg.Vault.Backend != "gcs" || cfg.Vault.Bucket != "my-gcs-bucket" {
		t.Errorf("Vault = %+v", cfg.Vault)
	}
}

func TestLoadProjectConfig_VaultGCSMissingBucket(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
vault:
  backend: gcs
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "vault.bucket") {
		t.Errorf("expected bucket required error; got %v", err)
	}
}

func TestLoadProjectConfig_VaultAzureBlob(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
vault:
  backend: azure_blob
  account: myaccount
  container: mycontainer
`)
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("azure_blob vault should be valid; got %v", err)
	}
	if cfg.Vault.Backend != "azure_blob" {
		t.Errorf("Backend = %q", cfg.Vault.Backend)
	}
}

func TestLoadProjectConfig_VaultAzureBlobMissingAccount(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
vault:
  backend: azure_blob
  container: mycontainer
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "vault.account") {
		t.Errorf("expected account required error; got %v", err)
	}
}

func TestLoadProjectConfig_VaultAzureBlobMissingContainer(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
vault:
  backend: azure_blob
  account: myaccount
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "vault.container") {
		t.Errorf("expected container required error; got %v", err)
	}
}

func TestLoadProjectConfig_VaultInvalidBackend(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
vault:
  backend: hdfs
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "vault.backend") {
		t.Errorf("expected invalid backend error; got %v", err)
	}
}

func TestLoadProjectConfig_VaultS3MissingRegion(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
vault:
  backend: s3
  bucket: my-bucket
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "vault.region") {
		t.Errorf("expected region required error; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// validatePeriod — missing branches: custom type, invalid time_basis
// ---------------------------------------------------------------------------

func TestLoadProjectConfig_PeriodCustomType(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
period:
  fiscal_calendar:
    type: custom
    periods:
      - id: "2026-H1"
        start: "2026-01-01"
        end: "2026-06-30"
`)
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("custom period should be valid; got %v", err)
	}
	if cfg.Period.FiscalCalendar.Type != "custom" {
		t.Errorf("Type = %q", cfg.Period.FiscalCalendar.Type)
	}
}

func TestLoadProjectConfig_PeriodCustomTypeMissingPeriods(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
period:
  fiscal_calendar:
    type: custom
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "periods") {
		t.Errorf("expected periods required error; got %v", err)
	}
}

func TestLoadProjectConfig_PeriodInvalidTimeBasis(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
period:
  fiscal_calendar:
    type: calendar_quarter
  time_basis: runtime
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "time_basis") {
		t.Errorf("expected time_basis error; got %v", err)
	}
}

func TestLoadProjectConfig_PeriodInvalidType(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
period:
  fiscal_calendar:
    type: sprints
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "fiscal_calendar.type") {
		t.Errorf("expected invalid type error; got %v", err)
	}
}

func TestLoadProjectConfig_PeriodCustomMissingID(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
period:
  fiscal_calendar:
    type: custom
    periods:
      - start: "2026-01-01"
        end: "2026-06-30"
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "id") {
		t.Errorf("expected id required error; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateCI — fail_severity validation
// ---------------------------------------------------------------------------

func TestLoadProjectConfig_CIInvalidFailSeverity(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
ci:
  fail_severity: extreme
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "fail_severity") {
		t.Errorf("expected fail_severity error; got %v", err)
	}
}

func TestLoadProjectConfig_CIValidFailSeverity(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
ci:
  fail_severity: medium
`)
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("valid fail_severity should pass; got %v", err)
	}
	if cfg.CI.FailSeverity != "medium" {
		t.Errorf("FailSeverity = %q", cfg.CI.FailSeverity)
	}
}

// ---------------------------------------------------------------------------
// validateExceptions — expires_at validation
// ---------------------------------------------------------------------------

func TestLoadProjectConfig_ExceptionValidExpiresAt(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
exceptions:
  - policy: soc2.cc6.1.mfa
    state: waived
    reason: "Migration in progress"
    expires_at: "2026-12-31"
`)
	_, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("valid expires_at should pass; got %v", err)
	}
}

func TestLoadProjectConfig_ExceptionBadExpiresAt(t *testing.T) {
	data := []byte(`
schema_version: project.v1
framework: soc2
exceptions:
  - policy: soc2.cc6.1.mfa
    state: waived
    reason: "Migration in progress"
    expires_at: "31-12-2026"
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "expires_at") {
		t.Errorf("expected expires_at format error; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// expectSchemaVersion — wrong version path
// ---------------------------------------------------------------------------

func TestLoadPolicy_WrongSchemaVersion(t *testing.T) {
	data := []byte(`
schema_version: policy.v99
id: test.wrong_version
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: s
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`)
	_, err := LoadPolicy(data)
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("expected schema_version error; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// BindingEntry.UnmarshalYAML — sequence node (unsupported kind)
// ---------------------------------------------------------------------------

func TestLoadProjectConfig_BindingEntryStringForm(t *testing.T) {
	// The string form ("aws.iam") is the common case — confirm it loads.
	data := []byte(`
schema_version: project.v1
framework: soc2
bindings:
  soc2.cc6.1.mfa:
    users:
      - aws.iam
`)
	cfg, err := LoadProjectConfig(data)
	if err != nil {
		t.Fatalf("string binding should parse; got %v", err)
	}
	entries := cfg.Bindings["soc2.cc6.1.mfa"]["users"]
	if len(entries) != 1 || entries[0].Source != "aws.iam" {
		t.Errorf("entries = %+v", entries)
	}
}

func TestLoadProjectConfig_BindingEntryMissingSource(t *testing.T) {
	// Mapping form without a source field.
	data := []byte(`
schema_version: project.v1
framework: soc2
bindings:
  soc2.cc6.1.mfa:
    users:
      - slot_params:
          filter: true
`)
	_, err := LoadProjectConfig(data)
	if err == nil || !strings.Contains(err.Error(), "source") {
		t.Errorf("expected source required error; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// parsePassWhen — invalid top-level node kind (neither mapping nor sequence)
// ---------------------------------------------------------------------------

func TestLoadPolicy_PassWhenInvalidNodeKind(t *testing.T) {
	// A scalar string where a mapping/sequence is expected.
	data := []byte(`
schema_version: policy.v1
id: test.bad_pass_when
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "test"
slots:
  s:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when: "just a string"
`)
	_, err := LoadPolicy(data)
	if err == nil {
		t.Error("expected error for scalar pass_when; got nil")
	}
}
