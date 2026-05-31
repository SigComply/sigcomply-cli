package spec

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func TestLoadPolicy_ValidMFAEnforced(t *testing.T) {
	data := readTestdata(t, "policy/valid_mfa_enforced.yaml")

	p, err := LoadPolicy(data)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	t.Run("scalars", func(t *testing.T) { assertMFAScalars(t, &p) })
	t.Run("slot", func(t *testing.T) { assertMFASlot(t, &p) })
	t.Run("parameter", func(t *testing.T) { assertMFAParameter(t, &p) })
	t.Run("evidence_mode", func(t *testing.T) { assertMFAEvidenceMode(t, &p) })
	t.Run("pass_when", func(t *testing.T) { assertMFAPassWhen(t, &p) })
	if len(p.Tags) != 2 {
		t.Errorf("Tags length = %d; want 2", len(p.Tags))
	}
}

func assertMFAScalars(t *testing.T, p *core.Policy) {
	t.Helper()
	if p.ID != "soc2.cc6.1.mfa_enforced" {
		t.Errorf("ID = %q; want soc2.cc6.1.mfa_enforced", p.ID)
	}
	if got := core.PrimaryControlID(p.Controls); got != "SOC2.CC6.1" {
		t.Errorf("Control = %q; want SOC2.CC6.1", got)
	}
	if p.Severity != core.SeverityHigh {
		t.Errorf("Severity = %q; want high", p.Severity)
	}
	if p.Cadence != "daily" {
		t.Errorf("Cadence = %q; want daily", p.Cadence)
	}
	if !p.OnPush {
		t.Error("OnPush = false; want true")
	}
	if p.RuleRef != "" {
		t.Errorf("RuleRef = %q; want empty (pass_when policy uses no rule ref)", p.RuleRef)
	}
}

func assertMFAEvidenceMode(t *testing.T, p *core.Policy) {
	t.Helper()
	if p.EvidenceMode != core.EvidenceModeAutomated {
		t.Errorf("EvidenceMode = %q; want %q", p.EvidenceMode, core.EvidenceModeAutomated)
	}
	if p.CatalogEntry != "" {
		t.Errorf("CatalogEntry = %q; want empty for automated policy", p.CatalogEntry)
	}
}

func assertMFAPassWhen(t *testing.T, p *core.Policy) {
	t.Helper()
	if p.PassWhen == nil {
		t.Fatal("PassWhen is nil; want non-nil")
	}
	if len(p.PassWhen.Clauses) != 1 {
		t.Fatalf("PassWhen.Clauses len = %d; want 1", len(p.PassWhen.Clauses))
	}
	clause := p.PassWhen.Clauses[0]
	if clause.Slot != "user_directory" {
		t.Errorf("Clause.Slot = %q; want user_directory", clause.Slot)
	}
	if clause.Quantifier != core.QuantifierAll {
		t.Errorf("Clause.Quantifier = %q; want all", clause.Quantifier)
	}
	if clause.Condition == nil {
		t.Fatal("Clause.Condition is nil")
	}
	if clause.Condition.Op != "eq" {
		t.Errorf("Condition.Op = %q; want eq", clause.Condition.Op)
	}
	if clause.Condition.Field != "payload.mfa_enabled" {
		t.Errorf("Condition.Field = %q; want payload.mfa_enabled", clause.Condition.Field)
	}
	if clause.Filter == nil {
		t.Fatal("Clause.Filter is nil; want non-nil (is_service_account filter)")
	}
	if clause.Filter.Op != "neq" {
		t.Errorf("Filter.Op = %q; want neq", clause.Filter.Op)
	}
	if clause.ViolationMsg == "" {
		t.Error("ViolationMsg is empty")
	}
	if clause.IdentityKey != "id" {
		t.Errorf("IdentityKey = %q; want id", clause.IdentityKey)
	}
}

func assertMFASlot(t *testing.T, p *core.Policy) {
	t.Helper()
	slot, ok := p.Slots["user_directory"]
	if !ok {
		t.Fatal("missing slot user_directory")
	}
	if len(slot.Accepts) != 1 || slot.Accepts[0] != "directory_user" {
		t.Errorf("slot.Accepts = %v; want [directory_user]", slot.Accepts)
	}
	if slot.Cardinality != core.SlotOneOrMore {
		t.Errorf("slot.Cardinality = %q; want one-or-more", slot.Cardinality)
	}
	if !slot.Required {
		t.Error("slot.Required = false; want true")
	}
}

func assertMFAParameter(t *testing.T, p *core.Policy) {
	t.Helper()
	exempt, ok := p.Parameters["exempt_service_accounts"]
	if !ok {
		t.Fatal("missing parameter exempt_service_accounts")
	}
	if exempt.Type != "bool" {
		t.Errorf("param.Type = %q; want bool", exempt.Type)
	}
	gotBool, ok := exempt.Default.(bool)
	if !ok || !gotBool {
		t.Errorf("param.Default = %#v; want true (bool)", exempt.Default)
	}
}

func TestLoadPolicy_ManualDefaultsOnPushFalse(t *testing.T) {
	data := readTestdata(t, "policy/valid_manual_access_review.yaml")

	p, err := LoadPolicy(data)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.EvidenceMode != core.EvidenceModeManual {
		t.Errorf("EvidenceMode = %q; want manual", p.EvidenceMode)
	}
	if p.CatalogEntry != "access_review_quarterly" {
		t.Errorf("CatalogEntry = %q; want access_review_quarterly", p.CatalogEntry)
	}
	if p.Cadence != "quarterly" {
		t.Errorf("Cadence = %q; want quarterly", p.Cadence)
	}
	if p.OnPush {
		t.Error("OnPush = true; want false for evidence_mode: manual when on_push is omitted")
	}
	if len(p.Slots) != 0 {
		t.Errorf("Slots len = %d; want 0 for manual policy", len(p.Slots))
	}
	if p.RuleRef != "" {
		t.Errorf("RuleRef = %q; want empty for manual policy", p.RuleRef)
	}
	if p.PassWhen != nil {
		t.Error("PassWhen non-nil; want nil for manual policy")
	}
	grace := p.Parameters["grace_period_days"]
	if grace.Type != "int" {
		t.Errorf("param.Type = %q; want int", grace.Type)
	}
	got, ok := grace.Default.(int)
	if !ok || got != 30 {
		t.Errorf("param.Default = %#v; want 30 (int)", grace.Default)
	}
}

func TestLoadPolicy_RejectsInvalid(t *testing.T) {
	cases := []struct {
		file    string
		wantSub string
	}{
		{"policy/invalid_missing_rule.yaml", "rule"},
		{"policy/invalid_missing_evidence_mode.yaml", "evidence_mode"},
		{"policy/invalid_manual_with_slots.yaml", "slots"},
		{"policy/invalid_manual_missing_catalog_entry.yaml", "catalog_entry"},
		{"policy/invalid_bad_cadence.yaml", "cadence"},
		{"policy/invalid_bad_severity.yaml", "severity"},
		{"policy/invalid_bad_cardinality.yaml", "cardinality"},
		{"policy/invalid_bad_param_type.yaml", "type"},
		{"policy/invalid_empty_slots.yaml", "slots"},
		{"policy/invalid_unknown_field.yaml", "cadennce"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data := readTestdata(t, tc.file)
			_, err := LoadPolicy(data)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q; want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadPolicy_EmptyInput(t *testing.T) {
	if _, err := LoadPolicy(nil); err == nil {
		t.Error("expected error on nil input")
	}
}

func TestLoadPolicy_PassWhenMultiSlot(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: soc2.storage.encryption
control: SOC2.CC6.7
severity: high
cadence: daily
evidence_mode: automated
description: "All object storage buckets must be encrypted at rest."
slots:
  s3_buckets:
    accepts: [object_storage_bucket]
    cardinality: one-or-more
    required: true
  gcs_buckets:
    accepts: [object_storage_bucket]
    cardinality: optional
    required: false
pass_when:
  - slot: s3_buckets
    quantifier: all
    condition:
      op: eq
      field: payload.encryption_at_rest_enabled
      value: true
    violation_message: "Bucket {{.id}} is not encrypted at rest"
  - slot: gcs_buckets
    quantifier: all
    condition:
      op: eq
      field: payload.encryption_at_rest_enabled
      value: true
    violation_message: "Bucket {{.id}} is not encrypted at rest"
`)
	p, err := LoadPolicy(data)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.PassWhen == nil {
		t.Fatal("PassWhen is nil")
	}
	if len(p.PassWhen.Clauses) != 2 {
		t.Errorf("Clauses len = %d; want 2", len(p.PassWhen.Clauses))
	}
}

func TestLoadPolicy_PassWhenAllOfCondition(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: soc2.storage.security
control: SOC2.CC6.7
severity: high
cadence: daily
evidence_mode: automated
description: "Buckets must be encrypted and block public access."
slots:
  buckets:
    accepts: [object_storage_bucket]
    cardinality: one-or-more
    required: true
pass_when:
  slot: buckets
  quantifier: all
  condition:
    op: all_of
    conditions:
      - op: eq
        field: payload.encryption_at_rest_enabled
        value: true
      - op: eq
        field: payload.public_access_blocked
        value: true
  violation_message: "Bucket {{.id}} fails security requirements"
`)
	p, err := LoadPolicy(data)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.PassWhen == nil || len(p.PassWhen.Clauses) != 1 {
		t.Fatal("want single pass_when clause")
	}
	cond := p.PassWhen.Clauses[0].Condition
	if cond.Op != "all_of" {
		t.Errorf("Condition.Op = %q; want all_of", cond.Op)
	}
	if len(cond.Conditions) != 2 {
		t.Errorf("sub-conditions len = %d; want 2", len(cond.Conditions))
	}
}

func TestLoadPolicy_RejectsPassWhenAndRule(t *testing.T) {
	data := []byte(`
schema_version: policy.v1
id: soc2.cc6.1.test
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "Test."
slots:
  users:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: users
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
rule: rules.mfa.v1
`)
	_, err := LoadPolicy(data)
	if err == nil {
		t.Fatal("expected error for policy with both pass_when and rule")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q; want substring \"mutually exclusive\"", err.Error())
	}
}
