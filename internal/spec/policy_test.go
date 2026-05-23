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
	if len(p.Tags) != 2 {
		t.Errorf("Tags length = %d; want 2", len(p.Tags))
	}
}

func assertMFAScalars(t *testing.T, p *core.Policy) {
	t.Helper()
	if p.ID != "soc2.cc6.1.mfa_enforced" {
		t.Errorf("ID = %q; want soc2.cc6.1.mfa_enforced", p.ID)
	}
	if p.Control != "SOC2.CC6.1" {
		t.Errorf("Control = %q; want SOC2.CC6.1", p.Control)
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
	if p.RuleRef != "rules.mfa_enforced.v1" {
		t.Errorf("RuleRef = %q; want rules.mfa_enforced.v1", p.RuleRef)
	}
}

func assertMFASlot(t *testing.T, p *core.Policy) {
	t.Helper()
	slot, ok := p.Slots["user_directory"]
	if !ok {
		t.Fatal("missing slot user_directory")
	}
	if slot.Type != "user_record" {
		t.Errorf("slot.Type = %q; want user_record", slot.Type)
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
	if p.Cadence != "quarterly" {
		t.Errorf("Cadence = %q; want quarterly", p.Cadence)
	}
	if p.OnPush {
		t.Error("OnPush = true; want false for a signed_document slot when on_push is omitted")
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
