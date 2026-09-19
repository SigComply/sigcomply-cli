package spec_test

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// testSlotRoster is the slot name used by the roster fixtures below.
const testSlotRoster = "roster"

const rosterPolicyHead = `schema_version: policy.v1
id: acme.roster.linked
control: SOC2.CC6.2
severity: high
cadence: daily
evidence_mode: automated
description: "Accounts are linked to the roster"
`

const rosterSlots = `slots:
  roster:
    accepts: [roster_entry]
    cardinality: exactly-one
    required: true
    role: roster
  accounts:
    accepts: [directory_user, directory_user.v2]
    cardinality: one-or-more
    required: true
    role: roster_subject
`

const rosterPassWhen = `pass_when:
  slot: accounts
  quantifier: none
  identity_key: account.ref
  filter:
    op: eq
    field: account.active
    value: true
  condition:
    op: matches_in
    field: account.key
    in_slot: roster
    remote_field: payload.email
    normalize: lower_trim
    where:
      op: eq
      field: payload.status
      value: inactive
`

func TestLoadPolicy_MatchesInAndRoles(t *testing.T) {
	p, err := spec.LoadPolicy([]byte(rosterPolicyHead + rosterSlots + rosterPassWhen))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.Slots[testSlotRoster].Role != core.SlotRoleRoster || p.Slots["accounts"].Role != core.SlotRoleRosterSubject {
		t.Errorf("roles = %q, %q", p.Slots[testSlotRoster].Role, p.Slots["accounts"].Role)
	}
	c := p.PassWhen.Clauses[0].Condition
	if c.Op != core.OpMatchesIn || c.InSlot != testSlotRoster || c.RemoteField != "payload.email" || c.Normalize != core.NormalizeLowerTrim {
		t.Errorf("condition = %+v", c)
	}
	if c.Where == nil || c.Where.Field != "payload.status" || c.Where.Value != "inactive" {
		t.Errorf("where = %+v", c.Where)
	}
}

func TestLoadPolicy_RejectsBadMatchesIn(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"undeclared in_slot", "in_slot: roster", "in_slot: rostr", `"rostr"`},
		{"bad normalize", "normalize: lower_trim", "normalize: lowercase", "normalize"},
		{"unknown key", "normalize: lower_trim", "normalise: lower_trim", "normalise"},
		{"missing remote_field", "    remote_field: payload.email\n", "", "remote_field"},
		{"missing in_slot", "    in_slot: roster\n", "", "in_slot"},
		{"matches_in in where", "      op: eq\n      field: payload.status\n      value: inactive\n",
			"      op: matches_in\n      field: payload.email\n      in_slot: accounts\n      remote_field: payload.email\n", "where"},
		{"unknown key in where", "      value: inactive\n", "      value: inactive\n      valu: x\n", "valu"},
		{"in_slot on other op", "    op: eq\n    field: account.active\n", "    op: eq\n    in_slot: roster\n    field: account.active\n", "in_slot"},
		{"undeclared slot in filter", "    op: eq\n    field: account.active\n    value: true\n",
			"    op: matches_in\n    field: account.key\n    in_slot: hr\n    remote_field: payload.email\n", `"hr"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := strings.Replace(rosterPassWhen, c.from, c.to, 1)
			if body == rosterPassWhen {
				t.Fatalf("test replacement %q did not apply", c.from)
			}
			_, err := spec.LoadPolicy([]byte(rosterPolicyHead + rosterSlots + body))
			if err == nil {
				t.Fatalf("want error containing %q; got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v; want it to contain %q", err, c.want)
			}
		})
	}
}

func TestLoadPolicy_RejectsBadSlotRoles(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"unknown role", "role: roster\n", "role: rooster\n", "rooster"},
		{"two roster slots", "role: roster_subject", "role: roster", "at most one"},
		{"subject without roster", "    role: roster\n", "", "roster_subject"},
		{"overlapping role types", "accepts: [directory_user, directory_user.v2]", "accepts: [directory_user, roster_entry]", "roster_entry"},
		{"unknown slot key", "    role: roster\n", "    rol: roster\n", "rol"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			slots := strings.Replace(rosterSlots, c.from, c.to, 1)
			if slots == rosterSlots {
				t.Fatalf("test replacement %q did not apply", c.from)
			}
			_, err := spec.LoadPolicy([]byte(rosterPolicyHead + slots + rosterPassWhen))
			if err == nil {
				t.Fatalf("want error containing %q; got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v; want it to contain %q", err, c.want)
			}
		})
	}
}

// A typo inside a pass_when clause must fail loading: the top-level
// decoder's KnownFields does not reach into the pass_when node.
func TestLoadPolicy_RejectsUnknownClauseKey(t *testing.T) {
	body := strings.Replace(rosterPassWhen, "identity_key:", "identity_keys:", 1)
	_, err := spec.LoadPolicy([]byte(rosterPolicyHead + rosterSlots + body))
	if err == nil || !strings.Contains(err.Error(), "identity_keys") {
		t.Fatalf("err = %v; want unknown field identity_keys", err)
	}
}

// Go-built policies never pass through the YAML loader, so the same rules
// must hold when validating a core.Policy directly.
func TestValidatePassWhen_CorePolicy(t *testing.T) {
	base := func() core.Policy {
		return core.Policy{
			ID: "p",
			Slots: map[string]core.Slot{
				testSlotRoster: {Accepts: []string{"roster_entry"}, Role: core.SlotRoleRoster},
				"accounts":     {Accepts: []string{"directory_user"}, Role: core.SlotRoleRosterSubject},
			},
			PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot:       "accounts",
				Quantifier: core.QuantifierAll,
				Condition: &core.PassWhenCondition{
					Op: core.OpMatchesIn, Field: "account.key", InSlot: testSlotRoster, RemoteField: "payload.email",
				},
			}}},
		}
	}
	if err := spec.ValidatePassWhen(base()); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if err := spec.ValidatePassWhen(core.Policy{ID: "manual"}); err != nil {
		t.Errorf("manual policy rejected: %v", err)
	}

	cases := map[string]func(p *core.Policy){
		"undeclared clause slot": func(p *core.Policy) { p.PassWhen.Clauses[0].Slot = "nope" },
		"bad normalize":          func(p *core.Policy) { p.PassWhen.Clauses[0].Condition.Normalize = "upper" },
		"missing field":          func(p *core.Policy) { p.PassWhen.Clauses[0].Condition.Field = "" },
		"matches_in nested in where": func(p *core.Policy) {
			p.PassWhen.Clauses[0].Condition.Where = &core.PassWhenCondition{Op: "all_of", Conditions: []*core.PassWhenCondition{
				{Op: core.OpMatchesIn, Field: "id", InSlot: testSlotRoster, RemoteField: "id"},
			}}
		},
		"invalid op": func(p *core.Policy) {
			p.PassWhen.Clauses[0].Condition = &core.PassWhenCondition{Op: "contains", Field: "id", Value: 1}
		},
		"bad role": func(p *core.Policy) { s := p.Slots[testSlotRoster]; s.Role = "boss"; p.Slots[testSlotRoster] = s },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(&p)
			if err := spec.ValidatePassWhen(p); err == nil {
				t.Error("want error; got nil")
			}
		})
	}
}
