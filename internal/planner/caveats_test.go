package planner

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/identitycenter"
)

const (
	slotEvidence  = "evidence"
	fieldMFA      = "mfa_enabled"
	srcIdentityCe = "aws.identity_center"
)

// fieldsReadBySlot is the static half of the caveat check: it must see every
// field path a clause reads, wherever it hides. Each case below is a shape
// that one of the existing clause walkers in this repo gets wrong.
func TestFieldsReadBySlot(t *testing.T) {
	leafC := func(field string) *core.PassWhenCondition {
		return &core.PassWhenCondition{Op: "eq", Field: field, Value: true}
	}

	cases := []struct {
		name string
		spec *core.PassWhenSpec
		want map[string][]string
	}{
		{
			name: "condition leaf",
			spec: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot: slotEvidence, Quantifier: core.QuantifierAll, Condition: leafC("payload." + fieldMFA),
			}}},
			want: map[string][]string{slotEvidence: {fieldMFA}},
		},
		{
			// TestEveryFilterGuardsOptionalFields only walks filters; a
			// condition-only reference must not be missed.
			name: "filter and condition both counted",
			spec: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot: slotEvidence, Quantifier: core.QuantifierAll,
				Filter:    leafC("payload.is_root"),
				Condition: leafC("payload." + fieldMFA),
			}}},
			want: map[string][]string{slotEvidence: {"is_root", fieldMFA}},
		},
		{
			// The admin-MFA policies bury mfa_enabled inside an all_of, so a
			// top-level Field read returns "".
			name: "nested all_of",
			spec: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot: slotEvidence, Quantifier: core.QuantifierNone,
				Condition: &core.PassWhenCondition{Op: "all_of", Conditions: []*core.PassWhenCondition{
					leafC("payload.is_admin"), leafC("payload." + fieldMFA),
				}},
			}}},
			want: map[string][]string{slotEvidence: {"is_admin", fieldMFA}},
		},
		{
			// RemoteField is read against records in InSlot, NOT the clause's
			// own slot — attributing it to the clause slot would warn about
			// the wrong source. collectMatchesIn does not descend Where at all.
			// The clause's own Field here is account.key, a virtual namespace
			// rather than a payload read, so the accounts slot contributes
			// nothing — caveats are declared on payload fields only.
			name: "matches_in attributes remote field to the remote slot",
			spec: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot: "accounts", Quantifier: core.QuantifierAll,
				Condition: &core.PassWhenCondition{
					Op: core.OpMatchesIn, Field: "account.key",
					InSlot: "roster", RemoteField: "payload.email",
					Where: leafC("payload.is_active"),
				},
			}}},
			want: map[string][]string{"roster": {"email", "is_active"}},
		},
		{
			name: "identity key is a field path on the clause slot",
			spec: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot: slotEvidence, Quantifier: core.QuantifierAll,
				Condition: leafC("payload." + fieldMFA), IdentityKey: "payload.email",
			}}},
			want: map[string][]string{slotEvidence: {"email", fieldMFA}},
		},
		{
			name: "nested payload path keeps only the root key",
			spec: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot: slotEvidence, Quantifier: core.QuantifierAll,
				Condition: leafC("payload.encryption.kms_key_id"),
			}}},
			want: map[string][]string{slotEvidence: {"encryption"}},
		},
		{
			name: "nil spec reads nothing",
			spec: nil,
			want: map[string][]string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fieldsReadBySlot(tc.spec)
			flat := map[string][]string{}
			for slot, fields := range got {
				names := make([]string, 0, len(fields))
				for f := range fields {
					names = append(names, f)
				}
				sort.Strings(names)
				flat[slot] = names
			}
			if !reflect.DeepEqual(flat, tc.want) {
				t.Errorf("fieldsReadBySlot = %v; want %v", flat, tc.want)
			}
		})
	}
}

// caveatStub is a source plugin that declares caveats.
type caveatStub struct {
	id      string
	emits   []string
	caveats []core.SourceCaveat
}

func (c *caveatStub) ID() string                                 { return c.id }
func (c *caveatStub) Emits() []string                            { return c.emits }
func (c *caveatStub) Init(context.Context, map[string]any) error { return nil }
func (c *caveatStub) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}
func (c *caveatStub) Caveats() []core.SourceCaveat { return c.caveats }

// plainStub declares no caveats at all — it must not be treated as caveated.
type plainStub struct {
	id    string
	emits []string
}

func (p *plainStub) ID() string                                 { return p.id }
func (p *plainStub) Emits() []string                            { return p.emits }
func (p *plainStub) Init(context.Context, map[string]any) error { return nil }
func (p *plainStub) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, nil
}

func mfaPolicy() *core.Policy {
	return &core.Policy{
		ID:    "test.mfa",
		Slots: map[string]core.Slot{slotEvidence: {Accepts: []string{evDirectoryUser}, Cardinality: core.SlotOneOrMore}},
		PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
			Slot: slotEvidence, Quantifier: core.QuantifierAll,
			Condition: &core.PassWhenCondition{Op: "eq", Field: "payload." + fieldMFA, Value: true},
		}}},
	}
}

func caveatRegistry(t *testing.T, plugins ...core.SourcePlugin) *registry.Registry[core.SourcePlugin] {
	t.Helper()
	reg := registry.NewSourceRegistry()
	for _, p := range plugins {
		if err := reg.Register(p); err != nil {
			t.Fatalf("register %s: %v", p.ID(), err)
		}
	}
	return reg
}

var ssoCaveat = core.SourceCaveat{
	EvidenceType: evDirectoryUser, Field: "mfa_enabled",
	Detail: "no per-user MFA API",
}

func TestCaveatWarnings(t *testing.T) {
	sso := &caveatStub{id: srcIdentityCe, emits: []string{evDirectoryUser}, caveats: []core.SourceCaveat{ssoCaveat}}
	idp := &plainStub{id: srcOkta, emits: []string{evDirectoryUser}}
	bind := func(ids ...string) map[string][]Binding {
		out := make([]Binding, 0, len(ids))
		for _, id := range ids {
			out = append(out, Binding{SourceID: id, AcceptedTypes: []string{evDirectoryUser}})
		}
		return map[string][]Binding{slotEvidence: out}
	}

	t.Run("caveated source alongside one that can answer names the pin target", func(t *testing.T) {
		got := caveatWarnings(mfaPolicy(), bind(srcIdentityCe, srcOkta), caveatRegistry(t, sso, idp))
		if len(got) != 1 {
			t.Fatalf("warnings = %d; want 1: %+v", len(got), got)
		}
		if got[0].SourceID != srcIdentityCe || got[0].Field != fieldMFA {
			t.Errorf("warning = %+v", got[0])
		}
		// This is the whole point: okta is bound to the same slot and its
		// records are unioned with the unverifiable ones.
		if !reflect.DeepEqual(got[0].Alternatives, []string{srcOkta}) {
			t.Errorf("Alternatives = %v; want [okta]", got[0].Alternatives)
		}
	})

	t.Run("sole caveated source has nothing to pin to", func(t *testing.T) {
		got := caveatWarnings(mfaPolicy(), bind(srcIdentityCe), caveatRegistry(t, sso))
		if len(got) != 1 {
			t.Fatalf("warnings = %d; want 1", len(got))
		}
		// Suggesting a bindings: pin here would be advice to pin the slot to
		// the only source already on it. The finding is genuine instead.
		if len(got[0].Alternatives) != 0 {
			t.Errorf("Alternatives = %v; want none", got[0].Alternatives)
		}
	})

	t.Run("no warning when no policy clause reads the field", func(t *testing.T) {
		pol := mfaPolicy()
		pol.PassWhen.Clauses[0].Condition.Field = "payload.is_active"
		if got := caveatWarnings(pol, bind(srcIdentityCe), caveatRegistry(t, sso)); len(got) != 0 {
			t.Errorf("warnings = %+v; want none — a caveat on an unread field costs the policy nothing", got)
		}
	})

	t.Run("no warning when the binding does not accept the caveated type", func(t *testing.T) {
		b := map[string][]Binding{slotEvidence: {{SourceID: srcIdentityCe, AcceptedTypes: []string{evDirectoryUserV2}}}}
		if got := caveatWarnings(mfaPolicy(), b, caveatRegistry(t, sso)); len(got) != 0 {
			t.Errorf("warnings = %+v; want none", got)
		}
	})

	t.Run("uncaveated sources alone produce nothing", func(t *testing.T) {
		if got := caveatWarnings(mfaPolicy(), bind(srcOkta), caveatRegistry(t, idp)); len(got) != 0 {
			t.Errorf("warnings = %+v; want none", got)
		}
	})
}

// The whole chain on real inputs: the shipped SOC 2 MFA policies, the real
// aws.identity_center plugin's own caveat, and a second identity source on
// the same slot. Stubs can agree with each other and still be wrong about
// what ships — this is the test that would catch a policy rewrite hiding
// mfa_enabled somewhere the walker does not look.
func TestCaveatWarnings_ShippedMFAPolicies(t *testing.T) {
	sso := identitycenter.New(identitycenter.Options{})
	reg := caveatRegistry(t, sso, &plainStub{id: srcOkta, emits: []string{evDirectoryUser}})
	// Bind through the real binder rather than hand-building bindings: the
	// AcceptedTypes intersection is exactly what keeps a v2-only slot from
	// reporting a caveat on a v1-only source.
	configured := map[string]map[string]any{sso.ID(): {}, srcOkta: {}}

	// Policies that read mfa_enabled on a slot accepting directory_user.
	want := map[string]bool{
		"soc2.cc6.1.mfa_enforced_all_users": true,
		"soc2.cc6.1.mfa_enforced_admins":    true,
	}
	seen := map[string]bool{}
	for _, pol := range soc2.Policies() {
		p := pol
		if p.EvidenceMode != core.EvidenceModeAutomated {
			continue
		}
		bindings, err := resolveBindings(&p, nil, reg, configured)
		if err != nil {
			t.Fatalf("policy %s: resolveBindings: %v", p.ID, err)
		}
		got := caveatWarnings(&p, bindings, reg)
		if len(got) == 0 {
			continue
		}
		seen[p.ID] = true
		if got[0].Field != fieldMFA || got[0].SourceID != sso.ID() {
			t.Errorf("policy %s: warning = %+v", p.ID, got[0])
		}
		if !reflect.DeepEqual(got[0].Alternatives, []string{srcOkta}) {
			t.Errorf("policy %s: Alternatives = %v; want [okta]", p.ID, got[0].Alternatives)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("shipped policy %s reads mfa_enabled but produced no caveat warning", id)
		}
	}
	// root_mfa_enabled accepts directory_user.v2 only, which Identity Center
	// does not emit, so it must NOT warn — the binding would never happen.
	if seen["soc2.cc6.1.root_mfa_enabled"] {
		t.Error("root_mfa_enabled warned, but Identity Center emits v1 and cannot bind that slot")
	}
}
