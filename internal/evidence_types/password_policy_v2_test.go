package evidencetypes

// password_policy_v2_test.go pins the shape of the password_policy.v2
// discriminated union.
//
// v2 exists because v1 could only be filled by a vendor that answers
// complexity as four character-class booleans. The cases below are
// therefore written as "can each plausible source emit an honest record?"
// rather than as field-by-field assertions: an AWS per-class singleton, an
// Okta group-scoped per-class policy, a Google-shaped strength_enum
// policy, an Entra-shaped record that can answer expiry and nothing else,
// and an account with no password policy at all. The last two are the ones
// v1 made impossible — v1 required all eight fields, so a source that
// cannot read six of them had no way to emit anything.
//
// The negative cases guard the union itself: naming a complexity_model
// obliges the source to carry that model's answer, and a reuse depth
// obliges the boolean it refines. Without those, "complexity_model":
// "per_class" with no booleans would validate and the clause reading them
// would error at evaluation time on evidence the operator already paid to
// collect.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// passwordPolicyV2TypeID is the registered type ID (the schema's title).
const passwordPolicyV2TypeID = "password_policy.v2"

// wantUnionErr is the fragment gojsonschema reports when an if/then arm
// of the discriminated union is unsatisfied ("Must validate \"then\" as
// \"if\" was valid"). The message names the keyword rather than the
// missing field, so the assertion matches on the keyword.
const wantUnionErr = "then"

func passwordPolicyV2Schema(t *testing.T) core.EvidenceType {
	t.Helper()
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, ok := set.EvidenceTypes.Lookup(passwordPolicyV2TypeID)
	if !ok {
		t.Fatalf("%s not registered", passwordPolicyV2TypeID)
	}
	if et.Version != 2 {
		t.Errorf("version = %d; want 2", et.Version)
	}
	return et
}

func TestPasswordPolicyV2_EveryPlausibleSourceCanEmit(t *testing.T) {
	et := passwordPolicyV2Schema(t)
	cases := []struct {
		name    string
		payload string
	}{
		{
			// AWS IAM: one policy per account, every attribute configurable.
			name: "aws_per_class_singleton",
			payload: `{"id":"account","provider":"aws","scope":"account","precedence":1,
				"min_length":14,"max_age_days":90,"reuse_prevented":true,"reuse_prevention_count":24,
				"complexity_model":"per_class","requires_uppercase":true,"requires_lowercase":true,
				"requires_numbers":true,"requires_symbols":true}`,
		},
		{
			// Okta: several group-assigned policies, ranked against each other.
			name: "okta_per_class_ranked_group_policy",
			payload: `{"id":"00pEngineering","name":"Engineering Password Policy","provider":"okta",
				"scope":"group","precedence":1,"min_length":14,"max_age_days":90,
				"reuse_prevented":true,"reuse_prevention_count":24,"complexity_model":"per_class",
				"requires_uppercase":true,"requires_lowercase":true,"requires_numbers":true,
				"requires_symbols":true}`,
		},
		{
			// Google Workspace: allowedStrength is STRONG|WEAK and the vendor
			// states it is not a character-class rule, so per_class is not
			// available to it. allowReuse is a bare boolean with no depth.
			name: "google_strength_enum_per_org_unit",
			payload: `{"id":"policies/abc","name":"Engineering OU","provider":"google_workspace",
				"scope":"org_unit","precedence":2,"min_length":12,"max_age_days":0,
				"reuse_prevented":true,"complexity_model":"strength_enum","password_strength":"strong"}`,
		},
		{
			// Entra: Graph answers expiry per verified domain and nothing
			// else. Length and complexity are Microsoft constants with no
			// tenant setting, so the values stay absent and not_configurable
			// records WHY they are absent. This record is the one v1 could
			// not express at all.
			name: "entra_expiry_only_per_domain",
			payload: `{"id":"example.com","provider":"entra","scope":"domain","max_age_days":90,
				"complexity_model":"fixed",
				"complexity_description":"three of four character classes, enforced by the platform for cloud-only accounts and not tenant-configurable",
				"not_configurable":["min_length","reuse","complexity"]}`,
		},
		{
			// An AWS account with no password policy configured: the zeros
			// here are observed (AWS said NoSuchEntity), not unread.
			name: "no_policy_configured_is_an_observed_none",
			payload: `{"id":"account","provider":"aws","scope":"account","precedence":1,
				"min_length":0,"max_age_days":0,"reuse_prevented":false,"reuse_prevention_count":0,
				"complexity_model":"none"}`,
		},
		{
			// Google Cloud Identity: the Policy API returns only the fields
			// an administrator explicitly set, and Google's own contract
			// defines an omitted field as "the documented default applies".
			// So the value is real and is reported — with `defaulted` naming
			// which of them came from the default rather than from a choice.
			name: "google_defaulted_fields_carry_the_value_and_the_marker",
			payload: `{"id":"policies/abc","provider":"google_workspace","scope":"org_unit",
				"precedence":1,"min_length":8,"max_age_days":0,"reuse_prevented":true,
				"complexity_model":"strength_enum","password_strength":"strong",
				"defaulted":["min_length","max_age_days","reuse","complexity"]}`,
		},
		{
			// A tenant that set everything explicitly emits no marker at
			// all — `defaulted` is omitted, exactly as not_configurable is
			// omitted when everything is configurable.
			name: "google_fully_configured_carries_no_defaulted_marker",
			payload: `{"id":"policies/abc","provider":"google_workspace","scope":"org_unit",
				"precedence":1,"min_length":12,"max_age_days":90,"reuse_prevented":true,
				"complexity_model":"strength_enum","password_strength":"strong"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(et.Schema, json.RawMessage(tc.payload)); err != nil {
				t.Errorf("expected valid, got: %v", err)
			}
		})
	}
}

func TestPasswordPolicyV2_UnionAndRequiredFieldsEnforced(t *testing.T) {
	et := passwordPolicyV2Schema(t)
	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		{
			name:    "missing_provider",
			payload: `{"id":"account","scope":"account"}`,
			wantErr: "provider",
		},
		{
			name:    "missing_scope",
			payload: `{"id":"account","provider":"aws"}`,
			wantErr: "scope",
		},
		{
			name:    "scope_outside_enum",
			payload: `{"id":"account","provider":"aws","scope":"everybody"}`,
			wantErr: "scope",
		},
		{
			// per_class without the booleans validates in a bottom-up schema
			// and errors at evaluation instead. The union forbids it here.
			name:    "per_class_without_booleans",
			payload: `{"id":"account","provider":"aws","scope":"account","complexity_model":"per_class"}`,
			wantErr: wantUnionErr,
		},
		{
			name:    "strength_enum_without_rating",
			payload: `{"id":"p1","provider":"google_workspace","scope":"org_unit","complexity_model":"strength_enum"}`,
			wantErr: wantUnionErr,
		},
		{
			name:    "fixed_without_description",
			payload: `{"id":"example.com","provider":"entra","scope":"domain","complexity_model":"fixed"}`,
			wantErr: wantUnionErr,
		},
		{
			name:    "strength_rating_outside_enum",
			payload: `{"id":"p1","provider":"google_workspace","scope":"org_unit","complexity_model":"strength_enum","password_strength":"medium"}`,
			wantErr: "password_strength",
		},
		{
			// A depth with no boolean would let a clause read the depth on
			// one source and the boolean on another with no overlap.
			name:    "reuse_depth_without_the_boolean_it_refines",
			payload: `{"id":"account","provider":"aws","scope":"account","reuse_prevention_count":24}`,
			wantErr: wantUnionErr,
		},
		{
			name:    "complexity_model_outside_enum",
			payload: `{"id":"account","provider":"aws","scope":"account","complexity_model":"entropy"}`,
			wantErr: "complexity_model",
		},
		{
			name:    "not_configurable_outside_enum",
			payload: `{"id":"example.com","provider":"entra","scope":"domain","not_configurable":["lockout"]}`,
			wantErr: "not_configurable",
		},
		{
			// defaulted shares not_configurable's vocabulary deliberately:
			// the two answer the same question ("why does this field read
			// the way it does?") about the same four attributes, and a
			// second, drifting spelling of the same names would make them
			// impossible to read together.
			name:    "defaulted_outside_enum",
			payload: `{"id":"policies/abc","provider":"google_workspace","scope":"org_unit","defaulted":["maximum_length"]}`,
			wantErr: "defaulted",
		},
		{
			name:    "defaulted_repeats_an_attribute",
			payload: `{"id":"policies/abc","provider":"google_workspace","scope":"org_unit","defaulted":["min_length","min_length"]}`,
			wantErr: "defaulted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(et.Schema, json.RawMessage(tc.payload))
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// v1 stays registered and unchanged: a project-local plugin may still emit
// it, and the six password policies accept both versions so that such a
// plugin keeps binding. Deleting v1 would make those records unbindable
// and the policies would skip in silence.
func TestPasswordPolicyV1_StillRegisteredAndUnchanged(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, ok := set.EvidenceTypes.Lookup("password_policy")
	if !ok {
		t.Fatal("password_policy (v1) is no longer registered")
	}
	var schema struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(et.Schema, &schema); err != nil {
		t.Fatalf("parse v1 schema: %v", err)
	}
	if len(schema.Required) != 8 {
		t.Errorf("v1 required = %v; want the original eight (v1 is frozen, not edited)", schema.Required)
	}
}
