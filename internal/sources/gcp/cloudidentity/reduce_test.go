package cloudidentity

import (
	"reflect"
	"testing"

	ciapi "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/googleapi"
)

// reduce_test.go covers the two things the Cloud Identity Policy API
// leaves to the caller: the ORDER (Google's sortOrder runs the opposite
// way from the schema's precedence, and a SYSTEM policy is a baseline
// rather than a decision) and the field-by-field REDUCTION (each policy
// carries only what an administrator explicitly set, so a fragment has to
// be completed before it describes a rule in force).

// pol builds one Policy resource. value is the raw setting JSON, so a
// test can express "this policy sets only minimumLength" literally,
// which is the case the whole reduction exists for.
func pol(name, typ string, sortOrder float64, q *ciapi.PolicyQuery, value string) *ciapi.Policy {
	if q == nil {
		q = &ciapi.PolicyQuery{}
	}
	q.SortOrder = sortOrder
	return &ciapi.Policy{
		Name:        name,
		Customer:    "customers/C03abc123",
		Type:        typ,
		PolicyQuery: q,
		Setting:     &ciapi.Setting{Type: settingTypePassword, Value: googleapi.RawMessage(value)},
	}
}

func orgUnit(id string) *ciapi.PolicyQuery { return &ciapi.PolicyQuery{OrgUnit: "orgUnits/" + id} }
func group(id string) *ciapi.PolicyQuery {
	return &ciapi.PolicyQuery{OrgUnit: "orgUnits/root", Group: "groups/" + id}
}

// TestRank_HighestSortOrderWinsAndAdminOutranksSystem pins the direction
// of the inversion. Google: highest sortOrder wins. The schema:
// precedence 1 wins. So rank() sorts DESCENDING and position 1 is the
// highest sortOrder — if this ever flips, every Google record reports the
// weakest policy as the governing one.
func TestRank_HighestSortOrderWinsAndAdminOutranksSystem(t *testing.T) {
	ranked, err := matchPasswordPolicies([]*ciapi.Policy{
		pol("policies/low", "ADMIN", 1, orgUnit("a"), `{}`),
		pol("policies/system", "SYSTEM", 9999, nil, `{}`),
		pol("policies/high", "ADMIN", 300, group("eng"), `{}`),
		pol("policies/mid", "ADMIN", 20, orgUnit("b"), `{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(ranked))
	for _, r := range ranked {
		got = append(got, r.id)
	}
	// Google shipped a BREAKING change to SYSTEM policies' name and
	// sortOrder on 2026-09-01, so a system sortOrder is not something to
	// trust against an administrator's explicit setting — here 9999 would
	// otherwise win outright. Type is compared first for exactly that
	// reason.
	want := []string{"policies/high", "policies/mid", "policies/low", "policies/system"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rank order = %v, want %v", got, want)
	}
}

// Two policies with an identical sortOrder must not reorder between runs
// — envelope bytes are signed, so unstable ordering is churn an auditor
// has to explain.
func TestRank_TiesBreakDeterministically(t *testing.T) {
	build := func() []string {
		ranked, err := matchPasswordPolicies([]*ciapi.Policy{
			pol("policies/zzz", "ADMIN", 5, orgUnit("a"), `{}`),
			pol("policies/aaa", "ADMIN", 5, orgUnit("b"), `{}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		return []string{ranked[0].id, ranked[1].id}
	}
	first, second := build(), build()
	if !reflect.DeepEqual(first, second) || first[0] != "policies/aaa" {
		t.Errorf("tie-break unstable or wrong: %v then %v", first, second)
	}
}

// TestMatch_ClientSideFilterKeepsOnlyThePasswordSetting: the listing
// carries every setting type the customer has (gmail.*, drive.*, …)
// because no server-side filter is used. Anything that is not the
// password setting must be dropped without being decoded — decoding a
// gmail setting as a password one would error the run.
func TestMatch_ClientSideFilterKeepsOnlyThePasswordSetting(t *testing.T) {
	other := &ciapi.Policy{
		Name:        "policies/gmail",
		PolicyQuery: &ciapi.PolicyQuery{},
		Setting: &ciapi.Setting{
			Type:  "settings/gmail.service_status",
			Value: googleapi.RawMessage(`{"serviceState":"ENABLED"}`),
		},
	}
	ranked, err := matchPasswordPolicies([]*ciapi.Policy{
		other,
		{Name: "policies/nil_setting"},
		nil,
		pol("policies/pw", "ADMIN", 1, nil, `{"minimumLength":12}`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ranked) != 1 || ranked[0].id != "policies/pw" {
		t.Fatalf("matched %+v; want only policies/pw", ranked)
	}
}

func TestQueryScope(t *testing.T) {
	cases := []struct {
		name string
		q    *ciapi.PolicyQuery
		want string
	}{
		{"nil_query_governs_the_customer", nil, scopeAccount},
		{"empty_query_governs_the_customer", &ciapi.PolicyQuery{}, scopeAccount},
		{"org_unit", orgUnit("eng"), scopeOrgUnit},
		// Google sets BOTH helper fields when a query names a group inside
		// an org unit. The narrower population is the one the record
		// describes, so group wins.
		{"group_inside_an_org_unit_is_a_group", group("contractors"), scopeGroup},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := queryScope(tc.q); got != tc.want {
				t.Errorf("queryScope = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolve_TakesEachFieldFromTheHighestRankedPolicyThatSetsIt is the
// reduction itself. Three policies each set a different field; the
// top-ranked record must end up carrying all three, because that is what
// its population actually experiences.
func TestResolve_TakesEachFieldFromTheHighestRankedPolicyThatSetsIt(t *testing.T) {
	ranked, err := matchPasswordPolicies([]*ciapi.Policy{
		pol("policies/top", "ADMIN", 300, group("eng"), `{"minimumLength":16}`),
		pol("policies/mid", "ADMIN", 200, orgUnit("eng"), `{"expirationDuration":"7776000s","minimumLength":12}`),
		pol("policies/base", "ADMIN", 100, orgUnit("root"), `{"allowReuse":true,"allowedStrength":"WEAK","minimumLength":8}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	top := resolve(ranked, 0)
	if top.minLength != 16 {
		t.Errorf("top min_length = %d, want 16 (its own value wins)", top.minLength)
	}
	if top.maxAgeDays != 90 {
		t.Errorf("top max_age_days = %d, want 90 (inherited from policies/mid)", top.maxAgeDays)
	}
	if top.reusePrevented {
		t.Error("top reuse_prevented = true, want false (allowReuse true, inherited from policies/base)")
	}
	if top.passwordStrength != strengthWeak {
		t.Errorf("top password_strength = %q, want %q (inherited from policies/base)", top.passwordStrength, strengthWeak)
	}
	// Nothing fell through to a Google default: every field was set by
	// SOMEBODY, which is what `defaulted` must not claim otherwise.
	if len(top.defaulted) != 0 {
		t.Errorf("top defaulted = %v, want empty — every field was explicitly set somewhere", top.defaulted)
	}

	// The middle policy inherits downward only: it must NOT pick up the
	// top policy's minimumLength 16, because a higher-ranked policy
	// governs a narrower population and says nothing about this one.
	mid := resolve(ranked, 1)
	if mid.minLength != 12 {
		t.Errorf("mid min_length = %d, want 12 (never inherits upward)", mid.minLength)
	}

	// The base policy sets no expiry, and nothing below it does either, so
	// this is the one field that reaches Google's documented default.
	base := resolve(ranked, 2)
	if base.maxAgeDays != defaultExpirationDays {
		t.Errorf("base max_age_days = %d, want the documented default %d", base.maxAgeDays, defaultExpirationDays)
	}
	if !reflect.DeepEqual(base.defaulted, []string{attrMaxAgeDays}) {
		t.Errorf("base defaulted = %v, want [%s] only", base.defaulted, attrMaxAgeDays)
	}
}

// TestResolve_EmptyPolicyIsEveryDocumentedDefault, Marked: the case (d)
// decision. Google returns only explicitly-set values and its own
// contract defines an omission as "the default applies", so the value is
// reported — and every one of them is named in `defaulted` so an auditor
// reads the value AND where it came from.
func TestResolve_EmptyPolicyIsEveryDocumentedDefaultMarked(t *testing.T) {
	ranked, err := matchPasswordPolicies([]*ciapi.Policy{pol("policies/only", "ADMIN", 1, nil, `{}`)})
	if err != nil {
		t.Fatal(err)
	}
	eff := resolve(ranked, 0)
	if eff.minLength != defaultMinimumLength {
		t.Errorf("min_length = %d, want %d", eff.minLength, defaultMinimumLength)
	}
	if eff.maxAgeDays != defaultExpirationDays {
		t.Errorf("max_age_days = %d, want %d", eff.maxAgeDays, defaultExpirationDays)
	}
	// allowReuse defaults to false, and the schema states the CONTROL
	// rather than the permission — so the default is "reuse IS prevented".
	if !eff.reusePrevented {
		t.Error("reuse_prevented = false, want true (allowReuse defaults false → reuse prevented)")
	}
	if eff.passwordStrength != strengthStrong || !eff.strengthKnown {
		t.Errorf("password_strength = %q/%v, want strong/true", eff.passwordStrength, eff.strengthKnown)
	}
	want := []string{attrMinLength, attrMaxAgeDays, attrReuse, attrComplexity}
	if !reflect.DeepEqual(eff.defaulted, want) {
		t.Errorf("defaulted = %v, want %v", eff.defaulted, want)
	}
}

// An explicitly-set field is never marked defaulted — the marker's only
// job is to separate "the administrator chose this" from "nobody chose
// and Google's default is in force", and a marker that fires on both says
// nothing.
func TestResolve_ExplicitValuesAreNotMarkedDefaulted(t *testing.T) {
	ranked, err := matchPasswordPolicies([]*ciapi.Policy{
		pol("policies/only", "ADMIN", 1, nil,
			`{"minimumLength":14,"expirationDuration":"7776000s","allowReuse":false,"allowedStrength":"STRONG"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	eff := resolve(ranked, 0)
	if len(eff.defaulted) != 0 {
		t.Errorf("defaulted = %v, want empty", eff.defaulted)
	}
	if eff.minLength != 14 || eff.maxAgeDays != 90 || !eff.reusePrevented || eff.passwordStrength != strengthStrong {
		t.Errorf("effective = %+v; want 14/90/prevented/strong", eff)
	}
}

// An allowedStrength this plugin does not recognize — a new enum arm, or
// ALLOWED_STRENGTH_UNSPECIFIED — must report "cannot answer" rather than
// guessing `strong` (a green tick on an unread value) or erroring (a
// customer's CI broken because Google extended an enum). And it must NOT
// be marked defaulted: nothing defaulted, the value was simply unreadable.
func TestMapStrength_UnknownArmIsNotAnAnswerAndNotADefault(t *testing.T) {
	ranked, err := matchPasswordPolicies([]*ciapi.Policy{
		pol("policies/only", "ADMIN", 1, nil, `{"allowedStrength":"ALLOWED_STRENGTH_UNSPECIFIED"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	eff := resolve(ranked, 0)
	if eff.strengthKnown || eff.passwordStrength != "" {
		t.Errorf("strength = %q/%v, want unknown", eff.passwordStrength, eff.strengthKnown)
	}
	for _, a := range eff.defaulted {
		if a == attrComplexity {
			t.Error("complexity marked defaulted; it was unreadable, not defaulted")
		}
	}
}

func TestMapStrength_IsCaseInsensitive(t *testing.T) {
	for _, in := range []string{"STRONG", "strong", " Strong "} {
		if got, ok := mapStrength(in); !ok || got != strengthStrong {
			t.Errorf("mapStrength(%q) = %q/%v", in, got, ok)
		}
	}
	if got, ok := mapStrength(googleStrengthWeak); !ok || got != strengthWeak {
		t.Errorf("mapStrength(WEAK) = %q/%v", got, ok)
	}
}

// A decode failure anywhere in the listing stops the whole match: the
// alternative is emitting the policies that did decode and silently
// dropping the one that did not, which reports a partial estate as a
// complete one.
func TestMatch_PropagatesADecodeFailure(t *testing.T) {
	_, err := matchPasswordPolicies([]*ciapi.Policy{
		pol("policies/ok", "ADMIN", 2, nil, `{"minimumLength":12}`),
		pol("policies/bad", "ADMIN", 1, nil, `{"expirationDuration":"90d"}`),
	})
	if err == nil {
		t.Fatal("matchPasswordPolicies succeeded; want the decode error to propagate")
	}
}
