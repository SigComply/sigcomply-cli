package cloudidentity

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"golang.org/x/oauth2"
	ciapi "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// cloudidentity_test.go is the plugin's L1 suite, and it is deliberately
// the WHOLE automated suite: there is no L2 cassette here. Google
// publishes no sample response body for settings/security.password, so a
// hand-authored cassette would record our own guesses and then assert
// them against the code that made them — permanent green, zero
// information, and indistinguishable from coverage at a glance. See the
// package doc and docs/architecture/12-multicloud-sources.md; recording a
// cassette against a real tenant (the same one cloudidentity_live_test.go
// needs) is what closes it.

var fixedNow = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// Shared fixture literals, named so goconst stays quiet.
const (
	testDelegatedSA = "dwd@proj.iam.gserviceaccount.com"
	testSuperAdmin  = "admin@acme.com"
)

type fakeAPI struct {
	policies []*ciapi.Policy
	err      error
	calls    int
}

func (f *fakeAPI) ListPolicies(context.Context) ([]*ciapi.Policy, error) {
	f.calls++
	return f.policies, f.err
}

func newPlugin(policies ...*ciapi.Policy) *Plugin {
	return New(Options{API: &fakeAPI{policies: policies}, Now: func() time.Time { return fixedNow }})
}

func collect(t *testing.T, p *Plugin) []core.EvidenceRecord {
	t.Helper()
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return recs
}

func payload(t *testing.T, r *core.EvidenceRecord) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Payload, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

// TestCollect_Conformance runs the shared harness (schema validation,
// completeness, determinism, metadata) over a realistic two-policy
// tenant. The exempt list is the set of v2 fields Google structurally
// cannot answer: it has no per-class booleans (allowedStrength is an
// opaque rating and Google says so), no history depth at all, no policy
// display name, no sign-on MFA attribute on a password policy — and
// not_configurable is absent because every attribute here IS
// configurable, which is exactly what makes `defaulted` the right marker
// instead.
func TestCollect_Conformance(t *testing.T) {
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin: newPlugin(
			pol("policies/base", "ADMIN", 100, orgUnit("root"),
				`{"minimumLength":12,"expirationDuration":"7776000s","allowReuse":false,"allowedStrength":"STRONG"}`),
			pol("policies/eng", "ADMIN", 300, group("eng"), `{"minimumLength":16}`),
		),
		Request:       core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}},
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		WantScope:     &core.RecordScope{Account: "C03abc123"},
		OptionalFields: []string{
			"password_policy.v2.name",
			"password_policy.v2.reuse_prevention_count",
			"password_policy.v2.requires_uppercase", "password_policy.v2.requires_lowercase",
			"password_policy.v2.requires_numbers", "password_policy.v2.requires_symbols",
			"password_policy.v2.complexity_description",
			"password_policy.v2.not_configurable",
			"password_policy.v2.mfa_required",
			// Absent here on purpose: this tenant set every attribute, so
			// there is nothing to mark. TestCollect_DefaultedMarksTheValue
			// covers the present case.
			"password_policy.v2.defaulted",
		},
	})
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
}

// TestCollect_RankAndScopeReachTheRecord pins what an auditor reads: the
// group policy outranks the org-unit one (higher sortOrder wins in
// Google, and precedence 1 wins in the schema — opposite directions,
// inverted in reduce.go), and each record says which population it
// governs.
func TestCollect_RankAndScopeReachTheRecord(t *testing.T) {
	recs := collect(t, newPlugin(
		pol("policies/base", "ADMIN", 100, orgUnit("root"), `{"minimumLength":12}`),
		pol("policies/eng", "ADMIN", 300, group("eng"), `{"minimumLength":16}`),
	))
	byID := map[string]map[string]any{}
	for _, r := range recs {
		byID[r.ID] = payload(t, &r)
	}
	if got := byID["policies/eng"]["precedence"]; got != float64(1) {
		t.Errorf("policies/eng precedence = %v, want 1 (highest sortOrder wins)", got)
	}
	if got := byID["policies/base"]["precedence"]; got != float64(2) {
		t.Errorf("policies/base precedence = %v, want 2", got)
	}
	if got := byID["policies/eng"]["scope"]; got != scopeGroup {
		t.Errorf("policies/eng scope = %v, want %q", got, scopeGroup)
	}
	if got := byID["policies/base"]["scope"]; got != scopeOrgUnit {
		t.Errorf("policies/base scope = %v, want %q", got, scopeOrgUnit)
	}
	if got := byID["policies/eng"]["min_length"]; got != float64(16) {
		t.Errorf("policies/eng min_length = %v, want its own 16", got)
	}
}

// TestCollect_NoPasswordPolicyEmitsNoRecords: whether a tenant always has
// at least one security.password policy is unverified, so zero is handled
// as a real outcome. Nothing is synthesized from Google's documented
// defaults — with no policy resource returned there is no evidence the
// API answered about a password policy at all, and the defaults would
// then be read out of a manual and signed. Every consuming clause is
// is_set-guarded, so this lands as a vacuous clause rather than a verdict.
func TestCollect_NoPasswordPolicyEmitsNoRecords(t *testing.T) {
	other := &ciapi.Policy{
		Name:        "policies/gmail",
		PolicyQuery: &ciapi.PolicyQuery{},
		Setting:     &ciapi.Setting{Type: "settings/gmail.service_status", Value: googleapi.RawMessage(`{}`)},
	}
	for _, tc := range []struct {
		name     string
		policies []*ciapi.Policy
	}{
		{"empty_listing", nil},
		{"listing_without_the_password_setting", []*ciapi.Policy{other}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs := collect(t, newPlugin(tc.policies...))
			if len(recs) != 0 {
				t.Errorf("records = %d, want 0 (never synthesize a record from documented defaults)", len(recs))
			}
		})
	}
}

// TestCollect_DecodeFailureIsAnErrorNotAZero is the guard that matters
// most. A failed decode that fell through to Go zeros would emit
// max_age_days 0 — which the expiry policy PASSES, because 0 is the
// schema's observed-no-expiry. The bug would ship as a green tick, so it
// has to stop the run instead.
func TestCollect_DecodeFailureIsAnErrorNotAZero(t *testing.T) {
	p := newPlugin(pol("policies/bad", "ADMIN", 1, nil, `{"expirationDuration":"90 days"}`))
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil {
		t.Fatalf("Collect succeeded with %d records; want a hard error", len(recs))
	}
	if !errors.Is(err, errDecode) {
		t.Errorf("err = %v, want errDecode", err)
	}
	if len(recs) != 0 {
		t.Errorf("records = %d, want 0 — a partial estate must not be reported as a complete one", len(recs))
	}
}

// TestCollect_DefaultedMarksTheValueAndKeepsIt is the (d) decision, at
// the wire. A tenant that never touched the password settings still gets
// a record with every value in force, and `defaulted` says every one of
// them came from Google's default rather than from an administrator.
// Emitting absence instead would be worse than useless: the clauses are
// is_set-guarded, so the record would vacuously pass all six and the
// collector would fail to close the gap it exists to close.
func TestCollect_DefaultedMarksTheValueAndKeepsIt(t *testing.T) {
	recs := collect(t, newPlugin(pol("policies/only", "ADMIN", 1, nil, `{}`)))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := payload(t, &recs[0])
	want := map[string]any{
		"id":                "policies/only",
		"provider":          providerGoogle,
		"scope":             scopeAccount,
		"precedence":        float64(1),
		"min_length":        float64(defaultMinimumLength),
		"max_age_days":      float64(defaultExpirationDays),
		"reuse_prevented":   true,
		"complexity_model":  complexityStrengthEnum,
		"password_strength": strengthStrong,
		"defaulted":         []any{attrMinLength, attrMaxAgeDays, attrReuse, attrComplexity},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload =\n%#v\nwant\n%#v", got, want)
	}
}

// TestCollect_NoFieldIsAnAccidentalZero asserts the property the payload
// struct's lack of pointers rests on: every emitted value came from
// either a decoded non-nil pointer or a named default constant. With a
// policy that sets every attribute to a NON-default value, no emitted
// field may equal its Go zero unless the tenant genuinely chose it — so a
// mapper that forgot to wire a field shows up here as a zero where a 14,
// a 30 or a "weak" belongs.
func TestCollect_NoFieldIsAnAccidentalZero(t *testing.T) {
	recs := collect(t, newPlugin(pol("policies/only", "ADMIN", 1, orgUnit("eng"),
		`{"minimumLength":14,"expirationDuration":"2592000s","allowReuse":true,"allowedStrength":"WEAK"}`)))
	got := payload(t, &recs[0])
	want := map[string]any{
		"id":                "policies/only",
		"provider":          providerGoogle,
		"scope":             scopeOrgUnit,
		"precedence":        float64(1),
		"min_length":        float64(14),
		"max_age_days":      float64(30),
		"reuse_prevented":   false, // allowReuse true → the control is OFF
		"complexity_model":  complexityStrengthEnum,
		"password_strength": strengthWeak,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload =\n%#v\nwant\n%#v", got, want)
	}
	// reuse_prevented false is the one legitimately-zero value above, and
	// it is the tenant's own answer (allowReuse: true) rather than a hole.
	// `defaulted` must therefore be absent entirely — a marker that fired
	// here would label an administrator's choice as a Google default.
	if _, present := got["defaulted"]; present {
		t.Error("defaulted present on a fully-configured policy")
	}
}

// An unreadable allowedStrength omits BOTH complexity fields together —
// complexity_model without password_strength fails the schema's
// discriminated union, and the schema is what stops a half-answer from
// reaching a clause.
func TestCollect_UnknownStrengthOmitsBothComplexityFields(t *testing.T) {
	recs := collect(t, newPlugin(pol("policies/only", "ADMIN", 1, nil,
		`{"minimumLength":14,"allowedStrength":"SOMETHING_NEW"}`)))
	got := payload(t, &recs[0])
	if _, present := got["complexity_model"]; present {
		t.Error("complexity_model emitted for an unrecognized allowedStrength")
	}
	if _, present := got["password_strength"]; present {
		t.Error("password_strength emitted for an unrecognized allowedStrength")
	}
}

// The customer stamp is read from the API's own Policy.Customer, never
// from config: a provenance stamp that might disagree with the credential
// is worse than none, and this one is observed rather than declared.
func TestCollect_ScopeComesFromTheApiAndIsOmittedWhenAbsent(t *testing.T) {
	withCustomer := collect(t, newPlugin(pol("policies/a", "ADMIN", 1, nil, `{}`)))
	if withCustomer[0].Scope == nil || withCustomer[0].Scope.Account != "C03abc123" {
		t.Errorf("Scope = %+v, want Account C03abc123", withCustomer[0].Scope)
	}
	bare := pol("policies/a", "ADMIN", 1, nil, `{}`)
	bare.Customer = ""
	if recs := collect(t, newPlugin(bare)); recs[0].Scope != nil {
		t.Errorf("Scope = %+v, want nil when the API reported no customer", recs[0].Scope)
	}
}

func TestCollect_RejectsASlotThatDoesNotWantTheType(t *testing.T) {
	_, err := newPlugin().Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil {
		t.Fatal("Collect accepted a slot that does not want password_policy.v2")
	}
}

func TestCollect_PropagatesAListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("boom")}, Now: func() time.Time { return fixedNow }})
	if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err == nil {
		t.Fatal("Collect swallowed a list error")
	}
}

// Records are returned ID-sorted (the shared harness requires it and
// envelope bytes depend on it) while the reduction still reads in rank
// order. The rank survives in `precedence`, which is the readable place
// for it.
func TestCollect_RecordsAreIDSortedWhileRankSurvivesInPrecedence(t *testing.T) {
	recs := collect(t, newPlugin(
		pol("policies/zzz", "ADMIN", 900, orgUnit("a"), `{}`),
		pol("policies/aaa", "ADMIN", 100, orgUnit("b"), `{}`),
	))
	ids := []string{recs[0].ID, recs[1].ID}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("record IDs = %v, want ascending", ids)
	}
	if got := payload(t, &recs[1])["precedence"]; got != float64(1) {
		t.Errorf("policies/zzz precedence = %v, want 1 (its sortOrder is the highest)", got)
	}
}

func TestPluginMetadata(t *testing.T) {
	p := newPlugin()
	if p.ID() != SourceID {
		t.Errorf("ID = %q, want %q", p.ID(), SourceID)
	}
	if !reflect.DeepEqual(p.Emits(), []string{EvidenceTypeID}) {
		t.Errorf("Emits = %v, want [%s]", p.Emits(), EvidenceTypeID)
	}
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// --- auth / factory -------------------------------------------------

func TestAuthConfig_SubjectWithoutTargetIsAConfigError(t *testing.T) {
	err := AuthConfig{ImpersonateSubject: testSuperAdmin}.Validate()
	if !errors.Is(err, errSubjectWithoutTarget) {
		t.Errorf("err = %v, want errSubjectWithoutTarget", err)
	}
	if err := (AuthConfig{TargetServiceAccount: testDelegatedSA, ImpersonateSubject: testSuperAdmin}).Validate(); err != nil {
		t.Errorf("valid delegation config rejected: %v", err)
	}
}

// The delegated scope must be the readonly policies scope VERBATIM: a
// super admin allow-lists that exact string in the Admin console, and a
// broader scope is rejected with unauthorized_client rather than accepted
// as a superset. Requesting anything else here would break every
// domain-wide-delegation deployment, silently, at token-mint time.
func TestClientOptions_RequestsTheVerbatimReadonlyScope(t *testing.T) {
	var got impersonate.CredentialsConfig
	orig := newTokenSource
	t.Cleanup(func() { newTokenSource = orig })
	newTokenSource = func(_ context.Context, cfg impersonate.CredentialsConfig, _ ...option.ClientOption) (oauth2.TokenSource, error) {
		got = cfg
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"}), nil
	}

	if _, err := clientOptions(context.Background(), AuthConfig{
		TargetServiceAccount: testDelegatedSA,
		ImpersonateSubject:   testSuperAdmin,
	}); err != nil {
		t.Fatalf("clientOptions: %v", err)
	}
	want := "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
	if !reflect.DeepEqual(got.Scopes, []string{want}) {
		t.Errorf("scopes = %v, want exactly [%s]", got.Scopes, want)
	}
	if got.Subject != testSuperAdmin || got.TargetPrincipal != testDelegatedSA {
		t.Errorf("credentials config = %+v", got)
	}
}

// Without impersonation the plugin asks for the same scope on plain ADC,
// and mints no impersonated token at all.
func TestClientOptions_PlainADCUsesTheSameReadonlyScope(t *testing.T) {
	orig := newTokenSource
	t.Cleanup(func() { newTokenSource = orig })
	calls := 0
	newTokenSource = func(context.Context, impersonate.CredentialsConfig, ...option.ClientOption) (oauth2.TokenSource, error) {
		calls++
		return nil, errors.New("must not be called")
	}
	opts, err := clientOptions(context.Background(), AuthConfig{})
	if err != nil {
		t.Fatalf("clientOptions: %v", err)
	}
	if !reflect.DeepEqual(opts, []option.ClientOption{option.WithScopes(ciapi.CloudIdentityPoliciesReadonlyScope)}) {
		t.Errorf("opts = %#v", opts)
	}
	if calls != 0 {
		t.Errorf("newTokenSource calls = %d, want 0 without impersonation", calls)
	}
}

// The factory must be registered and must declare every config key it
// reads, or a typo in `sources:` produces silence instead of a warning.
func TestFactoryIsRegisteredWithItsConfigKeys(t *testing.T) {
	if _, ok := sources.Lookup(SourceID); !ok {
		t.Fatalf("%s is not registered", SourceID)
	}
	want := []string{"impersonate_subject", "target_service_account"}
	if got := sources.ConfigKeys(SourceID); !reflect.DeepEqual(got, want) {
		t.Errorf("config keys = %v, want %v", got, want)
	}
}

func TestFactory_RejectsSubjectWithoutTarget(t *testing.T) {
	_, err := build(context.Background(), sources.Env{Config: map[string]any{"impersonate_subject": testSuperAdmin}})
	if !errors.Is(err, errSubjectWithoutTarget) {
		t.Errorf("err = %v, want errSubjectWithoutTarget", err)
	}
}

// --- pacing ---------------------------------------------------------

// The Policy API's quota is 1 QPS PER CUSTOMER and Google does not raise
// it, so the real adapter waits between pages rather than discovering the
// limit as a 429 and spending the collector's retry budget on it. The
// wait must still honor cancellation: a paced listing that ignores it
// holds the whole run open for as many seconds as the tenant has pages.
func TestWait_HonoursCancellationAndSkipsAZeroInterval(t *testing.T) {
	if err := wait(context.Background(), 0); err != nil {
		t.Errorf("wait(0) = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("wait on a canceled context = %v, want context.Canceled", err)
	}
}
