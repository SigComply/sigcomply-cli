package okta

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func intPtr(v int) *int { return &v }

const (
	policyIDDefault = "00p1"
	policyIDSecond  = "00p2"
)

func mustWrite(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// oktaDefaults mirrors the complexity block Okta's own published example
// returns, including the null that example carries on minNumber.
func oktaDefaultPolicy() PasswordPolicy {
	return PasswordPolicy{
		ID:     policyIDDefault,
		Name:   "Default Policy",
		Status: oktaStatusActive,
		Settings: passwordPolicySettings{Password: passwordSettings{
			Complexity: passwordComplexity{
				MinLength:    intPtr(8),
				MinLowerCase: intPtr(1),
				MinUpperCase: intPtr(1),
				MinNumber:    nil,
				MinSymbol:    intPtr(0),
			},
			Age: passwordAge{MaxAgeDays: intPtr(0), HistoryCount: intPtr(4)},
		}},
	}
}

func collectPolicies(t *testing.T, api *fakeAPI) []core.EvidenceRecord {
	t.Helper()
	p := New(Options{API: api, Org: testOrgURL, Now: func() time.Time {
		return time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	}})
	recs, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypePasswordPolicy},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return recs
}

func policyPayload(t *testing.T, rec *core.EvidenceRecord) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Payload, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}

func TestPlugin_EmitsPasswordPolicy(t *testing.T) {
	var found bool
	for _, e := range (&Plugin{}).Emits() {
		if e == EvidenceTypePasswordPolicy {
			found = true
		}
	}
	if !found {
		t.Errorf("Emits() = %v; want it to include %q", (&Plugin{}).Emits(), EvidenceTypePasswordPolicy)
	}
}

// Okta states each min* complexity field as a count where 0 means "no" and
// 1 means "yes", so the four booleans are a faithful read rather than a
// lossy squeeze.
func TestCollectPasswordPolicies_MapsOktaSettings(t *testing.T) {
	recs := collectPolicies(t, &fakeAPI{policies: []PasswordPolicy{oktaDefaultPolicy()}})
	if len(recs) != 1 {
		t.Fatalf("records = %d; want 1", len(recs))
	}
	rec := recs[0]
	if rec.Type != EvidenceTypePasswordPolicy {
		t.Errorf("Type = %q; want %q", rec.Type, EvidenceTypePasswordPolicy)
	}
	if rec.ID != policyIDDefault {
		t.Errorf("ID = %q; want the Okta policy id", rec.ID)
	}
	if rec.SourceID != SourceID {
		t.Errorf("SourceID = %q; want %q", rec.SourceID, SourceID)
	}
	if rec.CollectedAt.IsZero() {
		t.Error("CollectedAt is zero")
	}

	got := policyPayload(t, &rec)
	want := map[string]any{
		"id":                     policyIDDefault,
		"provider":               "okta",
		"min_length":             float64(8),
		"max_age_days":           float64(0),
		"reuse_prevention_count": float64(4),
		"requires_uppercase":     true,
		"requires_lowercase":     true,
		"requires_numbers":       false, // null in Okta's own example
		"requires_symbols":       false, // explicit 0
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("payload[%q] = %#v; want %#v", k, got[k], v)
		}
	}
	// mfa_required is a separate Okta policy type, not a password attribute.
	if _, ok := got["mfa_required"]; ok {
		t.Errorf("payload carries mfa_required; Okta cannot answer it here: %#v", got)
	}
}

// A null complexity field means "not required" for the booleans — but for
// min_length a null must not be read as a configured 0, which would be a
// fabricated weakest posture rather than an observed one.
func TestCollectPasswordPolicies_NullsAreNotFabricatedZeroes(t *testing.T) {
	pol := oktaDefaultPolicy()
	pol.Settings.Password.Complexity = passwordComplexity{}
	pol.Settings.Password.Age = passwordAge{}

	recs := collectPolicies(t, &fakeAPI{policies: []PasswordPolicy{pol}})
	got := policyPayload(t, &recs[0])
	for _, field := range []string{"requires_uppercase", "requires_lowercase", "requires_numbers", "requires_symbols"} {
		if got[field] != false {
			t.Errorf("payload[%q] = %#v; want false when Okta reports nothing", field, got[field])
		}
	}
	// Okta documents its own default minimum as 8; absent means we did not
	// read a value, and the honest floor is the schema's "0 = no minimum".
	if got["min_length"] != float64(0) {
		t.Errorf("min_length = %#v; want 0 when unreported", got["min_length"])
	}
}

// An inactive policy governs nobody. Failing a control on a rule that is not
// in force would be a false finding.
func TestCollectPasswordPolicies_SkipsInactivePolicies(t *testing.T) {
	active := oktaDefaultPolicy()
	inactive := oktaDefaultPolicy()
	inactive.ID = policyIDSecond
	inactive.Status = "INACTIVE"

	recs := collectPolicies(t, &fakeAPI{policies: []PasswordPolicy{active, inactive}})
	if len(recs) != 1 {
		t.Fatalf("records = %d; want 1 (the inactive policy governs nobody)", len(recs))
	}
	if recs[0].ID != policyIDDefault {
		t.Errorf("ID = %q; want the active policy", recs[0].ID)
	}
}

// An org with several group-assigned policies emits one record each: the
// consuming policies quantify `all`, so the verdict is "every password
// policy in this org meets the bar".
func TestCollectPasswordPolicies_OneRecordPerPolicySortedByID(t *testing.T) {
	first := oktaDefaultPolicy()
	first.ID = "00pZZZ"
	second := oktaDefaultPolicy()
	second.ID = "00pAAA"
	second.Settings.Password.Complexity.MinLength = intPtr(14)

	recs := collectPolicies(t, &fakeAPI{policies: []PasswordPolicy{first, second}})
	if len(recs) != 2 {
		t.Fatalf("records = %d; want 2", len(recs))
	}
	if recs[0].ID != "00pAAA" || recs[1].ID != "00pZZZ" {
		t.Errorf("IDs = [%q %q]; want them sorted ascending", recs[0].ID, recs[1].ID)
	}
	// Distinct ids matter: violations are deduplicated by payload id, and
	// AWS's record is hardcoded to "account".
	if recs[0].ID == recs[1].ID {
		t.Error("records share an ID; violations would be deduplicated away")
	}
}

func TestCollectPasswordPolicies_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{policyErr: errors.New("boom")}, Org: testOrgURL})
	if _, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypePasswordPolicy},
	}); err == nil {
		t.Fatal("expected the list error to propagate")
	}
}

func TestCollectPasswordPolicies_NoPoliciesIsNotAnError(t *testing.T) {
	recs := collectPolicies(t, &fakeAPI{})
	if len(recs) != 0 {
		t.Errorf("records = %d; want 0", len(recs))
	}
}

// The conformance harness runs Collect twice and requires deep equality.
func TestCollectPasswordPolicies_UsesTheInjectedClock(t *testing.T) {
	fixed := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	p := New(Options{
		API: &fakeAPI{policies: []PasswordPolicy{oktaDefaultPolicy()}},
		Org: testOrgURL, Now: func() time.Time { return fixed },
	})
	recs, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypePasswordPolicy},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !recs[0].CollectedAt.Equal(fixed) {
		t.Errorf("CollectedAt = %s; want the injected %s", recs[0].CollectedAt, fixed)
	}
}

// A slot that does not accept password_policy must not trigger the call.
func TestCollectPasswordPolicies_NotFetchedWhenSlotDoesNotAcceptIt(t *testing.T) {
	api := &fakeAPI{policies: []PasswordPolicy{oktaDefaultPolicy()}}
	p := New(Options{API: api, Org: testOrgURL})
	if _, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypeApp},
	}); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if api.listPolicyCount != 0 {
		t.Errorf("ListPasswordPolicies called %d times; want 0", api.listPolicyCount)
	}
}

// Okta documents sending the pagination links as SEPARATE `link:` header
// lines, not one comma-joined value:
//
//	link: <…?limit=20>; rel="self"
//	link: <…?after=…>; rel="next"
//
// Go's Header.Get returns only the first of those. Reading just that one
// makes a run stop after page 1 whenever `self` is sent first — silently
// truncating collection, which for an `all` quantifier turns unseen
// records into a pass.
func TestNextLinkPath_HandlesSeparateLinkHeaderLines(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `<https://acme.okta.com/api/v1/users?limit=200>; rel="self"`)
	h.Add("Link", `<https://acme.okta.com/api/v1/users?after=cursor1&limit=200>; rel="next"`)

	got := nextLinkFromHeader(h, "https://acme.okta.com")
	want := "/api/v1/users?after=cursor1&limit=200"
	if got != want {
		t.Errorf("next = %q; want %q", got, want)
	}
}

// The comma-joined single-header form must keep working.
func TestNextLinkPath_HandlesCommaJoinedLinkHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Link", `<https://acme.okta.com/api/v1/users?limit=200>; rel="self", `+
		`<https://acme.okta.com/api/v1/users?after=cursor1&limit=200>; rel="next"`)

	got := nextLinkFromHeader(h, "https://acme.okta.com")
	want := "/api/v1/users?after=cursor1&limit=200"
	if got != want {
		t.Errorf("next = %q; want %q", got, want)
	}
}

func TestNextLinkPath_NoNextEndsPagination(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `<https://acme.okta.com/api/v1/users?limit=200>; rel="self"`)

	if got := nextLinkFromHeader(h, "https://acme.okta.com"); got != "" {
		t.Errorf("next = %q; want empty to end pagination", got)
	}
}

// End to end through the real HTTP stack: a server that splits the links
// across two header lines must still be paged to completion.
func TestHTTPAPI_Pagination_SeparateLinkHeaderLines(t *testing.T) {
	var srv *httptest.Server
	page := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<`+srv.URL+r.URL.Path+`>; rel="self"`)
		if page == 0 {
			page++
			w.Header().Add("Link", `<`+srv.URL+`/api/v1/policies?after=cursor1&limit=200&type=PASSWORD>; rel="next"`)
			w.Header().Set("Content-Type", "application/json")
			mustWrite(t, w, []byte(`[{"id":"00pA","status":"ACTIVE","settings":{"password":{"complexity":{"minLength":14}}}}]`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		mustWrite(t, w, []byte(`[{"id":"00pB","status":"ACTIVE","settings":{"password":{"complexity":{"minLength":8}}}}]`))
	}))
	defer srv.Close()

	api := &httpAPI{base: srv.URL, token: testToken, client: srv.Client()}
	got, err := api.ListPasswordPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPasswordPolicies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("policies = %d; want 2 — page 2 was not followed", len(got))
	}
}
