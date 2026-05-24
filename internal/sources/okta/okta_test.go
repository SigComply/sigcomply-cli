package okta

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without real network calls.
type fakeAPI struct {
	users   []User
	apps    []App
	userErr error
	appErr  error

	listUsersCount int
	listAppsCount  int
}

func (f *fakeAPI) ListUsers(_ context.Context) ([]User, error) {
	f.listUsersCount++
	if f.userErr != nil {
		return nil, f.userErr
	}
	return f.users, nil
}

func (f *fakeAPI) ListApps(_ context.Context) ([]App, error) {
	f.listAppsCount++
	if f.appErr != nil {
		return nil, f.appErr
	}
	return f.apps, nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "https://acme.okta.com"})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 2 || em[0] != EvidenceTypeUser || em[1] != EvidenceTypeApp {
		t.Errorf("Emits = %v", em)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "https://acme.okta.com"})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func TestCollectUsers_HappyPath_SortsByID(t *testing.T) {
	last := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeAPI{
		users: []User{
			{ID: "u_zzz", Email: "z@acme.com", Status: "ACTIVE", MFAFactorCount: 1, LastLogin: last},
			{ID: "u_aaa", Email: "a@acme.com", Status: "ACTIVE", MFAFactorCount: 0},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeUser}, PolicyID: "p1"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	if records[0].ID != "u_aaa" || records[1].ID != "u_zzz" {
		t.Errorf("not sorted: %v %v", records[0].ID, records[1].ID)
	}
	if records[0].IdentityKey != "a@acme.com" {
		t.Errorf("IdentityKey = %q", records[0].IdentityKey)
	}
	var first userPayload
	if err := json.Unmarshal(records[0].Payload, &first); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if first.MFAFactorCount != 0 {
		t.Errorf("u_aaa factor count = %d", first.MFAFactorCount)
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v", i, records[i].CollectedAt)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}
}

func TestCollectApps_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		apps: []App{
			{ID: "0oab", Label: "Slack", SignOnMode: "SAML_2_0", MFARequired: true},
			{ID: "0oaa", Label: "Legacy", SignOnMode: "AUTO_LOGIN", MFARequired: false},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeApp}, PolicyID: "p2"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].ID != "0oaa" || records[1].ID != "0oab" {
		t.Errorf("not sorted: %v %v", records[0].ID, records[1].ID)
	}
	var legacy appPayload
	if err := json.Unmarshal(records[0].Payload, &legacy); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if legacy.MFARequired {
		t.Errorf("legacy.MFARequired should be false")
	}
	if records[0].IdentityKey != "" {
		t.Errorf("app records should not set IdentityKey; got %q", records[0].IdentityKey)
	}
}

func TestCollect_NoData(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	for _, et := range []string{EvidenceTypeUser, EvidenceTypeApp} {
		recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{et}})
		if err != nil {
			t.Fatalf("Collect %s: %v", et, err)
		}
		if len(recs) != 0 {
			t.Errorf("len = %d; want 0 for %s", len(recs), et)
		}
	}
}

func TestCollect_RejectsUnknownEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"github_repository"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollectUsers_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{userErr: errors.New("rate limit")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeUser}})
	if err == nil || !strings.Contains(err.Error(), "list users") {
		t.Errorf("want list users error; got %v", err)
	}
}

func TestCollectApps_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{appErr: errors.New("forbidden")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeApp}})
	if err == nil || !strings.Contains(err.Error(), "list apps") {
		t.Errorf("want list apps error; got %v", err)
	}
}

func TestCollect_DefaultNowIsInjected(t *testing.T) {
	fake := &fakeAPI{users: []User{{ID: "u1", Email: "u@acme.com", Status: "ACTIVE"}}}
	p := New(Options{API: fake})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeUser}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if recs[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now")
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{
		users: []User{{ID: "u1", Email: "u@acme.com", Status: "ACTIVE"}},
		apps:  []App{{ID: "0oa1", Label: "X", SignOnMode: "SAML_2_0", MFARequired: true}},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(),
			core.SlotRequest{AcceptedTypes: []string{EvidenceTypeUser}}); err != nil {
			t.Fatalf("Collect users: %v", err)
		}
		if _, err := p.Collect(context.Background(),
			core.SlotRequest{AcceptedTypes: []string{EvidenceTypeApp}}); err != nil {
			t.Fatalf("Collect apps: %v", err)
		}
	}
	if fake.listUsersCount != 3 || fake.listAppsCount != 3 {
		t.Errorf("counts = users:%d apps:%d; want 3/3", fake.listUsersCount, fake.listAppsCount)
	}
}

func TestNewFromConfig_ValidatesArgs(t *testing.T) {
	if _, err := NewFromConfig(context.Background(), "", "tok"); err == nil {
		t.Error("want error for empty orgURL")
	}
	if _, err := NewFromConfig(context.Background(), "https://acme.okta.com", ""); err == nil {
		t.Error("want error for empty token")
	}
	p, err := NewFromConfig(context.Background(), "https://acme.okta.com/", "tok")
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

func TestFederatedMFA(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"SAML_2_0", true},
		{"OPENID_CONNECT", true},
		{"SECURE_PASSWORD_STORE", true},
		{"AUTO_LOGIN", false},
		{"BROWSER_PLUGIN", false},
		{"", false},
		{"saml_2_0", true},
	}
	for _, c := range cases {
		if got := federatedMFA(c.mode); got != c.want {
			t.Errorf("federatedMFA(%q) = %v; want %v", c.mode, got, c.want)
		}
	}
}

func TestNextLinkPath(t *testing.T) {
	base := "https://acme.okta.com"
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{`<https://acme.okta.com/api/v1/users?after=X>; rel="next"`, "/api/v1/users?after=X"},
		{`<https://acme.okta.com/api/v1/users>; rel="self"`, ""},
		{`<https://acme.okta.com/api/v1/users?after=Y>; rel="next", <https://acme.okta.com/api/v1/users>; rel="self"`, "/api/v1/users?after=Y"},
		{`<malformed`, ""},
	}
	for _, c := range cases {
		if got := nextLinkPath(c.in, base); got != c.want {
			t.Errorf("nextLinkPath(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// --- HTTP adapter tests ----------------------------------------------------

func TestHTTPAPI_ListUsers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/users":
			const body = `[{"id":"u1","status":"ACTIVE","lastLogin":"2026-05-01T10:00:00Z","profile":{"email":"a@x.com"}},` +
				`{"id":"u2","status":"PROVISIONED","profile":{"email":"b@x.com"}}]`
			_, _ = w.Write([]byte(body)) //nolint:errcheck // test handler
		case "/api/v1/users/u1/factors":
			_, _ = w.Write([]byte(`[{"id":"f1","status":"ACTIVE"},{"id":"f2","status":"PENDING_ACTIVATION"}]`)) //nolint:errcheck // test handler
		case "/api/v1/users/u2/factors":
			_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	api := &httpAPI{base: srv.URL, token: "tok", client: srv.Client()}
	users, err := api.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("len = %d", len(users))
	}
	byID := map[string]User{}
	for _, u := range users {
		byID[u.ID] = u
	}
	if byID["u1"].MFAFactorCount != 1 {
		t.Errorf("u1 active factors = %d; want 1", byID["u1"].MFAFactorCount)
	}
	if byID["u1"].LastLogin.IsZero() {
		t.Errorf("u1 LastLogin not parsed")
	}
	if byID["u2"].MFAFactorCount != 0 {
		t.Errorf("u2 factors = %d", byID["u2"].MFAFactorCount)
	}
}

func TestHTTPAPI_ListApps_HappyPath(t *testing.T) {
	const body = `[{"id":"0oa1","label":"Slack","signOnMode":"SAML_2_0","status":"ACTIVE"},` +
		`{"id":"0oa2","label":"Legacy","signOnMode":"AUTO_LOGIN","status":"ACTIVE"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{base: srv.URL, token: "tok", client: srv.Client()}
	apps, err := api.ListApps(context.Background())
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	byID := map[string]App{}
	for _, a := range apps {
		byID[a.ID] = a
	}
	if !byID["0oa1"].MFARequired {
		t.Errorf("Slack should be MFA required (SAML)")
	}
	if byID["0oa2"].MFARequired {
		t.Errorf("Legacy should not be MFA required (AUTO_LOGIN)")
	}
}

func TestHTTPAPI_AuthHeaderSet(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{base: srv.URL, token: "sekrit", client: srv.Client()}
	if _, err := api.ListApps(context.Background()); err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	if gotAuth != "SSWS sekrit" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestHTTPAPI_GetJSON_Non2xxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	api := &httpAPI{base: srv.URL, token: "tok", client: srv.Client()}
	_, err := api.ListUsers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("want 429 error; got %v", err)
	}
}

func TestHTTPAPI_GetJSON_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{base: srv.URL, token: "tok", client: srv.Client()}
	_, err := api.ListApps(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("want decode error; got %v", err)
	}
}

func TestHTTPAPI_ListUsers_Pagination(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/factors") {
			_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
			return
		}
		if r.URL.RawQuery == "limit=200" {
			w.Header().Set("Link", `<`+base+`/api/v1/users?after=p2>; rel="next"`)
			_, _ = w.Write([]byte(`[{"id":"u1","status":"ACTIVE","profile":{"email":"a@x.com"}}]`)) //nolint:errcheck // test handler
			return
		}
		_, _ = w.Write([]byte(`[{"id":"u2","status":"ACTIVE","profile":{"email":"b@x.com"}}]`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	base = srv.URL
	api := &httpAPI{base: srv.URL, token: "tok", client: srv.Client()}
	users, err := api.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("want 2 users across pages; got %d", len(users))
	}
}

func TestHTTPAPI_RequestCtxCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{base: srv.URL, token: "tok", client: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := api.ListApps(ctx); err == nil {
		t.Errorf("want context-canceled error")
	}
}

func TestPayloadJSONRoundTrip(t *testing.T) {
	up := userPayload{ID: "u1", Email: "e@x.com", Status: "ACTIVE", MFAFactorCount: 2}
	b, err := json.Marshal(up)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back userPayload
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back != up {
		t.Errorf("roundtrip mismatch: %+v vs %+v", back, up)
	}
}
