package github

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

const testLoginAlice = "alice"

// fakeAPI drives the plugin without real network calls.
type fakeAPI struct {
	repos   []Repo
	members []Member
	repoErr error
	memErr  error

	listReposCount   int
	listMembersCount int
}

func (f *fakeAPI) ListRepos(_ context.Context) ([]Repo, error) {
	f.listReposCount++
	if f.repoErr != nil {
		return nil, f.repoErr
	}
	return f.repos, nil
}

func (f *fakeAPI) ListOrgMembers(_ context.Context) ([]Member, error) {
	f.listMembersCount++
	if f.memErr != nil {
		return nil, f.memErr
	}
	return f.members, nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "acme"})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 2 || em[0] != EvidenceTypeRepository || em[1] != EvidenceTypeOrgMember {
		t.Errorf("Emits = %v", em)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "acme"})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func TestCollectRepos_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		repos: []Repo{
			{Name: "zeta", DefaultBranch: "main", ProtectionOn: false, RequiredReviews: 0},
			{Name: "alpha", DefaultBranch: "main", ProtectionOn: true, RequiredReviews: 2},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: "acme", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{EvidenceType: EvidenceTypeRepository, PolicyID: "p1"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	if records[0].ID != "alpha" || records[1].ID != "zeta" {
		t.Errorf("not sorted by ID: %v %v", records[0].ID, records[1].ID)
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v", i, records[i].CollectedAt)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
		if records[i].Type != EvidenceTypeRepository {
			t.Errorf("record[%d].Type = %q", i, records[i].Type)
		}
	}
	var alpha repoPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if !alpha.BranchProtectionEnabled || alpha.RequiredReviewersCount != 2 {
		t.Errorf("alpha payload = %+v", alpha)
	}
}

func TestCollectMembers_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		members: []Member{
			{Login: "bob", TwoFactorOn: false, Role: "member"},
			{Login: "alice", TwoFactorOn: true, Role: "admin"},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: "acme", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{EvidenceType: EvidenceTypeOrgMember, PolicyID: "p2"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	if records[0].ID != testLoginAlice || records[1].ID != "bob" {
		t.Errorf("not sorted: %v %v", records[0].ID, records[1].ID)
	}
	if records[0].IdentityKey != testLoginAlice {
		t.Errorf("IdentityKey not set: %q", records[0].IdentityKey)
	}
	var bob memberPayload
	if err := json.Unmarshal(records[1].Payload, &bob); err != nil {
		t.Fatalf("Unmarshal bob: %v", err)
	}
	if bob.TwoFAEnabled {
		t.Errorf("bob.TwoFAEnabled should be false")
	}
	if bob.Role != "member" {
		t.Errorf("bob.Role = %q", bob.Role)
	}
}

func TestCollect_NoData(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "acme"})
	for _, et := range []string{EvidenceTypeRepository, EvidenceTypeOrgMember} {
		recs, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: et})
		if err != nil {
			t.Fatalf("Collect %s: %v", et, err)
		}
		if len(recs) != 0 {
			t.Errorf("len = %d; want 0 for %s", len(recs), et)
		}
	}
}

func TestCollect_RejectsUnknownEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: "s3_bucket"})
	if err == nil || !strings.Contains(err.Error(), "unsupported evidence type") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollectRepos_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{repoErr: errors.New("rate limit")}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeRepository})
	if err == nil || !strings.Contains(err.Error(), "list repos") {
		t.Errorf("want list repos error; got %v", err)
	}
}

func TestCollectMembers_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{memErr: errors.New("forbidden")}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeOrgMember})
	if err == nil || !strings.Contains(err.Error(), "list org members") {
		t.Errorf("want list org members error; got %v", err)
	}
}

func TestCollect_DefaultNowIsInjected(t *testing.T) {
	fake := &fakeAPI{repos: []Repo{{Name: "r1", DefaultBranch: "main"}}}
	p := New(Options{API: fake, Org: "acme"})
	recs, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeRepository})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if recs[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now")
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{
		repos:   []Repo{{Name: "r1", DefaultBranch: "main"}},
		members: []Member{{Login: "alice", TwoFactorOn: true}},
	}
	p := New(Options{API: fake, Org: "acme"})
	for range 3 {
		if _, err := p.Collect(context.Background(),
			core.SlotRequest{EvidenceType: EvidenceTypeRepository}); err != nil {
			t.Fatalf("Collect repos: %v", err)
		}
		if _, err := p.Collect(context.Background(),
			core.SlotRequest{EvidenceType: EvidenceTypeOrgMember}); err != nil {
			t.Fatalf("Collect members: %v", err)
		}
	}
	if fake.listReposCount != 3 {
		t.Errorf("listReposCount = %d; want 3", fake.listReposCount)
	}
	if fake.listMembersCount != 3 {
		t.Errorf("listMembersCount = %d; want 3", fake.listMembersCount)
	}
}

func TestNewFromToken_ValidatesArgs(t *testing.T) {
	if _, err := NewFromToken(context.Background(), "", "tok"); err == nil {
		t.Error("want error for empty org")
	}
	if _, err := NewFromToken(context.Background(), "acme", ""); err == nil {
		t.Error("want error for empty token")
	}
	p, err := NewFromToken(context.Background(), "acme", "tok")
	if err != nil {
		t.Fatalf("NewFromToken: %v", err)
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

func TestHasNextLink(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{`<https://api.github.com/x?page=2>; rel="next"`, true},
		{`<https://api.github.com/x?page=2>; rel="prev"`, false},
		{`<https://x>; rel="next", <https://y>; rel="last"`, true},
	}
	for _, c := range cases {
		if got := hasNextLink(c.in); got != c.want {
			t.Errorf("hasNextLink(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

// --- HTTP adapter tests ----------------------------------------------------

func TestHTTPAPI_ListRepos_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/repos"):
			_, _ = w.Write([]byte(`[{"name":"web","default_branch":"main"},{"name":"api","default_branch":"main"}]`)) //nolint:errcheck // test handler
		case r.URL.Path == "/repos/acme/web/branches/main/protection":
			_, _ = w.Write([]byte(`{"required_pull_request_reviews":{"required_approving_review_count":2}}`)) //nolint:errcheck // test handler
		case r.URL.Path == "/repos/acme/api/branches/main/protection":
			http.Error(w, "not found", http.StatusNotFound)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	repos, err := api.ListRepos(context.Background())
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("len = %d", len(repos))
	}
	byName := map[string]Repo{}
	for _, r := range repos {
		byName[r.Name] = r
	}
	if !byName["web"].ProtectionOn || byName["web"].RequiredReviews != 2 {
		t.Errorf("web protection = %+v", byName["web"])
	}
	if byName["api"].ProtectionOn {
		t.Errorf("api should have no protection")
	}
}

func TestHTTPAPI_ListOrgMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/memberships/"):
			login := strings.TrimPrefix(r.URL.Path, "/orgs/acme/memberships/")
			if login == "alice" {
				_, _ = w.Write([]byte(`{"role":"admin"}`)) //nolint:errcheck // test handler
			} else {
				_, _ = w.Write([]byte(`{"role":"member"}`)) //nolint:errcheck // test handler
			}
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/members"):
			if r.URL.Query().Get("filter") == "2fa_disabled" {
				_, _ = w.Write([]byte(`[{"login":"bob"}]`)) //nolint:errcheck // test handler
				return
			}
			_, _ = w.Write([]byte(`[{"login":"alice"},{"login":"bob"}]`)) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	members, err := api.ListOrgMembers(context.Background())
	if err != nil {
		t.Fatalf("ListOrgMembers: %v", err)
	}
	byLogin := map[string]Member{}
	for _, m := range members {
		byLogin[m.Login] = m
	}
	if !byLogin["alice"].TwoFactorOn {
		t.Errorf("alice should have 2fa on")
	}
	if byLogin["bob"].TwoFactorOn {
		t.Errorf("bob should have 2fa off")
	}
	if byLogin["alice"].Role != "admin" {
		t.Errorf("alice.Role = %q", byLogin["alice"].Role)
	}
}

func TestHTTPAPI_AuthHeaderSet(t *testing.T) {
	var gotAuth, gotAPIVer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIVer = r.Header.Get("X-GitHub-Api-Version")
		_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{org: "acme", token: "sekrit", base: srv.URL, client: srv.Client()}
	if _, err := api.ListRepos(context.Background()); err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if gotAuth != "Bearer sekrit" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAPIVer == "" {
		t.Errorf("X-GitHub-Api-Version missing")
	}
}

func TestHTTPAPI_GetJSON_Non2xxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server fault", http.StatusInternalServerError)
	}))
	defer srv.Close()
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	_, err := api.ListRepos(context.Background())
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want 500 error; got %v", err)
	}
}

func TestHTTPAPI_GetJSON_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	_, err := api.ListRepos(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("want decode error; got %v", err)
	}
}

func TestHTTPAPI_ListRepos_Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			w.Header().Set("Link", `<http://x?page=2>; rel="next"`)
			_, _ = w.Write([]byte(`[{"name":"r1","default_branch":"main"}]`)) //nolint:errcheck // test handler
		case "2":
			_, _ = w.Write([]byte(`[{"name":"r2","default_branch":"main"}]`)) //nolint:errcheck // test handler
		default:
			if strings.Contains(r.URL.Path, "/protection") {
				http.Error(w, "no", http.StatusNotFound)
				return
			}
		}
	}))
	defer srv.Close()
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	repos, err := api.ListRepos(context.Background())
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Errorf("want 2 repos across pages; got %d", len(repos))
	}
}

func TestHTTPAPI_RequestCtxCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := api.ListRepos(ctx); err == nil {
		t.Errorf("want context-canceled error")
	}
}

// Tiny smoke test that confirms json roundtrip of the payload shapes — the
// marshal path inside Collect is otherwise covered by the happy-path tests.
func TestPayloadJSONRoundTrip(t *testing.T) {
	rp := repoPayload{Name: "r", DefaultBranch: "main", BranchProtectionEnabled: true, RequiredReviewersCount: 1}
	b, err := json.Marshal(rp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back repoPayload
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back != rp {
		t.Errorf("roundtrip mismatch: %+v vs %+v", back, rp)
	}
}
