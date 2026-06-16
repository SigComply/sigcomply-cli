package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without real network calls.
type fakeAPI struct {
	repos     []Repo
	repoErr   error
	members   []Member
	memberErr error

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

func (f *fakeAPI) ListMembers(_ context.Context) ([]Member, error) {
	f.listMembersCount++
	if f.memberErr != nil {
		return nil, f.memberErr
	}
	return f.members, nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 2 || em[0] != EvidenceTypeRepository || em[1] != EvidenceTypeDirectoryUser {
		t.Errorf("Emits = %v; want [%q %q]", em, EvidenceTypeRepository, EvidenceTypeDirectoryUser)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func TestCollectRepos_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		repos: []Repo{
			{Name: "acme/zeta", DefaultBranch: "main", ProtectionOn: false, RequiredReviews: 0},
			{Name: "acme/alpha", DefaultBranch: "main", ProtectionOn: true, RequiredReviews: 2},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}, PolicyID: "p1"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	if records[0].ID != "acme/alpha" || records[1].ID != "acme/zeta" {
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
	if !alpha.DefaultBranchProtected || alpha.RequiredReviewersCount != 2 {
		t.Errorf("alpha payload = %+v", alpha)
	}
}

// TestCollectRepos_EmitsRequiredFields guards the null-trap: every
// policy-read property must be present in the emitted JSON (an absent
// field errors the consuming policy rather than reading as false).
func TestCollectRepos_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{repos: []Repo{{Name: "acme/r1", DefaultBranch: "main"}}}
	p := New(Options{API: fake})
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(recs[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{
		"name", "default_branch", "default_branch_protected", "required_reviewers_count",
		"allows_force_push", "requires_signed_commits", "requires_linear_history",
		"dependabot_alerts_enabled", "code_scanning_enabled", "dismiss_stale_reviews",
		"require_code_owner_reviews", "secret_scanning_enabled", "push_protection_enabled",
		"is_private", "archived",
	} {
		if _, ok := m[field]; !ok {
			t.Errorf("emitted payload missing field %q", field)
		}
	}
}

func TestCollect_RejectsUnknownEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "does not include emitted types") {
		t.Errorf("want rejection error; got %v", err)
	}
}

func TestCollectRepos_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{repoErr: errors.New("rate limit")}})
	_, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}})
	if err == nil || !strings.Contains(err.Error(), "list repos") {
		t.Errorf("want 'list repos' error; got %v", err)
	}
}

func TestCollectMembers_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		members: []Member{
			{Username: "zoe", Name: "Zoe Z", Email: "zoe@acme.io", MFAEnabled: false, IsAdmin: false, IsActive: true},
			{Username: "amy", Name: "Amy A", Email: "amy@acme.io", MFAEnabled: true, IsAdmin: true, IsActive: true},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}, PolicyID: "p1"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	if records[0].ID != "amy" || records[1].ID != "zoe" {
		t.Errorf("not sorted by ID: %v %v", records[0].ID, records[1].ID)
	}
	for i := range records {
		assertMemberRecordMeta(t, i, &records[i], now)
	}
	var amy memberPayload
	if err := json.Unmarshal(records[0].Payload, &amy); err != nil {
		t.Fatalf("Unmarshal amy: %v", err)
	}
	want := memberPayload{
		ID: "amy", DisplayName: "Amy A", Email: "amy@acme.io",
		MFAEnabled: true, IsAdmin: true, IsActive: true,
	}
	if amy != want {
		t.Errorf("amy payload = %+v; want %+v", amy, want)
	}
}

// assertMemberRecordMeta checks the non-payload envelope fields of a
// directory_user record. IdentityKey is the username (stable per-source
// identity), so it must equal the record ID.
func assertMemberRecordMeta(t *testing.T, i int, rec *core.EvidenceRecord, now time.Time) {
	t.Helper()
	if rec.Type != EvidenceTypeDirectoryUser {
		t.Errorf("record[%d].Type = %q", i, rec.Type)
	}
	if rec.SourceID != SourceID {
		t.Errorf("record[%d].SourceID = %q", i, rec.SourceID)
	}
	if rec.CollectedAt != now {
		t.Errorf("record[%d].CollectedAt = %v", i, rec.CollectedAt)
	}
	if rec.IdentityKey != rec.ID {
		t.Errorf("record[%d].IdentityKey = %q; want %q", i, rec.IdentityKey, rec.ID)
	}
}

// TestCollectMembers_EmitsRequiredFields guards the null-trap for the
// directory_user payload: every policy-read property must be present.
func TestCollectMembers_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{members: []Member{{Username: "u1"}}}
	p := New(Options{API: fake})
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(recs[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{"id", "display_name", "mfa_enabled", "is_admin", "is_active"} {
		if _, ok := m[field]; !ok {
			t.Errorf("emitted payload missing field %q", field)
		}
	}
}

func TestCollectMembers_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{memberErr: errors.New("rate limit")}})
	_, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "list members") {
		t.Errorf("want 'list members' error; got %v", err)
	}
}

// TestCollect_BothTypes verifies a slot accepting both emitted types
// receives repos and members together in one call.
func TestCollect_BothTypes(t *testing.T) {
	fake := &fakeAPI{
		repos:   []Repo{{Name: "acme/r1", DefaultBranch: "main"}},
		members: []Member{{Username: "u1", IsActive: true}},
	}
	p := New(Options{API: fake})
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository, EvidenceTypeDirectoryUser}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var repos, members int
	for _, r := range recs {
		switch r.Type {
		case EvidenceTypeRepository:
			repos++
		case EvidenceTypeDirectoryUser:
			members++
		}
	}
	if repos != 1 || members != 1 {
		t.Errorf("got repos=%d members=%d; want 1,1", repos, members)
	}
}

func TestCollect_DefaultNowIsInjected(t *testing.T) {
	fake := &fakeAPI{repos: []Repo{{Name: "acme/r1", DefaultBranch: "main"}}}
	p := New(Options{API: fake}) // Now nil → time.Now().UTC()
	before := time.Now().UTC()
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if recs[0].CollectedAt.Before(before) || recs[0].CollectedAt.After(time.Now().UTC()) {
		t.Errorf("CollectedAt %v outside [%v, now]", recs[0].CollectedAt, before)
	}
}

// TestCollect_KISSNoDRY_EachCallReFetches asserts the plugin caches
// nothing across Collect calls.
func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{repos: []Repo{{Name: "acme/r1", DefaultBranch: "main"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(),
			core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listReposCount != 3 {
		t.Errorf("listReposCount = %d; want 3", fake.listReposCount)
	}
}

func TestNewFromToken_ValidatesArgs(t *testing.T) {
	if _, err := NewFromToken(context.Background(), "", "tok", ""); err == nil {
		t.Error("want error for empty group")
	}
	if _, err := NewFromToken(context.Background(), "acme", "", ""); err == nil {
		t.Error("want error for empty token")
	}
	if _, err := NewFromToken(context.Background(), "acme", "tok", ""); err != nil {
		t.Errorf("valid args: %v", err)
	}
}

// TestSDKAPI_ListRepos_HappyPath exercises the real GitLab SDK adapter
// against an httptest server, verifying the per-project follow-up reads
// and the GitLab→git_repository field mapping. "web" is fully protected;
// "api" exercises the unprotected / 404 / public paths.
func TestSDKAPI_ListRepos_HappyPath(t *testing.T) {
	// Path→body table keeps the handler's complexity low; paths absent
	// from both maps are unexpected; paths in notFound return 404 (the
	// adapter's degrade-gracefully path for unprotected branches / no
	// push rule on free tier).
	responses := map[string]string{
		"/api/v4/groups/acme/projects": `[` +
			`{"id":7,"path_with_namespace":"acme/web","default_branch":"main",` +
			`"visibility":"private","archived":false,"merge_method":"ff",` +
			`"pre_receive_secret_detection_enabled":true},` +
			`{"id":8,"path_with_namespace":"acme/api","default_branch":"main",` +
			`"visibility":"public","archived":false,"merge_method":"merge",` +
			`"pre_receive_secret_detection_enabled":false}]`,
		"/api/v4/projects/7/protected_branches/main": `{"name":"main","allow_force_push":false,"code_owner_approval_required":true}`,
		"/api/v4/projects/7/approval_rules":          `[{"id":1,"rule_type":"any_approver","approvals_required":2}]`,
		"/api/v4/projects/8/approval_rules":          `[]`,
		"/api/v4/projects/7/approvals":               `{"reset_approvals_on_push":true}`,
		"/api/v4/projects/8/approvals":               `{"reset_approvals_on_push":false}`,
		"/api/v4/projects/7/push_rule":               `{"id":1,"reject_unsigned_commits":true}`,
	}
	notFound := map[string]bool{
		"/api/v4/projects/8/protected_branches/main": true,
		"/api/v4/projects/8/push_rule":               true,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := responses[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body)) //nolint:errcheck // test handler
			return
		}
		if notFound[r.URL.Path] {
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		t.Errorf("unexpected request: %s", r.URL.Path)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("tok", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	api := &sdkAPI{client: client, group: "acme"}
	repos, err := api.ListRepos(context.Background())
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("len = %d; want 2", len(repos))
	}
	byName := map[string]Repo{}
	for _, r := range repos {
		byName[r.Name] = r
	}
	web := byName["acme/web"]
	if web.RequiredReviews != 2 {
		t.Errorf("web.RequiredReviews = %d; want 2", web.RequiredReviews)
	}
	checks := []struct {
		name string
		got  bool
		want bool
	}{
		{"web.ProtectionOn", web.ProtectionOn, true},
		{"web.AllowsForcePush", web.AllowsForcePush, false},
		{"web.RequireCodeOwnerReviews", web.RequireCodeOwnerReviews, true},
		{"web.RequiresLinearHistory", web.RequiresLinearHistory, true},
		{"web.DismissStaleReviews", web.DismissStaleReviews, true},
		{"web.RequiresSignedCommits", web.RequiresSignedCommits, true},
		{"web.PushProtectionEnabled", web.PushProtectionEnabled, true},
		{"web.IsPrivate", web.IsPrivate, true},
		// No GitLab read-only analog → always false.
		{"web.SecretScanningEnabled", web.SecretScanningEnabled, false},
		{"web.CodeScanningEnabled", web.CodeScanningEnabled, false},
		{"web.DependabotAlertsEnabled", web.DependabotAlertsEnabled, false},
		// "api": public, unprotected default branch, no push rule.
		{"api.ProtectionOn", byName["acme/api"].ProtectionOn, false},
		{"api.IsPrivate", byName["acme/api"].IsPrivate, false},
		{"api.RequiresLinearHistory", byName["acme/api"].RequiresLinearHistory, false},
		{"api.RequiresSignedCommits", byName["acme/api"].RequiresSignedCommits, false},
		{"api.DismissStaleReviews", byName["acme/api"].DismissStaleReviews, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.name, c.got, c.want)
		}
	}
	if got := byName["acme/api"].RequiredReviews; got != 0 {
		t.Errorf("api.RequiredReviews = %d; want 0", got)
	}
}

// TestSDKAPI_ListMembers_HappyPath exercises the real GitLab SDK adapter
// against an httptest server, verifying the group-member → directory_user
// mapping and the degrade-gracefully path when the per-member Users-API
// read is forbidden (insufficient token privilege for 2FA / instance-admin).
//   - bob:   Owner (group admin), 2FA on
//   - carol: Developer but instance admin (is_admin folds in), 2FA off
//   - dan:   Developer, Users-API read 403 → mfa best-effort false, not admin
func TestSDKAPI_ListMembers_HappyPath(t *testing.T) {
	responses := map[string]string{
		"/api/v4/groups/acme/members/all": `[` +
			`{"id":11,"username":"bob","name":"Bob B","state":"active","access_level":50,"email":"bob@acme.io"},` +
			`{"id":12,"username":"carol","name":"Carol C","state":"active","access_level":30},` +
			`{"id":13,"username":"dan","name":"Dan D","state":"active","access_level":30}]`,
		"/api/v4/users/11": `{"id":11,"username":"bob","is_admin":false,"two_factor_enabled":true}`,
		"/api/v4/users/12": `{"id":12,"username":"carol","is_admin":true,"two_factor_enabled":false}`,
	}
	forbidden := map[string]bool{"/api/v4/users/13": true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := responses[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body)) //nolint:errcheck // test handler
			return
		}
		if forbidden[r.URL.Path] {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		t.Errorf("unexpected request: %s", r.URL.Path)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("tok", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	api := &sdkAPI{client: client, group: "acme"}
	members, err := api.ListMembers(context.Background())
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("len = %d; want 3", len(members))
	}
	byName := map[string]Member{}
	for _, m := range members {
		byName[m.Username] = m
	}
	checks := []struct {
		name string
		got  bool
		want bool
	}{
		{"bob.IsAdmin", byName["bob"].IsAdmin, true}, // Owner role
		{"bob.MFAEnabled", byName["bob"].MFAEnabled, true},
		{"bob.IsActive", byName["bob"].IsActive, true},
		{"carol.IsAdmin", byName["carol"].IsAdmin, true}, // instance admin folded in
		{"carol.MFAEnabled", byName["carol"].MFAEnabled, false},
		{"dan.IsAdmin", byName["dan"].IsAdmin, false},       // Developer, 403 read
		{"dan.MFAEnabled", byName["dan"].MFAEnabled, false}, // best-effort on 403
		{"dan.IsActive", byName["dan"].IsActive, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.name, c.got, c.want)
		}
	}
	if byName["bob"].Email != "bob@acme.io" {
		t.Errorf("bob.Email = %q; want bob@acme.io", byName["bob"].Email)
	}
}
