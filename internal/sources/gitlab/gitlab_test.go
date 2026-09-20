package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// Shared literals for the GitLab plugin tests: raw GitLab API values and
// the fake group/repo/member identifiers the fixtures reuse.
const (
	branchMain             = "main"
	environmentTierStaging = "staging"
	environmentNameProd    = "prod"
	gitlabStatusFailed     = "failed"

	testGroup     = "acme"
	testRepoR1    = "acme/r1"
	testRepoAPI   = "acme-group/api"
	testMergeSHA  = "abc123"
	testUserAmy   = "amy"
	testUserBob   = "bob"
	testUserCarol = "carol"
	testUserDave  = "dave"
	testUserErin  = "erin"

	pathGroupProjects = "/api/v4/groups/acme/projects"
)

// fakeAPI drives the plugin without real network calls.
type fakeAPI struct {
	repos     []Repo
	repoErr   error
	members   []Member
	memberErr error

	pulls       []PullRequest
	pullErr     error
	deployments []Deployment
	deployErr   error

	// gotStart/gotEnd record the window the plugin resolved and passed
	// down, so the period-param plumbing is assertable.
	gotStart time.Time
	gotEnd   time.Time

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

func (f *fakeAPI) ListMergedPullRequests(_ context.Context, start, end time.Time) ([]PullRequest, error) {
	f.gotStart, f.gotEnd = start, end
	if f.pullErr != nil {
		return nil, f.pullErr
	}
	return f.pulls, nil
}

func (f *fakeAPI) ListDeployments(_ context.Context, start, end time.Time) ([]Deployment, error) {
	f.gotStart, f.gotEnd = start, end
	if f.deployErr != nil {
		return nil, f.deployErr
	}
	return f.deployments, nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	want := []string{
		EvidenceTypeRepository, EvidenceTypeDirectoryUser,
		EvidenceTypePullRequest, EvidenceTypeDeployment,
	}
	if got := p.Emits(); !reflect.DeepEqual(got, want) {
		t.Errorf("Emits = %v; want %v", got, want)
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
			{Name: "acme/zeta", DefaultBranch: branchMain, ProtectionOn: false, RequiredReviews: 0},
			{Name: "acme/alpha", DefaultBranch: branchMain, ProtectionOn: true, RequiredReviews: 2},
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
	fake := &fakeAPI{repos: []Repo{{Name: testRepoR1, DefaultBranch: branchMain}}}
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
			{Username: testUserAmy, Name: "Amy A", Email: "amy@acme.io", MFAEnabled: true, IsAdmin: true, IsActive: true},
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
	if records[0].ID != testUserAmy || records[1].ID != "zoe" {
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
		ID: testUserAmy, Username: testUserAmy, DisplayName: "Amy A", Email: "amy@acme.io",
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
		repos:   []Repo{{Name: testRepoR1, DefaultBranch: branchMain}},
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
	fake := &fakeAPI{repos: []Repo{{Name: testRepoR1, DefaultBranch: branchMain}}}
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
	fake := &fakeAPI{repos: []Repo{{Name: testRepoR1, DefaultBranch: branchMain}}}
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
	if _, err := NewFromToken(context.Background(), testGroup, "", ""); err == nil {
		t.Error("want error for empty token")
	}
	if _, err := NewFromToken(context.Background(), testGroup, "tok", ""); err != nil {
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
		pathGroupProjects: `[` +
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
	api := &sdkAPI{client: client, group: testGroup}
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
	api := &sdkAPI{client: client, group: testGroup}
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
		{"bob.IsAdmin", byName[testUserBob].IsAdmin, true}, // Owner role
		{"bob.MFAEnabled", byName[testUserBob].MFAEnabled, true},
		{"bob.IsActive", byName[testUserBob].IsActive, true},
		{"carol.IsAdmin", byName[testUserCarol].IsAdmin, true}, // instance admin folded in
		{"carol.MFAEnabled", byName[testUserCarol].MFAEnabled, false},
		{"dan.IsAdmin", byName["dan"].IsAdmin, false},       // Developer, 403 read
		{"dan.MFAEnabled", byName["dan"].MFAEnabled, false}, // best-effort on 403
		{"dan.IsActive", byName["dan"].IsActive, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.name, c.got, c.want)
		}
	}
	if byName[testUserBob].Email != "bob@acme.io" {
		t.Errorf("bob.Email = %q; want bob@acme.io", byName[testUserBob].Email)
	}
}

// --- Period-scoped types: pull_request / deployment ------------------------

// The fixed clock and audit window the period-scoped tests share. The
// window is passed explicitly as slot params so the tests never depend
// on the trailing-one-year fallback (which the conformance run covers).
var (
	periodNow      = time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	periodStart    = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	periodEnd      = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	insidePeriod   = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	beforePeriod   = time.Date(2025, 11, 5, 8, 0, 0, 0, time.UTC)
	periodSlotArgs = map[string]any{"period_start": periodStart, "period_end": periodEnd}
)

// collectPeriodType runs Collect for one period-scoped evidence type
// over the shared window.
func collectPeriodType(t *testing.T, api API, typeID string) []core.EvidenceRecord {
	t.Helper()
	p := New(Options{API: api, Now: func() time.Time { return periodNow }})
	recs, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{typeID},
		Params:        periodSlotArgs,
		PolicyID:      "p1",
	})
	if err != nil {
		t.Fatalf("Collect(%s): %v", typeID, err)
	}
	return recs
}

// recordIDs is the list of record IDs, in emission order.
func recordIDs(recs []core.EvidenceRecord) []string {
	out := make([]string, 0, len(recs))
	for i := range recs {
		out = append(out, recs[i].ID)
	}
	return out
}

// assertRecordMeta checks the non-payload envelope fields of a
// period-scoped record. Neither type carries an IdentityKey — a merge
// request and a deployment are events, not identities.
func assertRecordMeta(t *testing.T, rec *core.EvidenceRecord, wantType string) {
	t.Helper()
	if rec.Type != wantType {
		t.Errorf("record %s: Type = %q; want %q", rec.ID, rec.Type, wantType)
	}
	if rec.SourceID != SourceID {
		t.Errorf("record %s: SourceID = %q; want %q", rec.ID, rec.SourceID, SourceID)
	}
	if rec.CollectedAt != periodNow {
		t.Errorf("record %s: CollectedAt = %v; want %v", rec.ID, rec.CollectedAt, periodNow)
	}
	if rec.IdentityKey != "" {
		t.Errorf("record %s: IdentityKey = %q; want empty", rec.ID, rec.IdentityKey)
	}
}

// TestCollectPullRequests_HappyPath_SortsByID pins the record ID form
// ("{group}/{project}#{iid}" — the string a customer writes in a
// waiver's resource_id) and the full emitted payload.
func TestCollectPullRequests_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{pulls: []PullRequest{
		{
			Repository: "acme-group/web", Number: 9, Author: testUserDave,
			MergedBy: testUserErin, TargetBranch: "release/1.0",
			MergeCommitSHA: "sq1", MergedAt: insidePeriod.Add(24 * time.Hour),
			Approvers: []string{testUserErin}, ChecksPassed: false,
		},
		{
			Repository: testRepoAPI, Number: 42, Author: testUserBob,
			MergedBy: testUserCarol, TargetBranch: branchMain,
			MergeCommitSHA: testMergeSHA, MergedAt: insidePeriod,
			Approvers: []string{testUserCarol, testUserDave}, ChecksPassed: true,
		},
	}}
	recs := collectPeriodType(t, fake, EvidenceTypePullRequest)

	wantIDs := []string{"acme-group/api#42", "acme-group/web#9"}
	if got := recordIDs(recs); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("record IDs = %v; want %v (ascending)", got, wantIDs)
	}
	for i := range recs {
		assertRecordMeta(t, &recs[i], EvidenceTypePullRequest)
	}
	var got pullRequestPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	want := pullRequestPayload{
		Repository: testRepoAPI, Number: 42, Author: testUserBob,
		MergedBy: testUserCarol, TargetBranch: branchMain, MergeCommitSHA: testMergeSHA,
		MergedAt:      insidePeriod.Format(time.RFC3339),
		ApprovalCount: 2, IndependentApprovalCount: 2,
		ApprovedBeforeMerge: true, ChecksPassed: true,
	}
	if got != want {
		t.Errorf("payload = %+v; want %+v", got, want)
	}
	if fake.gotStart != periodStart || fake.gotEnd != periodEnd {
		t.Errorf("window passed to API = [%v, %v]; want [%v, %v]",
			fake.gotStart, fake.gotEnd, periodStart, periodEnd)
	}
}

// TestCollectPullRequests_ApprovalDerivation covers the three derived
// approval fields. GitLab exposes no approval timestamp, so
// approved_before_merge is exactly "an independent approval exists" —
// an approval cannot be recorded there after the merge.
func TestCollectPullRequests_ApprovalDerivation(t *testing.T) {
	type derived struct {
		Approvals   int
		Independent int
		BeforeMerge bool
	}
	cases := []struct {
		name      string
		author    string
		approvers []string
		want      derived
	}{
		{"independent approval", testUserBob, []string{testUserCarol}, derived{1, 1, true}},
		{"self-approval only", testUserBob, []string{testUserBob}, derived{1, 0, false}},
		{"self plus independent", testUserBob, []string{testUserBob, testUserCarol}, derived{2, 1, true}},
		{"duplicate approvers counted once", testUserBob, []string{testUserCarol, testUserCarol}, derived{1, 1, true}},
		{"blank approvers ignored", testUserBob, []string{"", "   ", testUserCarol}, derived{1, 1, true}},
		{"no approvers", testUserBob, nil, derived{0, 0, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAPI{pulls: []PullRequest{{
				Repository: testRepoAPI, Number: 1, Author: tc.author,
				MergedAt: insidePeriod, Approvers: tc.approvers,
			}}}
			recs := collectPeriodType(t, fake, EvidenceTypePullRequest)
			if len(recs) != 1 {
				t.Fatalf("len = %d; want 1", len(recs))
			}
			var p pullRequestPayload
			mustUnmarshal(t, recs[0].Payload, &p)
			got := derived{p.ApprovalCount, p.IndependentApprovalCount, p.ApprovedBeforeMerge}
			if got != tc.want {
				t.Errorf("derived = %+v; want %+v", got, tc.want)
			}
		})
	}
}

// TestCollectPullRequests_WindowFilter asserts the plugin re-applies the
// window itself rather than trusting the adapter's server-side filter.
func TestCollectPullRequests_WindowFilter(t *testing.T) {
	fake := &fakeAPI{pulls: []PullRequest{
		{Repository: testRepoAPI, Number: 1, MergedAt: insidePeriod},
		{Repository: testRepoAPI, Number: 2, MergedAt: beforePeriod},
		{Repository: testRepoAPI, Number: 3, MergedAt: periodEnd.Add(time.Hour)},
		{Repository: testRepoAPI, Number: 4}, // never merged
	}}
	recs := collectPeriodType(t, fake, EvidenceTypePullRequest)
	if got := recordIDs(recs); !reflect.DeepEqual(got, []string{"acme-group/api#1"}) {
		t.Errorf("record IDs = %v; want only the in-window merge", got)
	}
}

// TestCollectPullRequests_EmitsRequiredFields guards the null-trap:
// every schema-declared property must be present in the emitted JSON
// (an absent field errors the consuming policy rather than reading as
// false/zero).
func TestCollectPullRequests_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{pulls: []PullRequest{
		{Repository: testRepoAPI, Number: 1, MergedAt: insidePeriod},
	}}
	recs := collectPeriodType(t, fake, EvidenceTypePullRequest)
	assertPayloadFields(t, recs[0].Payload, []string{
		"repository", "number", "author", "merged_by", "target_branch",
		"merge_commit_sha", "merged_at", "approval_count",
		"independent_approval_count", "approved_before_merge", "checks_passed",
	})
}

func TestCollectPullRequests_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{pullErr: errors.New("rate limit")}})
	_, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypePullRequest}})
	if err == nil || !strings.Contains(err.Error(), "list merged merge requests") {
		t.Errorf("want 'list merged merge requests' error; got %v", err)
	}
}

// TestCollectDeployments_HappyPath_SortsByID pins the record ID form
// and the full emitted payload.
func TestCollectDeployments_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{deployments: []Deployment{
		{
			Repository: "acme-group/web", ID: "12", Environment: environmentTierStaging,
			EnvironmentTier: environmentTierStaging, CreatedAt: insidePeriod.Add(time.Hour),
			Status: gitlabStatusFailed,
		},
		{
			Repository: testRepoAPI, ID: "900", SHA: testMergeSHA,
			Environment: environmentTierProduction, EnvironmentTier: environmentTierProduction,
			Creator: testUserBob, CreatedAt: insidePeriod, Status: deploymentStatusSuccess,
		},
	}}
	recs := collectPeriodType(t, fake, EvidenceTypeDeployment)

	wantIDs := []string{"acme-group/api/deployments/900", "acme-group/web/deployments/12"}
	if got := recordIDs(recs); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("record IDs = %v; want %v (ascending)", got, wantIDs)
	}
	for i := range recs {
		assertRecordMeta(t, &recs[i], EvidenceTypeDeployment)
	}
	var got deploymentPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	want := deploymentPayload{
		Repository: testRepoAPI, DeploymentID: "900", Environment: environmentTierProduction,
		IsProduction: true, DeployedBy: testUserBob,
		DeployedAt: insidePeriod.Format(time.RFC3339), CommitSHA: testMergeSHA,
		Status: deploymentStatusSuccess,
	}
	if got != want {
		t.Errorf("payload = %+v; want %+v", got, want)
	}
}

// TestCollectDeployments_DerivedFields covers the two normalizations the
// plugin owns: is_production (tier authoritative in both directions,
// name only as fallback) and the closed status vocabulary.
func TestCollectDeployments_DerivedFields(t *testing.T) {
	type derived struct {
		IsProduction bool
		Status       string
	}
	cases := []struct {
		name    string
		tier    string
		envName string
		status  string
		want    derived
	}{
		{"production tier", environmentTierProduction, "blue-prod-1", deploymentStatusSuccess, derived{true, deploymentStatusSuccess}},
		{"non-production tier beats production-looking name", environmentTierStaging, environmentNameProd, deploymentStatusSuccess, derived{false, deploymentStatusSuccess}},
		{"no tier, name prod", "", environmentNameProd, "running", derived{true, deploymentStatusPending}},
		{"no tier, name Production cased", "", "Production", "created", derived{true, deploymentStatusPending}},
		{"no tier, name live", "", "live", "blocked", derived{true, deploymentStatusPending}},
		{"no tier, name staging", "", environmentTierStaging, gitlabStatusFailed, derived{false, "failure"}},
		{"canceled is failure", "", environmentTierStaging, "canceled", derived{false, "failure"}},
		{"unrecognized status is unknown", "", environmentTierStaging, "skipped", derived{false, "unknown"}},
		{"empty status is unknown", "", environmentTierStaging, "", derived{false, "unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAPI{deployments: []Deployment{{
				Repository: testRepoAPI, ID: "1", Environment: tc.envName,
				EnvironmentTier: tc.tier, CreatedAt: insidePeriod, Status: tc.status,
			}}}
			recs := collectPeriodType(t, fake, EvidenceTypeDeployment)
			if len(recs) != 1 {
				t.Fatalf("len = %d; want 1", len(recs))
			}
			var p deploymentPayload
			mustUnmarshal(t, recs[0].Payload, &p)
			got := derived{p.IsProduction, p.Status}
			if got != tc.want {
				t.Errorf("derived = %+v; want %+v", got, tc.want)
			}
			if p.Environment != tc.envName {
				t.Errorf("environment = %q; want verbatim %q", p.Environment, tc.envName)
			}
		})
	}
}

// TestCollectDeployments_WindowFilter asserts the plugin re-applies the
// window itself.
func TestCollectDeployments_WindowFilter(t *testing.T) {
	fake := &fakeAPI{deployments: []Deployment{
		{Repository: testRepoAPI, ID: "1", CreatedAt: insidePeriod},
		{Repository: testRepoAPI, ID: "2", CreatedAt: beforePeriod},
		{Repository: testRepoAPI, ID: "3", CreatedAt: periodEnd.Add(time.Hour)},
		{Repository: testRepoAPI, ID: "4"},
	}}
	recs := collectPeriodType(t, fake, EvidenceTypeDeployment)
	if got := recordIDs(recs); !reflect.DeepEqual(got, []string{"acme-group/api/deployments/1"}) {
		t.Errorf("record IDs = %v; want only the in-window deployment", got)
	}
}

// TestCollectDeployments_EmitsRequiredFields guards the null-trap for
// the deployment payload.
func TestCollectDeployments_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{deployments: []Deployment{
		{Repository: testRepoAPI, ID: "1", CreatedAt: insidePeriod},
	}}
	recs := collectPeriodType(t, fake, EvidenceTypeDeployment)
	assertPayloadFields(t, recs[0].Payload, []string{
		"repository", "deployment_id", "environment", "is_production",
		"deployed_by", "deployed_at", "commit_sha", "status",
	})
}

func TestCollectDeployments_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{deployErr: errors.New("rate limit")}})
	_, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDeployment}})
	if err == nil || !strings.Contains(err.Error(), "list deployments") {
		t.Errorf("want 'list deployments' error; got %v", err)
	}
}

// assertPayloadFields asserts every named property is present as a key
// in the emitted JSON.
func assertPayloadFields(t *testing.T, payload []byte, fields []string) {
	t.Helper()
	var m map[string]any
	mustUnmarshal(t, payload, &m)
	for _, field := range fields {
		if _, ok := m[field]; !ok {
			t.Errorf("emitted payload missing field %q", field)
		}
	}
}

// TestPeriodWindow covers both window sources: explicit slot params, and
// the trailing-one-year fallback anchored on the INJECTED clock (never
// time.Now(), which would break the harness's two-Collect determinism
// check).
func TestPeriodWindow(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Now: func() time.Time { return periodNow }})
	gotStart, gotEnd := p.periodWindow(core.SlotRequest{Params: periodSlotArgs})
	if gotStart != periodStart || gotEnd != periodEnd {
		t.Errorf("params window = [%v, %v]; want [%v, %v]", gotStart, gotEnd, periodStart, periodEnd)
	}
	gotStart, gotEnd = p.periodWindow(core.SlotRequest{})
	if gotEnd != periodNow || gotStart != periodNow.AddDate(-1, 0, 0) {
		t.Errorf("fallback window = [%v, %v]; want [%v, %v]",
			gotStart, gotEnd, periodNow.AddDate(-1, 0, 0), periodNow)
	}
	// A wrongly-typed param is ignored, not coerced.
	gotStart, gotEnd = p.periodWindow(core.SlotRequest{
		Params: map[string]any{"period_start": "2026-01-01", "period_end": 42},
	})
	if gotEnd != periodNow || gotStart != periodNow.AddDate(-1, 0, 0) {
		t.Errorf("bad-typed params window = [%v, %v]; want the fallback", gotStart, gotEnd)
	}
}

// TestSDKAPI_ListMergedPullRequests_HappyPath exercises the real GitLab
// SDK adapter against an httptest server, covering the group-wide MR
// listing, the projectID→path index, and the per-MR follow-up reads:
//   - acme/web!42: merge_user set, one approver, a successful pipeline
//   - acme/api!7:  no merge_user (deprecated merged_by fallback), squash
//     merge (empty merge_commit_sha), approvals 403 (Premium-gated —
//     degrades to no approvers), no pipelines
//   - an MR from a project outside the group listing, which is skipped
func TestSDKAPI_ListMergedPullRequests_HappyPath(t *testing.T) {
	responses := map[string]string{
		pathGroupProjects: `[` +
			`{"id":7,"path_with_namespace":"acme/web"},` +
			`{"id":8,"path_with_namespace":"acme/api"}]`,
		"/api/v4/groups/acme/merge_requests": `[` +
			`{"iid":42,"project_id":7,"target_branch":"main","author":{"username":"bob"},` +
			`"merge_user":{"username":"carol"},"merged_at":"2026-03-01T12:00:00Z",` +
			`"merge_commit_sha":"abc123"},` +
			`{"iid":7,"project_id":8,"target_branch":"develop","author":{"username":"dave"},` +
			`"merged_by":{"username":"erin"},"merged_at":"2026-03-02T09:00:00Z",` +
			`"merge_commit_sha":"","squash_commit_sha":"sq1"},` +
			`{"iid":5,"project_id":99,"author":{"username":"mallory"},` +
			`"merged_at":"2026-03-03T09:00:00Z"}]`,
		"/api/v4/projects/7/merge_requests/42/approvals": `{"approved_by":[{"user":{"username":"carol"}}]}`,
		"/api/v4/projects/7/merge_requests/42/pipelines": `[{"id":1,"status":"success"},{"id":0,"status":"failed"}]`,
		"/api/v4/projects/8/merge_requests/7/pipelines":  `[]`,
	}
	forbidden := map[string]bool{"/api/v4/projects/8/merge_requests/7/approvals": true}
	api := newTestSDKAPI(t, responses, forbidden)

	got, err := api.ListMergedPullRequests(context.Background(), periodStart, periodEnd)
	if err != nil {
		t.Fatalf("ListMergedPullRequests: %v", err)
	}
	want := []PullRequest{
		{
			Repository: "acme/web", Number: 42, Author: testUserBob, MergedBy: testUserCarol,
			TargetBranch: branchMain, MergeCommitSHA: testMergeSHA,
			MergedAt:  time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
			Approvers: []string{testUserCarol}, ChecksPassed: true,
		},
		{
			// Squash merge → squash_commit_sha stands in for the absent
			// merge commit; approvals 403 → no approvers, non-fatal; no
			// pipelines → checks_passed false.
			Repository: "acme/api", Number: 7, Author: testUserDave, MergedBy: testUserErin,
			TargetBranch: "develop", MergeCommitSHA: "sq1",
			MergedAt: time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListMergedPullRequests =\n%+v\nwant\n%+v", got, want)
	}
}

// TestSDKAPI_ListDeployments_HappyPath exercises the per-project
// deployments listing (GitLab has no group-level route): projects are
// visited in ascending-ID order, the id falls back to iid when absent,
// and a deployment created outside the window is dropped.
func TestSDKAPI_ListDeployments_HappyPath(t *testing.T) {
	responses := map[string]string{
		pathGroupProjects: `[` +
			`{"id":8,"path_with_namespace":"acme/api"},` +
			`{"id":7,"path_with_namespace":"acme/web"}]`,
		"/api/v4/projects/7/deployments": `[` +
			`{"id":900,"iid":3,"sha":"abc123","status":"success",` +
			`"created_at":"2026-03-01T12:00:00Z","user":{"username":"bob"},` +
			`"environment":{"name":"production","tier":"production"}}]`,
		"/api/v4/projects/8/deployments": `[` +
			`{"id":0,"iid":12,"status":"failed","created_at":"2026-03-02T09:00:00Z",` +
			`"environment":{"name":"prod"}},` +
			`{"id":5,"status":"success","created_at":"2020-01-01T00:00:00Z"}]`,
	}
	api := newTestSDKAPI(t, responses, nil)

	got, err := api.ListDeployments(context.Background(), periodStart, periodEnd)
	if err != nil {
		t.Fatalf("ListDeployments: %v", err)
	}
	want := []Deployment{
		{
			Repository: "acme/web", ID: "900", SHA: testMergeSHA, Environment: environmentTierProduction,
			EnvironmentTier: environmentTierProduction, Creator: testUserBob,
			CreatedAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), Status: deploymentStatusSuccess,
		},
		{
			// id omitted → iid is the fallback identifier.
			Repository: "acme/api", ID: "12", Environment: environmentNameProd,
			CreatedAt: time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC), Status: gitlabStatusFailed,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListDeployments =\n%+v\nwant\n%+v", got, want)
	}
}

func TestSDKAPI_ListMergedPullRequests_ErrorPropagates(t *testing.T) {
	api := newTestSDKAPI(t, nil, map[string]bool{pathGroupProjects: true})
	if _, err := api.ListMergedPullRequests(context.Background(), periodStart, periodEnd); err == nil {
		t.Error("want error when the project listing fails")
	}
}

func TestSDKAPI_ListDeployments_ErrorPropagates(t *testing.T) {
	responses := map[string]string{
		pathGroupProjects: `[{"id":7,"path_with_namespace":"acme/web"}]`,
	}
	api := newTestSDKAPI(t, responses,
		map[string]bool{"/api/v4/projects/7/deployments": true})
	if _, err := api.ListDeployments(context.Background(), periodStart, periodEnd); err == nil {
		t.Error("want error when a project's deployment listing fails")
	}
}

// newTestSDKAPI builds an sdkAPI against an httptest server serving the
// given path→body table; paths in denied return 403 (the adapter's
// degrade-gracefully / error path), and any other path fails the test.
func newTestSDKAPI(t *testing.T, responses map[string]string, denied map[string]bool) *sdkAPI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := responses[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body)) //nolint:errcheck // test handler
			return
		}
		if denied[r.URL.Path] {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		t.Errorf("unexpected request: %s", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	client, err := gitlab.NewClient("tok", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &sdkAPI{client: client, group: testGroup}
}

// Every field the plugin emits without observing it must be declared, because
// a shipped policy reads each one and would otherwise grade a control on a
// value nobody measured. The set is asserted by (type, field) lookup rather
// than by index: caveats are a growing list, and an index-keyed assertion
// breaks — or worse, silently checks the wrong entry — the next time one is
// added.
func TestCaveats_DeclaresEveryUnobservedField(t *testing.T) {
	var p core.SourcePlugin = New(Options{})
	c, ok := p.(core.CaveatedSource)
	if !ok {
		t.Fatal("gitlab must implement core.CaveatedSource")
	}
	cav := c.Caveats()

	got := map[[2]string]core.SourceCaveat{}
	for _, cv := range cav {
		key := [2]string{cv.EvidenceType, cv.Field}
		if _, dup := got[key]; dup {
			t.Errorf("caveat %v declared twice; the planner would warn twice for one gap", key)
		}
		got[key] = cv
	}

	want := [][2]string{
		// Conditional: readable only by a group-owner / instance-admin token.
		{EvidenceTypeDirectoryUser, "mfa_enabled"},
		// Absolute: pipeline scanning lives in .gitlab-ci.yml, so these three
		// can only ever fail their policy, never pass it.
		{EvidenceTypeRepository, "secret_scanning_enabled"},
		{EvidenceTypeRepository, "code_scanning_enabled"},
		{EvidenceTypeRepository, "dependabot_alerts_enabled"},
		// Conditional: premium endpoints that 403/404 for a free-tier project
		// or a lesser-privileged token, leaving the zero value behind.
		{EvidenceTypeRepository, "requires_signed_commits"},
		{EvidenceTypeRepository, "require_code_owner_reviews"},
		{EvidenceTypeRepository, "required_reviewers_count"},
	}
	for _, key := range want {
		cv, ok := got[key]
		if !ok {
			t.Errorf("no caveat declared for %s.%s; a shipped policy reads it", key[0], key[1])
			continue
		}
		if cv.Detail == "" {
			t.Errorf("caveat %v has no detail; it tells the operator nothing to act on", key)
		}
	}
	if len(cav) != len(want) {
		t.Errorf("Caveats() = %d entries, want %d: %+v", len(cav), len(want), cav)
	}
}
