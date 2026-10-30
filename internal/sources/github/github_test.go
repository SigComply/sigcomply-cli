package github

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

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const testLoginAlice = "alice"

// Fixture identities, repositories and API values shared by the GitHub
// plugin tests.
const (
	testLoginBob   = "bob"
	testLoginCarol = "carol"
	testLoginDave  = "dave"

	testOrg     = "acme"
	testRepoWeb = "acme/web"
	testRepoAPI = "acme/api"

	testToken      = "tok"
	testBranchMain = "main"
	testCommitSHA  = "abc123"

	testRoleAdmin         = "admin"
	testPermissionRead    = "read"
	testResourceTypeRepo  = "repository"
	testAlertStatusActive = "ACTIVE"
	testCVEID             = "CVE-2020-8203"
	testSeverityHigh      = "high"
	testAlertStateOpen    = "open"

	testReviewApproved = "APPROVED"
	testCheckCompleted = "completed"

	testEnvProduction = "production"
	testEnvStaging    = "staging"
)

// fakeAPI drives the plugin without real network calls.
type fakeAPI struct {
	repos         []Repo
	members       []Member
	collaborators []Member
	orgPolicy     OrgPolicy
	alerts        []DependabotAlert
	pulls         []PullRequest
	deployments   []Deployment
	repoErr       error
	memErr        error
	collabErr     error
	orgErr        error
	alertErr      error
	pullErr       error
	deployErr     error

	listReposCount       int
	listMembersCount     int
	listCollabCount      int
	getOrgPolicyCount    int
	listAlertsCount      int
	listPullsCount       int
	listDeploymentsCount int

	// Window the plugin resolved on the last period-scoped call.
	gotStart, gotEnd time.Time
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

func (f *fakeAPI) ListOutsideCollaborators(_ context.Context) ([]Member, error) {
	f.listCollabCount++
	if f.collabErr != nil {
		return nil, f.collabErr
	}
	return f.collaborators, nil
}

func (f *fakeAPI) GetOrgPolicy(_ context.Context) (OrgPolicy, error) {
	f.getOrgPolicyCount++
	if f.orgErr != nil {
		return OrgPolicy{}, f.orgErr
	}
	return f.orgPolicy, nil
}

func (f *fakeAPI) ListDependabotAlerts(_ context.Context) ([]DependabotAlert, error) {
	f.listAlertsCount++
	if f.alertErr != nil {
		return nil, f.alertErr
	}
	return f.alerts, nil
}

func (f *fakeAPI) ListMergedPullRequests(_ context.Context, start, end time.Time) ([]PullRequest, error) {
	f.listPullsCount++
	f.gotStart, f.gotEnd = start, end
	if f.pullErr != nil {
		return nil, f.pullErr
	}
	return f.pulls, nil
}

func (f *fakeAPI) ListDeployments(_ context.Context, start, end time.Time) ([]Deployment, error) {
	f.listDeploymentsCount++
	f.gotStart, f.gotEnd = start, end
	if f.deployErr != nil {
		return nil, f.deployErr
	}
	return f.deployments, nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: testOrg})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 6 || em[0] != EvidenceTypeRepository || em[1] != EvidenceTypeDirectoryUser ||
		em[2] != EvidenceTypeOrgPolicy || em[3] != EvidenceTypeVulnerability ||
		em[4] != EvidenceTypePullRequest || em[5] != EvidenceTypeDeployment {
		t.Errorf("Emits = %v", em)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: testOrg})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func TestCollectRepos_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		repos: []Repo{
			{Name: "zeta", DefaultBranch: testBranchMain, ProtectionOn: false, RequiredReviews: 0},
			{Name: "alpha", DefaultBranch: testBranchMain, ProtectionOn: true, RequiredReviews: 2},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}, PolicyID: "p1"})
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
	if !alpha.DefaultBranchProtected || alpha.RequiredReviewersCount != 2 {
		t.Errorf("alpha payload = %+v", alpha)
	}
}

func TestCollectMembers_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		members: []Member{
			{Login: testLoginBob, TwoFactorOn: false, Role: "member"},
			{Login: testLoginAlice, TwoFactorOn: true, Role: testRoleAdmin},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}, PolicyID: "p2"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	if records[0].ID != testLoginAlice || records[1].ID != testLoginBob {
		t.Errorf("not sorted: %v %v", records[0].ID, records[1].ID)
	}
	if records[0].IdentityKey != testLoginAlice {
		t.Errorf("IdentityKey not set: %q", records[0].IdentityKey)
	}
	var bob memberPayload
	if err := json.Unmarshal(records[1].Payload, &bob); err != nil {
		t.Fatalf("Unmarshal bob: %v", err)
	}
	if bob.MFAEnabled {
		t.Errorf("bob.MFAEnabled should be false")
	}
	if bob.IsAdmin {
		t.Errorf("bob.IsAdmin should be false (role=member)")
	}
	if !bob.IsActive {
		t.Errorf("bob.IsActive should be true (listed members are active)")
	}
}

func TestCollectMembers_IncludesOutsideCollaborators(t *testing.T) {
	fake := &fakeAPI{
		members: []Member{{Login: testLoginAlice, TwoFactorOn: true, Role: testRoleAdmin}},
		collaborators: []Member{
			{Login: "contractor-carol", TwoFactorOn: false},
		},
	}
	p := New(Options{API: fake, Org: testOrg})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2 (1 member + 1 collaborator)", len(records))
	}
	byID := map[string]memberPayload{}
	for _, r := range records {
		var m memberPayload
		if err := json.Unmarshal(r.Payload, &m); err != nil {
			t.Fatalf("Unmarshal %s: %v", r.ID, err)
		}
		byID[r.ID] = m
	}
	if byID[testLoginAlice].IsExternal {
		t.Errorf("member alice should not be external")
	}
	if !byID[testLoginAlice].IsAdmin {
		t.Errorf("member alice should be admin")
	}
	if byID[testLoginAlice].Username != testLoginAlice {
		t.Errorf("member alice username = %q; want login alice", byID[testLoginAlice].Username)
	}
	carol := byID["contractor-carol"]
	if carol.Username != "contractor-carol" {
		t.Errorf("collaborator username = %q; want login contractor-carol", carol.Username)
	}
	if !carol.IsExternal {
		t.Errorf("outside collaborator carol should be external")
	}
	if carol.IsAdmin {
		t.Errorf("outside collaborator carol must never be org admin")
	}
	if carol.MFAEnabled {
		t.Errorf("carol has 2FA off")
	}
	if fake.listCollabCount != 1 {
		t.Errorf("listCollabCount = %d; want 1", fake.listCollabCount)
	}
}

func TestCollectMembers_OutsideCollaboratorErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{collabErr: errors.New("forbidden")}, Org: testOrg})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "list outside collaborators") {
		t.Errorf("want list outside collaborators error; got %v", err)
	}
}

func TestCollectOrgPolicy_HappyPath(t *testing.T) {
	fake := &fakeAPI{orgPolicy: OrgPolicy{
		TwoFactorRequired:      true,
		DefaultRepoPermission:  testPermissionRead,
		SecretScanningNewRepos: true,
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeOrgPolicy}, PolicyID: "p3"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (singleton)", len(records))
	}
	r := records[0]
	if r.ID != testOrg || r.Type != EvidenceTypeOrgPolicy || r.SourceID != SourceID || r.CollectedAt != now {
		t.Errorf("record meta = %+v", r)
	}
	var op orgPolicyPayload
	if err := json.Unmarshal(r.Payload, &op); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if op.ID != testOrg || op.Provider != "github" || !op.TwoFactorRequired ||
		op.DefaultMemberRepositoryPermission != testPermissionRead || !op.SecretScanningEnabledNewRepos {
		t.Errorf("payload = %+v", op)
	}
}

// TestCollectOrgPolicy_EmitsRequiredFields guards the under-emission
// null-trap: the source_control_org_policy schema's required fields must
// always be present in the emitted payload.
func TestCollectOrgPolicy_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{orgPolicy: OrgPolicy{DefaultRepoPermission: "none"}}
	p := New(Options{API: fake, Org: testOrg})
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeOrgPolicy}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(recs[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{"id", "two_factor_required", "default_member_repository_permission"} {
		if _, ok := m[field]; !ok {
			t.Errorf("emitted org-policy payload missing required field %q", field)
		}
	}
}

func TestCollectOrgPolicy_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{orgErr: errors.New("forbidden")}, Org: testOrg})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeOrgPolicy}})
	if err == nil || !strings.Contains(err.Error(), "get org policy") {
		t.Errorf("want get org policy error; got %v", err)
	}
}

func TestCollectVulnerabilities_HappyPath_MapsAndSorts(t *testing.T) {
	fake := &fakeAPI{alerts: []DependabotAlert{
		{Number: 7, RepoFullName: testRepoWeb, PackageName: "lodash", Summary: "Prototype pollution",
			Severity: testSeverityHigh, State: testAlertStateOpen, CVEID: testCVEID, CVSSScore: 7.4, PatchAvailable: true},
		{Number: 3, RepoFullName: testRepoAPI, PackageName: "left-pad", Summary: "ReDoS",
			Severity: "critical", State: testAlertStateOpen},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnerability}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID: "acme/api/3" < "acme/web/7".
	if records[0].ID != "acme/api/3" || records[1].ID != "acme/web/7" {
		t.Errorf("not sorted by ID: %q %q", records[0].ID, records[1].ID)
	}
	var web vulnFindingPayload
	if err := json.Unmarshal(records[1].Payload, &web); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := vulnFindingPayload{
		ID:                   "acme/web/7",
		ResourceID:           testRepoWeb,
		ResourceType:         testResourceTypeRepo,
		Title:                "lodash: Prototype pollution",
		Severity:             "HIGH",
		Status:               testAlertStatusActive,
		CVEID:                testCVEID,
		Score:                7.4,
		RemediationAvailable: true,
	}
	if web != want {
		t.Errorf("web payload = %+v; want %+v", web, want)
	}
	if records[1].Type != EvidenceTypeVulnerability || records[1].CollectedAt != now {
		t.Errorf("record meta = %+v", records[1])
	}
}

func TestNormalizeSeverityAndState(t *testing.T) {
	sev := map[string]string{
		"critical": "CRITICAL", testSeverityHigh: "HIGH", "medium": "MEDIUM", "moderate": "MEDIUM",
		"low": "LOW", "weird": "INFORMATIONAL", "": "INFORMATIONAL",
	}
	for in, want := range sev {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q; want %q", in, got, want)
		}
	}
	state := map[string]string{
		testAlertStateOpen: testAlertStatusActive, "fixed": "RESOLVED", "dismissed": "SUPPRESSED",
		"auto_dismissed": "SUPPRESSED", deploymentStatusUnknown: testAlertStatusActive,
	}
	for in, want := range state {
		if got := normalizeAlertState(in); got != want {
			t.Errorf("normalizeAlertState(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestCollectVulnerabilities_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{alerts: []DependabotAlert{{Number: 1, RepoFullName: "acme/x", Severity: "low", State: testAlertStateOpen}}}
	p := New(Options{API: fake, Org: testOrg})
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnerability}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(recs[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{"id", "resource_id", "resource_type", "severity", "status", "remediation_available"} {
		if _, ok := m[field]; !ok {
			t.Errorf("emitted vuln payload missing field %q", field)
		}
	}
}

func TestCollectVulnerabilities_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{alertErr: errors.New("rate limit")}, Org: testOrg})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnerability}})
	if err == nil || !strings.Contains(err.Error(), "list dependabot alerts") {
		t.Errorf("want list dependabot alerts error; got %v", err)
	}
}

func TestCollect_NoData(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: testOrg})
	for _, et := range []string{EvidenceTypeRepository, EvidenceTypeDirectoryUser} {
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
	p := New(Options{API: &fakeAPI{}, Org: testOrg})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"s3_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollectRepos_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{repoErr: errors.New("rate limit")}, Org: testOrg})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}})
	if err == nil || !strings.Contains(err.Error(), "list repos") {
		t.Errorf("want list repos error; got %v", err)
	}
}

func TestCollectMembers_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{memErr: errors.New("forbidden")}, Org: testOrg})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "list org members") {
		t.Errorf("want list org members error; got %v", err)
	}
}

func TestCollect_DefaultNowIsInjected(t *testing.T) {
	fake := &fakeAPI{repos: []Repo{{Name: "r1", DefaultBranch: testBranchMain}}}
	p := New(Options{API: fake, Org: testOrg})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if recs[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now")
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{
		repos:   []Repo{{Name: "r1", DefaultBranch: testBranchMain}},
		members: []Member{{Login: testLoginAlice, TwoFactorOn: true}},
	}
	p := New(Options{API: fake, Org: testOrg})
	for range 3 {
		if _, err := p.Collect(context.Background(),
			core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}}); err != nil {
			t.Fatalf("Collect repos: %v", err)
		}
		if _, err := p.Collect(context.Background(),
			core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}}); err != nil {
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
	if _, err := NewFromToken(context.Background(), "", testToken, ""); err == nil {
		t.Error("want error for empty org")
	}
	if _, err := NewFromToken(context.Background(), testOrg, "", ""); err == nil {
		t.Error("want error for empty token")
	}
	p, err := NewFromToken(context.Background(), testOrg, testToken, "")
	if err != nil {
		t.Fatalf("NewFromToken: %v", err)
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

// A blank base_url must keep pointing at github.com; a GitHub Enterprise
// Server URL must be used verbatim, minus any trailing slash (every call
// site concatenates base + "/path").
func TestNewFromToken_BaseURL(t *testing.T) {
	const ghes = "https://ghe.example.com/api/v3"
	cases := []struct{ in, want string }{
		{"", defaultBaseURL},
		{ghes, ghes},
		{ghes + "/", ghes},
	}
	for _, c := range cases {
		p, err := NewFromToken(context.Background(), testOrg, testToken, c.in)
		if err != nil {
			t.Fatalf("NewFromToken(%q): %v", c.in, err)
		}
		api, ok := p.api.(*httpAPI)
		if !ok {
			t.Fatalf("NewFromToken(%q): api is %T, want *httpAPI", c.in, p.api)
		}
		if api.base != c.want {
			t.Errorf("base for %q = %q; want %q", c.in, api.base, c.want)
		}
	}
}

func TestNextLink(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{`<https://api.github.com/x?page=2>; rel="next"`, "https://api.github.com/x?page=2"},
		{`<https://api.github.com/x?page=2>; rel="prev"`, ""},
		{`<https://x?after=cur>; rel="next", <https://y>; rel="last"`, "https://x?after=cur"},
	}
	for _, c := range cases {
		if got := nextLink(c.in); got != c.want {
			t.Errorf("nextLink(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// --- HTTP adapter tests ----------------------------------------------------

func TestHTTPAPI_ListRepos_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/repos"):
			_, _ = w.Write([]byte(`[` + //nolint:errcheck // test handler
				`{"name":"web","default_branch":"main","private":true,` +
				`"security_and_analysis":{"secret_scanning":{"status":"enabled"},` +
				`"secret_scanning_push_protection":{"status":"enabled"}}},` +
				`{"name":"api","default_branch":"main"}]`))
		case r.URL.Path == "/repos/acme/web/rules/branches/main", r.URL.Path == "/repos/acme/api/rules/branches/main":
			_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
		case r.URL.Path == "/repos/acme/web/code-scanning/analyses":
			_, _ = w.Write([]byte(`[{"id":1}]`)) //nolint:errcheck // test handler
		case r.URL.Path == "/repos/acme/api/code-scanning/analyses":
			http.Error(w, `{"message":"no analysis found"}`, http.StatusNotFound)
		case r.URL.Path == "/repos/acme/web/branches/main/protection":
			_, _ = w.Write([]byte(`{"required_pull_request_reviews":{"required_approving_review_count":2,` + //nolint:errcheck // test handler
				`"dismiss_stale_reviews":true,"require_code_owner_reviews":true},` +
				`"required_signatures":{"enabled":true},"allow_force_pushes":{"enabled":false},` +
				`"required_linear_history":{"enabled":true}}`))
		case r.URL.Path == "/repos/acme/api/branches/main/protection":
			http.Error(w, `{"message":"Branch not protected"}`, http.StatusNotFound)
		case r.URL.Path == "/repos/acme/web/vulnerability-alerts":
			w.WriteHeader(http.StatusNoContent) // enabled
		case r.URL.Path == "/repos/acme/api/vulnerability-alerts":
			http.Error(w, "not found", http.StatusNotFound) // disabled
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
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
	web := byName["web"]
	if web.RequiredReviews != 2 {
		t.Errorf("web.RequiredReviews = %d; want 2", web.RequiredReviews)
	}
	// All booleans the fully-protected "web" repo should report true, plus
	// the two false-expecting fields, in one table to keep complexity low.
	checks := []struct {
		name string
		got  bool
		want bool
	}{
		{"ProtectionOn", web.ProtectionOn, true},
		{"RequiresSignedCommits", web.RequiresSignedCommits, true},
		{"RequiresLinearHistory", web.RequiresLinearHistory, true},
		{"AllowsForcePush", web.AllowsForcePush, false},
		{"DismissStaleReviews", web.DismissStaleReviews, true},
		{"RequireCodeOwnerReviews", web.RequireCodeOwnerReviews, true},
		{"SecretScanningEnabled", web.SecretScanningEnabled, true},
		{"PushProtectionEnabled", web.PushProtectionEnabled, true},
		{"CodeScanningEnabled", web.CodeScanningEnabled, true},
		{"IsPrivate", web.IsPrivate, true},
		{"DependabotAlertsEnabled", web.DependabotAlertsEnabled, true},
		{"api.ProtectionOn", byName["api"].ProtectionOn, false},
		{"api.AllowsForcePush", byName["api"].AllowsForcePush, true},
		{"api.CodeScanningEnabled", byName["api"].CodeScanningEnabled, false},
		{"api.DependabotAlertsEnabled", byName["api"].DependabotAlertsEnabled, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.name, c.got, c.want)
		}
	}
}

func TestHTTPAPI_ListOrgMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/memberships/"):
			login := strings.TrimPrefix(r.URL.Path, "/orgs/acme/memberships/")
			if login == testLoginAlice {
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

	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	members, err := api.ListOrgMembers(context.Background())
	if err != nil {
		t.Fatalf("ListOrgMembers: %v", err)
	}
	byLogin := map[string]Member{}
	for _, m := range members {
		byLogin[m.Login] = m
	}
	if !byLogin[testLoginAlice].TwoFactorOn {
		t.Errorf("alice should have 2fa on")
	}
	if byLogin[testLoginBob].TwoFactorOn {
		t.Errorf("bob should have 2fa off")
	}
	if byLogin[testLoginAlice].Role != testRoleAdmin {
		t.Errorf("alice.Role = %q", byLogin[testLoginAlice].Role)
	}
}

func TestHTTPAPI_ListOutsideCollaborators_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/orgs/acme/outside_collaborators") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("filter") == "2fa_disabled" {
			_, _ = w.Write([]byte(`[{"login":"carol"}]`)) //nolint:errcheck // test handler
			return
		}
		_, _ = w.Write([]byte(`[{"login":"carol"},{"login":"dave"}]`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	collabs, err := api.ListOutsideCollaborators(context.Background())
	if err != nil {
		t.Fatalf("ListOutsideCollaborators: %v", err)
	}
	byLogin := map[string]Member{}
	for _, m := range collabs {
		byLogin[m.Login] = m
	}
	if len(byLogin) != 2 {
		t.Fatalf("want 2 collaborators; got %d", len(byLogin))
	}
	if byLogin[testLoginCarol].TwoFactorOn {
		t.Errorf("carol should have 2FA off")
	}
	if !byLogin[testLoginDave].TwoFactorOn {
		t.Errorf("dave should have 2FA on")
	}
	if byLogin[testLoginCarol].Role != "" {
		t.Errorf("outside collaborators carry no role; got %q", byLogin[testLoginCarol].Role)
	}
}

func TestHTTPAPI_GetOrgPolicy_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"two_factor_requirement_enabled":true,` + //nolint:errcheck // test handler
			`"default_repository_permission":"read",` +
			`"members_can_create_public_repositories":false,` +
			`"secret_scanning_enabled_for_new_repositories":true}`))
	}))
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	op, err := api.GetOrgPolicy(context.Background())
	if err != nil {
		t.Fatalf("GetOrgPolicy: %v", err)
	}
	if !op.TwoFactorRequired || op.DefaultRepoPermission != testPermissionRead ||
		op.MembersCanCreatePublicRepos || !op.SecretScanningNewRepos {
		t.Errorf("OrgPolicy = %+v", op)
	}
}

// TestHTTPAPI_GetOrgPolicy_NullTwoFactor confirms a null 2FA flag (caller
// without org-admin scope) normalizes to false rather than panicking.
func TestHTTPAPI_GetOrgPolicy_NullTwoFactor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"two_factor_requirement_enabled":null,"default_repository_permission":"none"}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	op, err := api.GetOrgPolicy(context.Background())
	if err != nil {
		t.Fatalf("GetOrgPolicy: %v", err)
	}
	if op.TwoFactorRequired {
		t.Errorf("null 2FA should normalize to false")
	}
}

func TestHTTPAPI_ListDependabotAlerts_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/dependabot/alerts" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("state") != testAlertStateOpen {
			t.Errorf("want state=open; got %q", r.URL.Query().Get("state"))
		}
		_, _ = w.Write([]byte(`[{"number":7,"state":"open",` + //nolint:errcheck // test handler
			`"dependency":{"package":{"name":"lodash"}},` +
			`"security_advisory":{"cve_id":"CVE-2020-8203","summary":"Prototype pollution","severity":"high","cvss":{"score":7.4}},` +
			`"security_vulnerability":{"first_patched_version":{"identifier":"4.17.19"}},` +
			`"repository":{"full_name":"acme/web"}}]`))
	}))
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	alerts, err := api.ListDependabotAlerts(context.Background())
	if err != nil {
		t.Fatalf("ListDependabotAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("len = %d; want 1", len(alerts))
	}
	a := alerts[0]
	if a.Number != 7 || a.RepoFullName != testRepoWeb || a.PackageName != "lodash" ||
		a.Severity != testSeverityHigh || a.CVEID != testCVEID || a.CVSSScore != 7.4 || !a.PatchAvailable {
		t.Errorf("alert = %+v", a)
	}
}

// TestHTTPAPI_ListDependabotAlerts_ForbiddenIsEmpty confirms a 403 saying
// alerts are disabled for the org yields no findings rather than failing
// the run.
func TestHTTPAPI_ListDependabotAlerts_ForbiddenIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Dependabot alerts are disabled", http.StatusForbidden)
	}))
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	alerts, err := api.ListDependabotAlerts(context.Background())
	if err != nil {
		t.Fatalf("ListDependabotAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("want 0 alerts on 403; got %d", len(alerts))
	}
}

// A 403 for any other reason (a token without Dependabot alerts read, a
// rate limit) must not read as "no vulnerabilities".
func TestHTTPAPI_ListDependabotAlerts_OtherForbiddenErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Resource not accessible by personal access token"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	if _, err := api.ListDependabotAlerts(context.Background()); err == nil {
		t.Fatal("ListDependabotAlerts = nil error; want the 403 returned")
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
	api := &httpAPI{org: testOrg, token: "sekrit", base: srv.URL, client: srv.Client()}
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
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
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
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	_, err := api.ListRepos(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("want decode error; got %v", err)
	}
}

func TestHTTPAPI_ListRepos_Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/protection"):
			http.Error(w, `{"message":"Branch not protected"}`, http.StatusNotFound)
		case strings.Contains(r.URL.Path, "/rules/branches/"), strings.HasSuffix(r.URL.Path, "/code-scanning/analyses"):
			_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
		case strings.HasSuffix(r.URL.Path, "/vulnerability-alerts"):
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Query().Get("page") == "1":
			w.Header().Set("Link", "<http://"+r.Host+"/orgs/acme/repos?page=2>; rel=\"next\"")
			_, _ = w.Write([]byte(`[{"name":"r1","default_branch":"main"}]`)) //nolint:errcheck // test handler
		case r.URL.Query().Get("page") == "2":
			_, _ = w.Write([]byte(`[{"name":"r2","default_branch":"main"}]`)) //nolint:errcheck // test handler
		}
	}))
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
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
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := api.ListRepos(ctx); err == nil {
		t.Errorf("want context-canceled error")
	}
}

// Tiny smoke test that confirms json roundtrip of the payload shapes — the
// marshal path inside Collect is otherwise covered by the happy-path tests.
func TestPayloadJSONRoundTrip(t *testing.T) {
	rp := repoPayload{Name: "r", DefaultBranch: testBranchMain, DefaultBranchProtected: true, RequiredReviewersCount: 1}
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

// TestCollectRepos_EmitsAllPolicyReadFields guards against the
// under-emission null-trap: every git_repository field the SOC 2 CC8.1 /
// CC6.5 policies read must be present in the emitted payload, or the
// evaluator now errors the policy (absent field != false).
func TestCollectRepos_EmitsAllPolicyReadFields(t *testing.T) {
	fake := &fakeAPI{repos: []Repo{{Name: "r1", DefaultBranch: testBranchMain}}}
	p := New(Options{API: fake, Org: testOrg})
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
		"default_branch_protected", "required_reviewers_count", "allows_force_push",
		"requires_signed_commits", "dependabot_alerts_enabled", "code_scanning_enabled",
		"dismiss_stale_reviews", "require_code_owner_reviews",
		"secret_scanning_enabled", "push_protection_enabled",
	} {
		if _, ok := m[field]; !ok {
			t.Errorf("emitted payload missing policy-read field %q", field)
		}
	}
}

// --- pull_request ----------------------------------------------------------

// prWindow is the audit window the period-scoped tests pass as slot params.
var (
	prWindowStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prWindowEnd   = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
)

// periodRequest builds a SlotRequest carrying the period params the
// orchestrator injects as native time.Time values.
func periodRequest(evidenceType string) core.SlotRequest {
	return core.SlotRequest{
		AcceptedTypes: []string{evidenceType},
		Params: map[string]any{
			"period_start": prWindowStart,
			"period_end":   prWindowEnd,
			"now":          prWindowEnd,
		},
	}
}

func TestCollectPullRequests_HappyPath_MapsAndSorts(t *testing.T) {
	merged := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	fake := &fakeAPI{pulls: []PullRequest{
		{
			Repository: testRepoWeb, Number: 3, Author: testLoginAlice, MergedBy: testLoginBob,
			TargetBranch: testBranchMain, MergeCommitSHA: testCommitSHA, MergedAt: merged,
			Reviews: []Review{
				{User: testLoginAlice, State: testReviewApproved, SubmittedAt: merged.Add(-48 * time.Hour)},
				{User: testLoginBob, State: testReviewApproved, SubmittedAt: merged.Add(-24 * time.Hour)},
			},
			CheckRuns: []CheckRun{{Status: testCheckCompleted, Conclusion: deploymentStatusSuccess}},
		},
		{
			// Self-approved with no CI: the failing side of both derived
			// booleans, and an unattributed merge with no merge commit.
			Repository: testRepoAPI, Number: 12, Author: testLoginCarol,
			TargetBranch: testBranchMain, MergedAt: merged.Add(24 * time.Hour),
			Reviews: []Review{{User: testLoginCarol, State: testReviewApproved, SubmittedAt: merged}},
		},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), periodRequest(EvidenceTypePullRequest))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID: "acme/api#12" < "acme/web#3".
	if records[0].ID != "acme/api#12" || records[1].ID != "acme/web#3" {
		t.Errorf("not sorted by ID: %v", recordIDs(records))
	}
	assertRecordMeta(t, &records[1], EvidenceTypePullRequest, now)

	got := unmarshalPayload[pullRequestPayload](t, records[1].Payload)
	want := pullRequestPayload{
		Repository: testRepoWeb, Number: 3, Author: testLoginAlice, MergedBy: testLoginBob,
		TargetBranch: testBranchMain, MergeCommitSHA: testCommitSHA, MergedAt: "2026-02-01T10:00:00Z",
		ApprovalCount: 2, IndependentApprovalCount: 1, ApprovedBeforeMerge: true, ChecksPassed: true,
	}
	if got != want {
		t.Errorf("web payload = %+v; want %+v", got, want)
	}
	gotSelf := unmarshalPayload[pullRequestPayload](t, records[0].Payload)
	wantSelf := pullRequestPayload{
		Repository: testRepoAPI, Number: 12, Author: testLoginCarol, TargetBranch: testBranchMain,
		MergedAt: "2026-02-02T10:00:00Z", ApprovalCount: 1,
	}
	if gotSelf != wantSelf {
		t.Errorf("self-approved payload = %+v; want %+v", gotSelf, wantSelf)
	}
}
func TestApprovalState_LatestReviewPerUserDecides(t *testing.T) {
	merged := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name            string
		author          string
		reviews         []Review
		wantApprovals   int
		wantIndependent int
		wantBeforeMerge bool
	}{
		{
			name: "dismissed approval does not count", author: testLoginAlice,
			reviews: []Review{
				{User: testLoginDave, State: testReviewApproved, SubmittedAt: merged.Add(-2 * time.Hour)},
				{User: testLoginDave, State: "DISMISSED", SubmittedAt: merged.Add(-time.Hour)},
			},
		},
		{
			name: "changes requested supersedes an earlier approval", author: testLoginAlice,
			reviews: []Review{
				{User: testLoginDave, State: testReviewApproved, SubmittedAt: merged.Add(-2 * time.Hour)},
				{User: testLoginDave, State: "CHANGES_REQUESTED", SubmittedAt: merged.Add(-time.Hour)},
			},
		},
		{
			name: "comment after approval is ignored", author: testLoginAlice,
			reviews: []Review{
				{User: testLoginDave, State: testReviewApproved, SubmittedAt: merged.Add(-2 * time.Hour)},
				{User: testLoginDave, State: "COMMENTED", SubmittedAt: merged.Add(-time.Hour)},
			},
			wantApprovals: 1, wantIndependent: 1, wantBeforeMerge: true,
		},
		{
			name: "duplicate approvals count once", author: testLoginAlice,
			reviews: []Review{
				{User: testLoginDave, State: testReviewApproved, SubmittedAt: merged.Add(-2 * time.Hour)},
				{User: testLoginDave, State: testReviewApproved, SubmittedAt: merged.Add(-time.Hour)},
			},
			wantApprovals: 1, wantIndependent: 1, wantBeforeMerge: true,
		},
		{
			name: "self approval is not independent", author: testLoginAlice,
			reviews: []Review{
				{User: testLoginAlice, State: testReviewApproved, SubmittedAt: merged.Add(-time.Hour)},
			},
			wantApprovals: 1,
		},
		{
			name: "retroactive approval counts but not before merge", author: testLoginAlice,
			reviews: []Review{
				{User: "eve", State: testReviewApproved, SubmittedAt: merged.Add(time.Hour)},
			},
			wantApprovals: 1, wantIndependent: 1,
		},
		{
			name: "approval exactly at merge counts as before merge", author: testLoginAlice,
			reviews: []Review{
				{User: "eve", State: testReviewApproved, SubmittedAt: merged},
			},
			wantApprovals: 1, wantIndependent: 1, wantBeforeMerge: true,
		},
		{
			name: "no reviews at all", author: testLoginAlice,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := PullRequest{Author: tc.author, MergedAt: merged, Reviews: tc.reviews}
			gotA, gotI, gotB := approvalState(&pr)
			if gotA != tc.wantApprovals || gotI != tc.wantIndependent || gotB != tc.wantBeforeMerge {
				t.Errorf("approvalState = (%d, %d, %v); want (%d, %d, %v)",
					gotA, gotI, gotB, tc.wantApprovals, tc.wantIndependent, tc.wantBeforeMerge)
			}
		})
	}
}

func TestChecksPassed(t *testing.T) {
	tests := []struct {
		name        string
		runs        []CheckRun
		statusState string
		statusCount int
		want        bool
	}{
		{name: "no checks configured is not a pass"},
		{name: "no statuses (state pending, count 0) is not a pass", statusState: "pending"},
		{name: "commit statuses only, success", statusState: "success", statusCount: 2, want: true},
		{name: "commit statuses only, failure", statusState: "failure", statusCount: 1},
		{name: "commit statuses pending", statusState: "pending", statusCount: 1},
		{name: "check runs pass but a status failed", runs: []CheckRun{
			{Status: testCheckCompleted, Conclusion: deploymentStatusSuccess},
		}, statusState: "failure", statusCount: 1},
		{name: "check runs and statuses pass", runs: []CheckRun{
			{Status: testCheckCompleted, Conclusion: deploymentStatusSuccess},
		}, statusState: "success", statusCount: 1, want: true},
		{name: "all success", runs: []CheckRun{
			{Status: testCheckCompleted, Conclusion: deploymentStatusSuccess},
			{Status: testCheckCompleted, Conclusion: deploymentStatusSuccess},
		}, want: true},
		{name: "neutral and skipped count as success", runs: []CheckRun{
			{Status: testCheckCompleted, Conclusion: "neutral"},
			{Status: testCheckCompleted, Conclusion: "skipped"},
		}, want: true},
		{name: "one failure", runs: []CheckRun{
			{Status: testCheckCompleted, Conclusion: deploymentStatusSuccess},
			{Status: testCheckCompleted, Conclusion: deploymentStatusFailure},
		}},
		{name: "still running", runs: []CheckRun{{Status: "in_progress"}}},
		{name: "canceled", runs: []CheckRun{{Status: testCheckCompleted, Conclusion: "canceled"}}},
		{name: "timed out", runs: []CheckRun{{Status: testCheckCompleted, Conclusion: "timed_out"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := checksPassed(tc.runs, tc.statusState, tc.statusCount); got != tc.want {
				t.Errorf("checksPassed(%v) = %v; want %v", tc.runs, got, tc.want)
			}
		})
	}
}

func TestCollectPullRequests_DropsMergesOutsideWindow(t *testing.T) {
	fake := &fakeAPI{pulls: []PullRequest{
		{Repository: testRepoWeb, Number: 1, MergedAt: prWindowStart.Add(-time.Hour)},
		{Repository: testRepoWeb, Number: 2, MergedAt: prWindowEnd.Add(time.Hour)},
		{Repository: testRepoWeb, Number: 3}, // never merged: zero timestamp
		{Repository: testRepoWeb, Number: 4, MergedAt: prWindowStart.Add(time.Hour)},
	}}
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return prWindowEnd }})
	records, err := p.Collect(context.Background(), periodRequest(EvidenceTypePullRequest))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "acme/web#4" {
		t.Fatalf("records = %v; want only acme/web#4", recordIDs(records))
	}
}

func TestCollectPullRequests_EmitsAllSchemaFields(t *testing.T) {
	fake := &fakeAPI{pulls: []PullRequest{
		{Repository: testRepoWeb, Number: 1, MergedAt: prWindowStart.Add(time.Hour)},
	}}
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return prWindowEnd }})
	recs, err := p.Collect(context.Background(), periodRequest(EvidenceTypePullRequest))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertPayloadHasFields(t, recs[0].Payload, []string{
		testResourceTypeRepo, "number", "author", "merged_by", "target_branch", "merge_commit_sha",
		"merged_at", "approval_count", "independent_approval_count", "approved_before_merge",
		"checks_passed",
	})
}

func TestCollectPullRequests_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{pullErr: errors.New("rate limit")}, Org: testOrg})
	_, err := p.Collect(context.Background(), periodRequest(EvidenceTypePullRequest))
	if err == nil || !strings.Contains(err.Error(), "list merged pull requests") {
		t.Errorf("want list merged pull requests error; got %v", err)
	}
}

// --- deployment ------------------------------------------------------------

func TestCollectDeployments_HappyPath_MapsAndSorts(t *testing.T) {
	created := time.Date(2026, 2, 2, 8, 30, 0, 0, time.UTC)
	fake := &fakeAPI{deployments: []Deployment{
		{
			Repository: testRepoWeb, ID: "10", SHA: testCommitSHA, Environment: testEnvProduction,
			Creator: testLoginBob, CreatedAt: created, State: deploymentStatusSuccess,
		},
		{
			// No production signal, no creator and no status entries.
			Repository: testRepoAPI, ID: "5", Environment: testEnvStaging,
			CreatedAt: created.Add(24 * time.Hour),
		},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), periodRequest(EvidenceTypeDeployment))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID: "acme/api/deployments/5" < "acme/web/deployments/10".
	if records[0].ID != "acme/api/deployments/5" || records[1].ID != "acme/web/deployments/10" {
		t.Errorf("not sorted by ID: %v", recordIDs(records))
	}
	assertRecordMeta(t, &records[1], EvidenceTypeDeployment, now)

	got := unmarshalPayload[deploymentPayload](t, records[1].Payload)
	want := deploymentPayload{
		Repository: testRepoWeb, DeploymentID: "10", Environment: testEnvProduction,
		IsProduction: true, DeployedBy: testLoginBob, DeployedAt: "2026-02-02T08:30:00Z",
		CommitSHA: testCommitSHA, Status: deploymentStatusSuccess,
	}
	if got != want {
		t.Errorf("production payload = %+v; want %+v", got, want)
	}
	// Absent production_environment plus a non-production name leaves
	// is_production false; an empty statuses list yields "unknown", never
	// pending and never failure.
	gotStaging := unmarshalPayload[deploymentPayload](t, records[0].Payload)
	wantStaging := deploymentPayload{
		Repository: testRepoAPI, DeploymentID: "5", Environment: testEnvStaging,
		DeployedAt: "2026-02-03T08:30:00Z", Status: deploymentStatusUnknown,
	}
	if gotStaging != wantStaging {
		t.Errorf("staging payload = %+v; want %+v", gotStaging, wantStaging)
	}
}
func TestIsProductionEnvironment(t *testing.T) {
	tests := []struct {
		flag bool
		env  string
		want bool
	}{
		{flag: true, env: testEnvStaging, want: true}, // explicit flag wins
		{env: testEnvProduction, want: true},
		{env: "Prod", want: true},
		{env: "LIVE", want: true},
		{env: " production ", want: true},
		{env: testEnvStaging},
		{env: "prod-canary"}, // not a conventional name: not production
		{env: ""},
	}
	for _, tc := range tests {
		if got := isProductionEnvironment(tc.flag, tc.env); got != tc.want {
			t.Errorf("isProductionEnvironment(%v, %q) = %v; want %v", tc.flag, tc.env, got, tc.want)
		}
	}
}

func TestNormalizeDeploymentState(t *testing.T) {
	states := map[string]string{
		deploymentStatusSuccess: deploymentStatusSuccess, "error": deploymentStatusFailure, deploymentStatusFailure: deploymentStatusFailure,
		deploymentStatusPending: deploymentStatusPending, "queued": deploymentStatusPending, "in_progress": deploymentStatusPending,
		"inactive": deploymentStatusUnknown, "": deploymentStatusUnknown, "weird": deploymentStatusUnknown,
	}
	for in, want := range states {
		if got := normalizeDeploymentState(in); got != want {
			t.Errorf("normalizeDeploymentState(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestCollectDeployments_DropsCreationsOutsideWindow(t *testing.T) {
	fake := &fakeAPI{deployments: []Deployment{
		{Repository: testRepoWeb, ID: "1", CreatedAt: prWindowStart.Add(-time.Hour)},
		{Repository: testRepoWeb, ID: "2", CreatedAt: prWindowEnd.Add(time.Hour)},
		{Repository: testRepoWeb, ID: "3"}, // zero timestamp
		{Repository: testRepoWeb, ID: "4", CreatedAt: prWindowStart.Add(time.Hour)},
	}}
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return prWindowEnd }})
	records, err := p.Collect(context.Background(), periodRequest(EvidenceTypeDeployment))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "acme/web/deployments/4" {
		t.Fatalf("records = %v; want only acme/web/deployments/4", recordIDs(records))
	}
}

func TestCollectDeployments_EmitsAllSchemaFields(t *testing.T) {
	fake := &fakeAPI{deployments: []Deployment{
		{Repository: testRepoWeb, ID: "1", CreatedAt: prWindowStart.Add(time.Hour)},
	}}
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return prWindowEnd }})
	recs, err := p.Collect(context.Background(), periodRequest(EvidenceTypeDeployment))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertPayloadHasFields(t, recs[0].Payload, []string{
		testResourceTypeRepo, "deployment_id", "environment", "is_production",
		"deployed_by", "deployed_at", "commit_sha", "status",
	})
}

func TestCollectDeployments_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{deployErr: errors.New("forbidden")}, Org: testOrg})
	_, err := p.Collect(context.Background(), periodRequest(EvidenceTypeDeployment))
	if err == nil || !strings.Contains(err.Error(), "list deployments") {
		t.Errorf("want list deployments error; got %v", err)
	}
}

// --- period window ---------------------------------------------------------

func TestPeriodWindow_UsesInjectedParams(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return prWindowEnd }})
	if _, err := p.Collect(context.Background(), periodRequest(EvidenceTypePullRequest)); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !fake.gotStart.Equal(prWindowStart) || !fake.gotEnd.Equal(prWindowEnd) {
		t.Errorf("window = [%v, %v]; want [%v, %v]", fake.gotStart, fake.gotEnd, prWindowStart, prWindowEnd)
	}
}

func TestPeriodWindow_FallsBackToTrailingYearOnInjectedClock(t *testing.T) {
	fake := &fakeAPI{}
	now := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return now }})
	// No Params at all — the shape sourcetest.RunConformance passes.
	if _, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDeployment}}); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !fake.gotEnd.Equal(now) {
		t.Errorf("end = %v; want the injected clock %v", fake.gotEnd, now)
	}
	if want := now.AddDate(-1, 0, 0); !fake.gotStart.Equal(want) {
		t.Errorf("start = %v; want %v", fake.gotStart, want)
	}
}

func TestPeriodWindow_BothTypesShareOneWindow(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake, Org: testOrg, Now: func() time.Time { return prWindowEnd }})
	req := core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypePullRequest, EvidenceTypeDeployment},
		Params:        map[string]any{"period_start": prWindowStart, "period_end": prWindowEnd},
	}
	if _, err := p.Collect(context.Background(), req); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.listPullsCount != 1 || fake.listDeploymentsCount != 1 {
		t.Errorf("calls = pulls %d, deployments %d; want 1 each",
			fake.listPullsCount, fake.listDeploymentsCount)
	}
}

// --- shared test helpers ---------------------------------------------------

func unmarshalPayload[T any](t *testing.T, payload []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(payload, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return v
}

// assertRecordMeta checks the envelope metadata every emitted record must
// carry. IdentityKey stays empty on both period-scoped types — neither is a
// directory identity the roster join matches on.
func assertRecordMeta(t *testing.T, r *core.EvidenceRecord, wantType string, wantNow time.Time) {
	t.Helper()
	if r.Type != wantType || r.CollectedAt != wantNow ||
		r.SourceID != SourceID || r.IdentityKey != "" {
		t.Errorf("record meta = %+v", r)
	}
}

func recordIDs(records []core.EvidenceRecord) []string {
	out := make([]string, 0, len(records))
	for i := range records {
		out = append(out, records[i].ID)
	}
	return out
}

func assertPayloadHasFields(t *testing.T, payload []byte, fields []string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			t.Errorf("emitted payload missing field %q", f)
		}
	}
}

// --- httpAPI: period-scoped endpoints --------------------------------------

// Paths of the web repo's pull-request endpoints in the handlers below.
const (
	pathWebPulls        = "/repos/acme/web/pulls"
	pathWebPull3        = "/repos/acme/web/pulls/3"
	pathWebPull3Reviews = "/repos/acme/web/pulls/3/reviews"
)

// pullsTestHandler serves the repos / pulls / detail / reviews / check-runs
// endpoints ListMergedPullRequests walks.
func pullsTestHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = w.Write([]byte(`[{"name":"web","default_branch":"main"},` + //nolint:errcheck // test handler
				`{"name":"nobranch"}]`))
		case pathWebPulls:
			assertPullsQuery(t, r)
			_, _ = w.Write([]byte(`[` + //nolint:errcheck // test handler
				// Merged inside the window.
				`{"number":3,"merged_at":"2026-02-01T10:00:00Z","updated_at":"2026-02-01T10:00:00Z",` +
				`"merge_commit_sha":"abc123","user":{"login":"alice"},` +
				`"base":{"ref":"main"},"head":{"sha":"headsha"}},` +
				// Closed without merging: not a change.
				`{"number":4,"merged_at":null,"updated_at":"2026-01-20T10:00:00Z",` +
				`"user":{"login":"bob"},"base":{"ref":"main"},"head":{"sha":"x"}},` +
				// Older than the window: stops pagination.
				`{"number":1,"merged_at":"2025-11-01T10:00:00Z","updated_at":"2025-11-01T10:00:00Z",` +
				`"user":{"login":"carol"},"base":{"ref":"main"},"head":{"sha":"y"}}]`))
		case pathWebPull3:
			_, _ = w.Write([]byte(`{"merged_by":{"login":"bob"}}`)) //nolint:errcheck // test handler
		case pathWebPull3Reviews:
			_, _ = w.Write([]byte(`[{"state":"APPROVED","submitted_at":"2026-01-31T10:00:00Z",` + //nolint:errcheck // test handler
				`"user":{"login":"bob"}}]`))
		case "/repos/acme/web/commits/headsha/check-runs":
			_, _ = w.Write([]byte(`{"total_count":1,"check_runs":[{"status":"completed","conclusion":"success"}]}`)) //nolint:errcheck // test handler
		case "/repos/acme/web/commits/headsha/status":
			_, _ = w.Write([]byte(`{"state":"success","total_count":1,"statuses":[{"state":"success"}]}`)) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	})
}

// assertPullsQuery checks the listing is requested closed-on-default-branch,
// newest-updated-first — the ordering the pagination stop depends on.
func assertPullsQuery(t *testing.T, r *http.Request) {
	t.Helper()
	q := r.URL.Query()
	want := map[string]string{"state": "closed", "base": testBranchMain, "sort": "updated", "direction": "desc"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("pulls query %s = %q; want %q", k, q.Get(k), v)
		}
	}
}

func TestHTTPAPI_ListMergedPullRequests_HappyPath(t *testing.T) {
	srv := httptest.NewServer(pullsTestHandler(t))
	defer srv.Close()

	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	prs, err := api.ListMergedPullRequests(context.Background(),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ListMergedPullRequests: %v", err)
	}
	// The branch-less repo is never queried, and the unmerged and
	// out-of-window items are dropped.
	want := []PullRequest{{
		Repository: testRepoWeb, Number: 3, Author: testLoginAlice, MergedBy: testLoginBob,
		TargetBranch: testBranchMain, MergeCommitSHA: testCommitSHA,
		MergedAt: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC),
		Reviews: []Review{{
			User: testLoginBob, State: testReviewApproved,
			SubmittedAt: time.Date(2026, 1, 31, 10, 0, 0, 0, time.UTC),
		}},
		CheckRuns:         []CheckRun{{Status: testCheckCompleted, Conclusion: deploymentStatusSuccess}},
		CommitStatusState: deploymentStatusSuccess,
		CommitStatusCount: 1,
	}}
	if !reflect.DeepEqual(prs, want) {
		t.Errorf("ListMergedPullRequests = %+v; want %+v", prs, want)
	}
}

// Every per-repo read the change evidence depends on must surface its
// error: a repo dropped on a 403 (rate limit, missing scope) used to let
// the change-management policies pass on the repos that could be read.
func TestHTTPAPI_ListMergedPullRequests_PerRepoErrorsSurface(t *testing.T) {
	failing := []string{
		pathWebPulls,
		pathWebPull3,
		pathWebPull3Reviews,
		"/repos/acme/web/commits/headsha/check-runs",
		"/repos/acme/web/commits/headsha/status",
	}
	for _, deny := range failing {
		t.Run(deny, func(t *testing.T) {
			ok := pullsTestHandler(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == deny {
					http.Error(w, `{"message":"API rate limit exceeded for user ID 1."}`, http.StatusForbidden)
					return
				}
				ok.ServeHTTP(w, r)
			}))
			defer srv.Close()
			api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
			_, err := api.ListMergedPullRequests(context.Background(),
				time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
			if err == nil || !strings.Contains(err.Error(), "rate limit") {
				t.Errorf("err = %v; want the 403 on %s returned", err, deny)
			}
		})
	}
}

// A null author and a null merged_by are vendor answers, not errors.
func TestHTTPAPI_ListMergedPullRequests_NullUsers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/repos"):
			_, _ = w.Write([]byte(`[{"name":"web","default_branch":"main"}]`)) //nolint:errcheck // test handler
		case r.URL.Path == pathWebPulls:
			_, _ = w.Write([]byte(`[{"number":3,"merged_at":"2026-02-01T10:00:00Z",` + //nolint:errcheck // test handler
				`"updated_at":"2026-02-01T10:00:00Z","user":null,` +
				`"base":{"ref":"main"},"head":{"sha":""}}]`))
		case r.URL.Path == pathWebPull3:
			_, _ = w.Write([]byte(`{"merged_by":null}`)) //nolint:errcheck // test handler
		case r.URL.Path == pathWebPull3Reviews:
			_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
		default:
			// check-runs and status are never called: the head SHA is empty.
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	prs, err := api.ListMergedPullRequests(context.Background(),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ListMergedPullRequests: %v", err)
	}
	if len(prs) != 1 || prs[0].Author != "" || prs[0].MergedBy != "" ||
		len(prs[0].Reviews) != 0 || len(prs[0].CheckRuns) != 0 || prs[0].CommitStatusCount != 0 {
		t.Errorf("pulls = %+v", prs)
	}
}

// deploymentsTestHandler serves the repos / deployments / statuses endpoints
// ListDeployments walks.
func deploymentsTestHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = w.Write([]byte(`[{"name":"web","default_branch":"main"}]`)) //nolint:errcheck // test handler
		case "/repos/acme/web/deployments":
			_, _ = w.Write([]byte(`[` + //nolint:errcheck // test handler
				// production_environment ABSENT: must read as false.
				`{"id":10,"sha":"abc123","environment":"production",` +
				`"created_at":"2026-02-02T08:30:00Z","creator":{"login":"bob"}},` +
				// creator null and no statuses.
				`{"id":5,"sha":"def456","environment":"staging",` +
				`"created_at":"2026-02-03T08:30:00Z","creator":null},` +
				// Older than the window: stops pagination.
				`{"id":1,"environment":"staging","created_at":"2025-11-01T00:00:00Z"}]`))
		case "/repos/acme/web/deployments/10/statuses":
			_, _ = w.Write([]byte(`[{"state":"success"},{"state":"pending"}]`)) //nolint:errcheck // test handler
		case "/repos/acme/web/deployments/5/statuses":
			_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	})
}

func TestHTTPAPI_ListDeployments_HappyPath(t *testing.T) {
	srv := httptest.NewServer(deploymentsTestHandler(t))
	defer srv.Close()

	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	deployments, err := api.ListDeployments(context.Background(),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ListDeployments: %v", err)
	}
	// The newest status wins; an empty statuses list leaves State empty
	// (normalized to "unknown" by the collector).
	want := []Deployment{
		{
			Repository: testRepoWeb, ID: "10", SHA: testCommitSHA, Environment: testEnvProduction,
			Creator: testLoginBob, CreatedAt: time.Date(2026, 2, 2, 8, 30, 0, 0, time.UTC),
			State: deploymentStatusSuccess,
		},
		{
			Repository: testRepoWeb, ID: "5", SHA: "def456", Environment: testEnvStaging,
			CreatedAt: time.Date(2026, 2, 3, 8, 30, 0, 0, time.UTC),
		},
	}
	if !reflect.DeepEqual(deployments, want) {
		t.Errorf("ListDeployments = %+v; want %+v", deployments, want)
	}
}

func TestHTTPAPI_ListDeployments_PerRepoErrorsSurface(t *testing.T) {
	for _, deny := range []string{"/repos/acme/web/deployments", "/repos/acme/web/deployments/10/statuses"} {
		t.Run(deny, func(t *testing.T) {
			ok := deploymentsTestHandler(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == deny {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				ok.ServeHTTP(w, r)
			}))
			defer srv.Close()
			api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
			if _, err := api.ListDeployments(context.Background(),
				time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)); err == nil {
				t.Errorf("ListDeployments = nil error; want the 403 on %s returned", deny)
			}
		})
	}
}

// GitHub's org-wide 2FA flag is a tri-state the adapter flattens: a token
// without admin:org sees null and the plugin emits false, with nothing in the
// run to distinguish "2FA is not enforced" from "we were not allowed to look".
// That is the same shape as gitlab's mfa_enabled — conditional, not absolute —
// and two shipped policies grade a control on it, so the plugin must say so.
func TestCaveats_DeclaresTheOrg2FAPrivilegeGap(t *testing.T) {
	var p core.SourcePlugin = New(Options{})
	c, ok := p.(core.CaveatedSource)
	if !ok {
		t.Fatal("github must implement core.CaveatedSource")
	}
	cav := c.Caveats()

	// Looked up by (type, field), never by index: another caveat may join this
	// one, and the assertion must keep testing the same thing when it does.
	var found *core.SourceCaveat
	for i := range cav {
		if cav[i].EvidenceType == EvidenceTypeOrgPolicy && cav[i].Field == "two_factor_required" {
			found = &cav[i]
		}
	}
	if found == nil {
		t.Fatalf("Caveats() = %+v; want source_control_org_policy.two_factor_required", cav)
	}
	if found.Detail == "" {
		t.Error("a caveat with no detail tells the operator nothing to act on")
	}
}

// mfa_enabled must NOT be caveated: the per-user 2FA listing needs the same
// admin:org scope, but its failure is RETURNED as an error rather than
// swallowed, so a run without the scope errors the policy instead of grading
// it on a fabricated false. A caveat there would warn about a gap that cannot
// silently occur.
func TestCaveats_DoesNotCaveatDirectoryUserMFA(t *testing.T) {
	c, ok := core.SourcePlugin(New(Options{})).(core.CaveatedSource)
	if !ok {
		t.Fatal("github must implement core.CaveatedSource")
	}
	for _, cv := range c.Caveats() {
		if cv.EvidenceType == EvidenceTypeDirectoryUser && cv.Field == "mfa_enabled" {
			t.Errorf("caveat %+v declared, but the 2FA listing error is returned, not swallowed", cv)
		}
	}
}

// Endpoint keys for repoDetailServer responses.
const (
	epProtection    = "protection"
	epRules         = "rules"
	epVulnerability = "vulnerability"
	epCodeScanning  = "codescanning"
)

// repoDetailServer serves one repo "app" (or archived "old") with the
// given per-endpoint responses; an unset endpoint answers with the
// "nothing configured" response.
type repoDetailResp struct {
	status int
	body   string
}

func repoDetailServer(t *testing.T, resp map[string]repoDetailResp) *httptest.Server {
	t.Helper()
	defaults := map[string]repoDetailResp{
		epProtection:    {http.StatusNotFound, `{"message":"Branch not protected"}`},
		epRules:         {http.StatusOK, `[]`},
		epVulnerability: {http.StatusNoContent, ``},
		epCodeScanning:  {http.StatusNotFound, `{"message":"no analysis found"}`},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ""
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/repos"):
			_, _ = w.Write([]byte(`[{"name":"app","default_branch":"main"},{"name":"old","default_branch":"main","archived":true}]`)) //nolint:errcheck // test handler
			return
		case strings.HasPrefix(r.URL.Path, "/repos/acme/old/"):
			t.Errorf("archived repo queried: %s", r.URL.Path)
			return
		case r.URL.Path == "/repos/acme/app/branches/main/protection":
			key = epProtection
		case r.URL.Path == "/repos/acme/app/rules/branches/main":
			key = epRules
		case r.URL.Path == "/repos/acme/app/vulnerability-alerts":
			key = epVulnerability
		case r.URL.Path == "/repos/acme/app/code-scanning/analyses":
			key = epCodeScanning
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			return
		}
		rr, ok := resp[key]
		if !ok {
			rr = defaults[key]
		}
		w.WriteHeader(rr.status)
		_, _ = w.Write([]byte(rr.body)) //nolint:errcheck // test handler
	}))
}

func listOneRepo(t *testing.T, resp map[string]repoDetailResp) (Repo, error) {
	t.Helper()
	srv := repoDetailServer(t, resp)
	defer srv.Close()
	api := &httpAPI{org: testOrg, token: testToken, base: srv.URL, client: srv.Client()}
	repos, err := api.ListRepos(context.Background())
	if err != nil {
		return Repo{}, err
	}
	for _, r := range repos {
		if r.Name == "app" {
			return r, nil
		}
	}
	t.Fatalf("repo app missing from %+v", repos)
	return Repo{}, nil
}

// An unprotected branch permits force-push; a ruleset protects a branch the
// classic endpoint calls unprotected; and an unreadable protection is an
// error, never a guessed "unprotected, force-push blocked".
func TestHTTPAPI_ListRepos_ProtectionSemantics(t *testing.T) {
	classicNoForce := `{"required_pull_request_reviews":{"required_approving_review_count":1},` +
		`"allow_force_pushes":{"enabled":false}}`
	tests := []struct {
		name    string
		resp    map[string]repoDetailResp
		want    Repo
		wantErr string
	}{
		{
			name: "no classic protection, no rules: unprotected, force-push allowed",
			want: Repo{ProtectionOn: false, AllowsForcePush: true},
		},
		{
			name: "plan without branch protection (403 upgrade): unprotected",
			resp: map[string]repoDetailResp{epProtection: {http.StatusForbidden,
				`{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature."}`}},
			want: Repo{AllowsForcePush: true},
		},
		{
			name: "classic protection blocks force-push",
			resp: map[string]repoDetailResp{epProtection: {http.StatusOK, classicNoForce}},
			want: Repo{ProtectionOn: true, RequiredReviews: 1},
		},
		{
			name: "classic protection that allows force-push",
			resp: map[string]repoDetailResp{epProtection: {http.StatusOK, `{"allow_force_pushes":{"enabled":true}}`}},
			want: Repo{ProtectionOn: true, AllowsForcePush: true},
		},
		{
			name: "ruleset only",
			resp: map[string]repoDetailResp{epRules: {http.StatusOK, `[` +
				`{"type":"pull_request","parameters":{"required_approving_review_count":2,` +
				`"dismiss_stale_reviews_on_push":true,"require_code_owner_review":true}},` +
				`{"type":"non_fast_forward"},{"type":"required_signatures"},{"type":"required_linear_history"}]`}},
			want: Repo{ProtectionOn: true, RequiredReviews: 2, DismissStaleReviews: true,
				RequireCodeOwnerReviews: true, RequiresSignedCommits: true, RequiresLinearHistory: true},
		},
		{
			name: "classic allows force-push but a ruleset blocks it; stricter review count wins",
			resp: map[string]repoDetailResp{
				epProtection: {http.StatusOK, `{"required_pull_request_reviews":{"required_approving_review_count":3},"allow_force_pushes":{"enabled":true}}`},
				epRules:      {http.StatusOK, `[{"type":"pull_request","parameters":{"required_approving_review_count":1}},{"type":"non_fast_forward"}]`},
			},
			want: Repo{ProtectionOn: true, RequiredReviews: 3},
		},
		{
			name:    "token without admin read on protection",
			resp:    map[string]repoDetailResp{epProtection: {http.StatusForbidden, msgAdminRights}},
			wantErr: "admin rights",
		},
		{
			name:    "rate limit on protection",
			resp:    map[string]repoDetailResp{epProtection: {http.StatusForbidden, `{"message":"API rate limit exceeded"}`}},
			wantErr: "rate limit",
		},
		{
			name:    "server error on protection",
			resp:    map[string]repoDetailResp{epProtection: {http.StatusBadGateway, `bad gateway`}},
			wantErr: "502",
		},
		{
			name:    "a 404 that is not 'Branch not protected'",
			resp:    map[string]repoDetailResp{epProtection: {http.StatusNotFound, `{"message":"Not Found"}`}},
			wantErr: "404",
		},
		{
			name:    "rules unreadable",
			resp:    map[string]repoDetailResp{epRules: {http.StatusInternalServerError, `boom`}},
			wantErr: "branch rules",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listOneRepo(t, tc.resp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v; want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListRepos: %v", err)
			}
			if got.ProtectionOn != tc.want.ProtectionOn || got.AllowsForcePush != tc.want.AllowsForcePush ||
				got.RequiredReviews != tc.want.RequiredReviews || got.DismissStaleReviews != tc.want.DismissStaleReviews ||
				got.RequireCodeOwnerReviews != tc.want.RequireCodeOwnerReviews ||
				got.RequiresSignedCommits != tc.want.RequiresSignedCommits ||
				got.RequiresLinearHistory != tc.want.RequiresLinearHistory {
				t.Errorf("protection = %+v; want %+v", got, tc.want)
			}
		})
	}
}

// code_scanning_enabled comes from the code-scanning analyses endpoint
// (security_and_analysis has no code-scanning field), and the Dependabot
// probe must not read a denied request as "disabled".
func TestHTTPAPI_ListRepos_SecurityFeatureSemantics(t *testing.T) {
	tests := []struct {
		name         string
		resp         map[string]repoDetailResp
		wantScanning bool
		wantDepbot   bool
		wantErr      string
	}{
		{name: "analysis present", resp: map[string]repoDetailResp{epCodeScanning: {http.StatusOK, `[{"id":7}]`}},
			wantScanning: true, wantDepbot: true},
		{name: "no analysis found", wantDepbot: true},
		{name: "empty analyses list", resp: map[string]repoDetailResp{epCodeScanning: {http.StatusOK, `[]`}}, wantDepbot: true},
		{name: "Advanced Security not enabled", resp: map[string]repoDetailResp{epCodeScanning: {http.StatusForbidden,
			`{"message":"Advanced Security must be enabled for this repository to use code scanning."}`}}, wantDepbot: true},
		{name: "code scanning denied to the token", resp: map[string]repoDetailResp{epCodeScanning: {http.StatusForbidden,
			`{"message":"Resource not accessible by integration"}`}}, wantErr: "code scanning"},
		{name: "dependabot alerts disabled", resp: map[string]repoDetailResp{epVulnerability: {http.StatusNotFound, ``}}},
		{name: "dependabot probe denied", resp: map[string]repoDetailResp{epVulnerability: {http.StatusForbidden,
			msgAdminRights}}, wantErr: "dependabot"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listOneRepo(t, tc.resp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v; want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListRepos: %v", err)
			}
			if got.CodeScanningEnabled != tc.wantScanning || got.DependabotAlertsEnabled != tc.wantDepbot {
				t.Errorf("code_scanning=%v dependabot=%v; want %v %v",
					got.CodeScanningEnabled, got.DependabotAlertsEnabled, tc.wantScanning, tc.wantDepbot)
			}
		})
	}
}

// Archived repositories are read-only and out of scope for the
// repository policies: the plugin emits no git_repository record for them.
func TestCollectRepos_DropsArchivedRepos(t *testing.T) {
	api := &fakeAPI{repos: []Repo{
		{Name: "live", DefaultBranch: testBranchMain},
		{Name: "old", DefaultBranch: testBranchMain, Archived: true},
	}}
	recs, err := New(Options{API: api, Org: testOrg}).Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != "live" {
		t.Errorf("records = %v; want only the unarchived repo", recordIDs(recs))
	}
}

// msgAdminRights is GitHub's 403 body for a non-admin token on an
// admin-only repository read.
const msgAdminRights = `{"message":"Must have admin rights to Repository."}`

// Classic branch protection and the vulnerability-alerts probe need admin
// on the repository. A token without it fails the source (fail closed),
// and the error names the repository and the permission to grant, so the
// customer can fix the token instead of guessing.
func TestHTTPAPI_ListRepos_AdminPermissionErrorNamesRepoAndPermission(t *testing.T) {
	denied := `{"message":"Resource not accessible by integration"}`
	tests := []struct {
		name string
		resp map[string]repoDetailResp
	}{
		{"protection denied to GITHUB_TOKEN", map[string]repoDetailResp{epProtection: {http.StatusForbidden, denied}}},
		{"protection denied to a non-admin user", map[string]repoDetailResp{epProtection: {http.StatusForbidden,
			msgAdminRights}}},
		{"protection hidden from the token", map[string]repoDetailResp{epProtection: {http.StatusNotFound, `{"message":"Not Found"}`}}},
		{"vulnerability alerts denied", map[string]repoDetailResp{epVulnerability: {http.StatusForbidden, denied}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := listOneRepo(t, tc.resp)
			if err == nil {
				t.Fatal("ListRepos = nil error; want the permission failure")
			}
			for _, want := range []string{"repository app", "admin", "Administration: read", "GITHUB_TOKEN"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q; want it to contain %q", err, want)
				}
			}
		})
	}
}
