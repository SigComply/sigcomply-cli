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
	repos         []Repo
	members       []Member
	collaborators []Member
	orgPolicy     OrgPolicy
	alerts        []DependabotAlert
	repoErr       error
	memErr        error
	collabErr     error
	orgErr        error
	alertErr      error

	listReposCount    int
	listMembersCount  int
	listCollabCount   int
	getOrgPolicyCount int
	listAlertsCount   int
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

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "acme"})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 4 || em[0] != EvidenceTypeRepository || em[1] != EvidenceTypeDirectoryUser ||
		em[2] != EvidenceTypeOrgPolicy || em[3] != EvidenceTypeVulnerability {
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
			{Login: "bob", TwoFactorOn: false, Role: "member"},
			{Login: "alice", TwoFactorOn: true, Role: "admin"},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: "acme", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}, PolicyID: "p2"})
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
		members: []Member{{Login: "alice", TwoFactorOn: true, Role: "admin"}},
		collaborators: []Member{
			{Login: "contractor-carol", TwoFactorOn: false},
		},
	}
	p := New(Options{API: fake, Org: "acme"})
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
	if byID["alice"].IsExternal {
		t.Errorf("member alice should not be external")
	}
	if !byID["alice"].IsAdmin {
		t.Errorf("member alice should be admin")
	}
	carol := byID["contractor-carol"]
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
	p := New(Options{API: &fakeAPI{collabErr: errors.New("forbidden")}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "list outside collaborators") {
		t.Errorf("want list outside collaborators error; got %v", err)
	}
}

func TestCollectOrgPolicy_HappyPath(t *testing.T) {
	fake := &fakeAPI{orgPolicy: OrgPolicy{
		TwoFactorRequired:      true,
		DefaultRepoPermission:  "read",
		SecretScanningNewRepos: true,
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: "acme", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeOrgPolicy}, PolicyID: "p3"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (singleton)", len(records))
	}
	r := records[0]
	if r.ID != "acme" || r.Type != EvidenceTypeOrgPolicy || r.SourceID != SourceID || r.CollectedAt != now {
		t.Errorf("record meta = %+v", r)
	}
	var op orgPolicyPayload
	if err := json.Unmarshal(r.Payload, &op); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if op.ID != "acme" || op.Provider != "github" || !op.TwoFactorRequired ||
		op.DefaultMemberRepositoryPermission != "read" || !op.SecretScanningEnabledNewRepos {
		t.Errorf("payload = %+v", op)
	}
}

// TestCollectOrgPolicy_EmitsRequiredFields guards the under-emission
// null-trap: the source_control_org_policy schema's required fields must
// always be present in the emitted payload.
func TestCollectOrgPolicy_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{orgPolicy: OrgPolicy{DefaultRepoPermission: "none"}}
	p := New(Options{API: fake, Org: "acme"})
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
	p := New(Options{API: &fakeAPI{orgErr: errors.New("forbidden")}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeOrgPolicy}})
	if err == nil || !strings.Contains(err.Error(), "get org policy") {
		t.Errorf("want get org policy error; got %v", err)
	}
}

func TestCollectVulnerabilities_HappyPath_MapsAndSorts(t *testing.T) {
	fake := &fakeAPI{alerts: []DependabotAlert{
		{Number: 7, RepoFullName: "acme/web", PackageName: "lodash", Summary: "Prototype pollution",
			Severity: "high", State: "open", CVEID: "CVE-2020-8203", CVSSScore: 7.4, PatchAvailable: true},
		{Number: 3, RepoFullName: "acme/api", PackageName: "left-pad", Summary: "ReDoS",
			Severity: "critical", State: "open"},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Org: "acme", Now: func() time.Time { return now }})
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
		ResourceID:           "acme/web",
		ResourceType:         "repository",
		Title:                "lodash: Prototype pollution",
		Severity:             "HIGH",
		Status:               "ACTIVE",
		CVEID:                "CVE-2020-8203",
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
		"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "moderate": "MEDIUM",
		"low": "LOW", "weird": "INFORMATIONAL", "": "INFORMATIONAL",
	}
	for in, want := range sev {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q; want %q", in, got, want)
		}
	}
	state := map[string]string{
		"open": "ACTIVE", "fixed": "RESOLVED", "dismissed": "SUPPRESSED",
		"auto_dismissed": "SUPPRESSED", "unknown": "ACTIVE",
	}
	for in, want := range state {
		if got := normalizeAlertState(in); got != want {
			t.Errorf("normalizeAlertState(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestCollectVulnerabilities_EmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{alerts: []DependabotAlert{{Number: 1, RepoFullName: "acme/x", Severity: "low", State: "open"}}}
	p := New(Options{API: fake, Org: "acme"})
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
	p := New(Options{API: &fakeAPI{alertErr: errors.New("rate limit")}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnerability}})
	if err == nil || !strings.Contains(err.Error(), "list dependabot alerts") {
		t.Errorf("want list dependabot alerts error; got %v", err)
	}
}

func TestCollect_NoData(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, Org: "acme"})
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
	p := New(Options{API: &fakeAPI{}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"s3_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollectRepos_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{repoErr: errors.New("rate limit")}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRepository}})
	if err == nil || !strings.Contains(err.Error(), "list repos") {
		t.Errorf("want list repos error; got %v", err)
	}
}

func TestCollectMembers_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{memErr: errors.New("forbidden")}, Org: "acme"})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "list org members") {
		t.Errorf("want list org members error; got %v", err)
	}
}

func TestCollect_DefaultNowIsInjected(t *testing.T) {
	fake := &fakeAPI{repos: []Repo{{Name: "r1", DefaultBranch: "main"}}}
	p := New(Options{API: fake, Org: "acme"})
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
		repos:   []Repo{{Name: "r1", DefaultBranch: "main"}},
		members: []Member{{Login: "alice", TwoFactorOn: true}},
	}
	p := New(Options{API: fake, Org: "acme"})
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
			_, _ = w.Write([]byte(`[` + //nolint:errcheck // test handler
				`{"name":"web","default_branch":"main","private":true,` +
				`"security_and_analysis":{"secret_scanning":{"status":"enabled"},` +
				`"secret_scanning_push_protection":{"status":"enabled"},` +
				`"code_scanning_default_setup":{"status":"enabled"}}},` +
				`{"name":"api","default_branch":"main"}]`))
		case r.URL.Path == "/repos/acme/web/branches/main/protection":
			_, _ = w.Write([]byte(`{"required_pull_request_reviews":{"required_approving_review_count":2,` + //nolint:errcheck // test handler
				`"dismiss_stale_reviews":true,"require_code_owner_reviews":true},` +
				`"required_signatures":{"enabled":true},"allow_force_pushes":{"enabled":false},` +
				`"required_linear_history":{"enabled":true}}`))
		case r.URL.Path == "/repos/acme/api/branches/main/protection":
			http.Error(w, "not found", http.StatusNotFound)
		case r.URL.Path == "/repos/acme/web/vulnerability-alerts":
			w.WriteHeader(http.StatusNoContent) // enabled
		case r.URL.Path == "/repos/acme/api/vulnerability-alerts":
			http.Error(w, "not found", http.StatusNotFound) // disabled
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
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
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
	if byLogin["carol"].TwoFactorOn {
		t.Errorf("carol should have 2FA off")
	}
	if !byLogin["dave"].TwoFactorOn {
		t.Errorf("dave should have 2FA on")
	}
	if byLogin["carol"].Role != "" {
		t.Errorf("outside collaborators carry no role; got %q", byLogin["carol"].Role)
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
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	op, err := api.GetOrgPolicy(context.Background())
	if err != nil {
		t.Fatalf("GetOrgPolicy: %v", err)
	}
	if !op.TwoFactorRequired || op.DefaultRepoPermission != "read" ||
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
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
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
		if r.URL.Query().Get("state") != "open" {
			t.Errorf("want state=open; got %q", r.URL.Query().Get("state"))
		}
		_, _ = w.Write([]byte(`[{"number":7,"state":"open",` + //nolint:errcheck // test handler
			`"dependency":{"package":{"name":"lodash"}},` +
			`"security_advisory":{"cve_id":"CVE-2020-8203","summary":"Prototype pollution","severity":"high","cvss":{"score":7.4}},` +
			`"security_vulnerability":{"first_patched_version":{"identifier":"4.17.19"}},` +
			`"repository":{"full_name":"acme/web"}}]`))
	}))
	defer srv.Close()
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	alerts, err := api.ListDependabotAlerts(context.Background())
	if err != nil {
		t.Fatalf("ListDependabotAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("len = %d; want 1", len(alerts))
	}
	a := alerts[0]
	if a.Number != 7 || a.RepoFullName != "acme/web" || a.PackageName != "lodash" ||
		a.Severity != "high" || a.CVEID != "CVE-2020-8203" || a.CVSSScore != 7.4 || !a.PatchAvailable {
		t.Errorf("alert = %+v", a)
	}
}

// TestHTTPAPI_ListDependabotAlerts_ForbiddenIsEmpty confirms a 403
// (alerts disabled for the org / token lacks scope) yields no findings
// rather than failing the run.
func TestHTTPAPI_ListDependabotAlerts_ForbiddenIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Dependabot alerts are disabled", http.StatusForbidden)
	}))
	defer srv.Close()
	api := &httpAPI{org: "acme", token: "tok", base: srv.URL, client: srv.Client()}
	alerts, err := api.ListDependabotAlerts(context.Background())
	if err != nil {
		t.Fatalf("ListDependabotAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("want 0 alerts on 403; got %d", len(alerts))
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
	rp := repoPayload{Name: "r", DefaultBranch: "main", DefaultBranchProtected: true, RequiredReviewersCount: 1}
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
	fake := &fakeAPI{repos: []Repo{{Name: "r1", DefaultBranch: "main"}}}
	p := New(Options{API: fake, Org: "acme"})
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
