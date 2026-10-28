package cmd

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

// githubCassette is the GitHub source's committed L2 cassette, recorded
// against a real org and scrubbed. The binary E2E test serves it over
// HTTP so the real source plugin runs inside the real binary.
const githubCassette = "../../internal/sources/github/testdata/cassettes/org_collect"

// githubCassetteOrg is the org the cassette was scrubbed to; the
// project config must name it so the plugin builds matching URLs.
const githubCassetteOrg = "e2e-test-org"

// fakeGitHub replays a go-vcr cassette as an HTTP server. A request is
// matched on method, path and query (order-insensitive). The cassette
// records the repository and member endpoints only; ghSupplement answers
// the org-level and per-repo list endpoints it lacks. Anything else gets
// a 404 and lands in unmatched, which the test requires to be empty: a
// new endpoint the plugin starts calling must be added on purpose.
type fakeGitHub struct {
	srv *httptest.Server

	mu        sync.Mutex
	unmatched []string
	auth      map[string]bool
}

// ghSupplement answers what the cassette did not record, with the
// smallest body the plugin's decoder accepts. The org enforces no 2FA
// and grants read by default; the lists are empty (no open Dependabot
// alerts, no merged pull requests, no deployments in the period).
func ghSupplement(path string) (string, bool) {
	org := "/orgs/" + githubCassetteOrg
	repo := regexp.MustCompile(`^/repos/` + githubCassetteOrg + `/[^/]+/(pulls|deployments)$`)
	switch {
	case path == org:
		return `{"login":"` + githubCassetteOrg + `","two_factor_requirement_enabled":false,"default_repository_permission":"read",` +
			`"members_can_create_public_repositories":false,"web_commit_signoff_required":false,` +
			`"advanced_security_enabled_for_new_repositories":false,"secret_scanning_enabled_for_new_repositories":false,` +
			`"dependabot_alerts_enabled_for_new_repositories":false}`, true
	case path == org+"/dependabot/alerts", repo.MatchString(path):
		return `[]`, true
	}
	return "", false
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	c, err := cassette.Load(githubCassette)
	if err != nil {
		t.Fatalf("load cassette: %v", err)
	}
	type reply struct {
		code    int
		headers http.Header
		body    string
	}
	replies := map[string]reply{}
	for _, in := range c.Interactions {
		u, err := url.Parse(in.Request.URL)
		if err != nil {
			t.Fatalf("cassette URL %q: %v", in.Request.URL, err)
		}
		replies[ghRequestKey(in.Request.Method, u)] = reply{in.Response.Code, in.Response.Headers, in.Response.Body}
	}
	fg := &fakeGitHub{auth: map[string]bool{}}
	fg.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ghRequestKey(r.Method, r.URL)
		rep, ok := replies[key]
		if !ok && r.Method == http.MethodGet {
			if body, found := ghSupplement(r.URL.Path); found {
				rep, ok = reply{code: http.StatusOK, headers: http.Header{"Content-Type": {"application/json"}}, body: body}, true
			}
		}
		fg.mu.Lock()
		fg.auth[r.Header.Get("Authorization")] = true
		if !ok {
			fg.unmatched = append(fg.unmatched, key)
		}
		fg.mu.Unlock()
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`)) //nolint:errcheck // test server
			return
		}
		for k, vs := range rep.headers {
			// Recorded transport headers describe the original
			// connection, not this one.
			if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Encoding") {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rep.code)
		_, _ = w.Write([]byte(rep.body)) //nolint:errcheck // test server
	}))
	t.Cleanup(fg.srv.Close)
	return fg
}

// ghRequestKey normalises a request to "METHOD path?sorted-query".
func ghRequestKey(method string, u *url.URL) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return method + " " + u.Path + "?" + strings.Join(parts, "&")
}

// checkRequests fails when the plugin called an endpoint the fake does
// not answer, or sent any Authorization other than the env's token.
func (fg *fakeGitHub) checkRequests(t *testing.T, token string) {
	t.Helper()
	fg.mu.Lock()
	defer fg.mu.Unlock()
	if len(fg.unmatched) > 0 {
		t.Errorf("the plugin called endpoints neither the cassette nor ghSupplement answers: %v", fg.unmatched)
	}
	if len(fg.auth) != 1 || !fg.auth["Bearer "+token] {
		t.Errorf("Authorization headers sent = %v; want only the GITHUB_TOKEN value", fg.auth)
	}
}

// TestBinaryE2E_Check_GitHubSourceFromCassette runs an automated source
// inside the binary: the real GitHub plugin, configured with base_url,
// reads the committed cassette from a local server next to the manual
// source. Every policy's outcome is pinned, so a change in the plugin,
// a schema or a GitHub policy that moves a verdict fails here.
func TestBinaryE2E_Check_GitHubSourceFromCassette(t *testing.T) {
	const token = "dummy-token"
	fg := newFakeGitHub(t)
	p := newE2EProjectFor(t, defaultFW,
		"  github:\n    org: "+githubCassetteOrg+"\n    base_url: "+fg.srv.URL+"\n")
	seedAllManualEvidence(t, p)

	res := runSigcomply(t, p.dir, []string{"GITHUB_TOKEN=" + token}, "check", "--no-cloud")
	// The cassette's org has an unprotected repo and a member without
	// 2FA: GitHub policies fail, and nothing errors.
	res.wantCode(t, 1)
	fg.checkRequests(t, token)
	runDir := singleRunDir(t, p.vault, defaultFW)
	assertOutcomesGolden(t, runDir, "soc2_github_cassette")
	assertVaultSigned(t, runDir)

	// --pr runs the on_push subset against the same org.
	pr := runSigcomply(t, p.dir, []string{"GITHUB_TOKEN=" + token}, "check", "--pr", "--no-cloud")
	pr.wantCode(t, 1)
	if c := parseRunCounts(t, pr.stdout); c.fail == 0 || c.errored != 0 {
		t.Errorf("--pr against the cassette org: %+v; want on_push failures and no errors", c)
	}
	fg.checkRequests(t, token)
}
