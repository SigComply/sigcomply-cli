package submitter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type stubProvider struct {
	token, provider string
	err             error
}

func (s *stubProvider) Token(_ context.Context, _ string) (token, providerName string, err error) {
	if s.err != nil {
		return "", "", s.err
	}
	return s.token, s.provider, nil
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name          string
		opts          Options
		hasOIDC, inCI bool
		wantDecision  Decision
	}{
		{"disable", Options{Disable: true, BaseURL: "https://x"}, true, true, DecisionSkip},
		{"no-url", Options{}, true, true, DecisionSkip},
		{"force-ok", Options{Force: true, BaseURL: "https://x"}, true, false, DecisionSubmit},
		{"force-no-token", Options{Force: true, BaseURL: "https://x"}, false, false, DecisionMissingToken},
		{"force-no-baseurl", Options{Force: true}, true, true, DecisionMissingBaseURL},
		{"default-ci-with-token", Options{BaseURL: "https://x"}, true, true, DecisionSubmit},
		{"default-ci-no-token", Options{BaseURL: "https://x"}, false, true, DecisionSkip},
		{"default-local", Options{BaseURL: "https://x"}, true, false, DecisionSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Decide(c.opts, c.hasOIDC, c.inCI); got != c.wantDecision {
				t.Errorf("Decide = %v; want %v", got, c.wantDecision)
			}
		})
	}
}

func TestSubmit_RequiresBaseURL(t *testing.T) {
	_, err := Submit(context.Background(), Options{}, &core.SubmissionPayload{})
	if err == nil {
		t.Fatal("want error on empty BaseURL")
	}
}

func TestSubmit_PostsPayloadWithHeaders(t *testing.T) {
	var (
		gotPath    string
		gotMethod  string
		gotAuth    string
		gotOIDCHdr string
		gotCLIHdr  string
		gotBody    []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotOIDCHdr = r.Header.Get("X-OIDC-Provider")
		gotCLIHdr = r.Header.Get("X-Sigcomply-CLI-Version")
		gotBody, _ = io.ReadAll(r.Body) //nolint:errcheck // test handler; body content covered by later assertions
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"accepted":true}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	payload := &core.SubmissionPayload{Schema: "sigcomply.cloud.v1", RunID: "r1", Framework: "soc2"}
	resp, err := Submit(context.Background(), Options{
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
		TokenProvider: &stubProvider{token: "jwt-x", provider: "github"},
		CLIVersion:    "1.0.0",
	}, payload)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if gotPath != Path {
		t.Errorf("path = %q; want %q", gotPath, Path)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q", gotMethod)
	}
	if gotAuth != "Bearer jwt-x" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if gotOIDCHdr != "github" {
		t.Errorf("oidc provider header = %q", gotOIDCHdr)
	}
	if gotCLIHdr != "1.0.0" {
		t.Errorf("cli version header = %q", gotCLIHdr)
	}
	var decoded core.SubmissionPayload
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.RunID != "r1" {
		t.Errorf("body run id = %q", decoded.RunID)
	}
}

func TestSubmit_TokenProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err := Submit(context.Background(), Options{
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
		TokenProvider: &stubProvider{err: ErrNoToken},
	}, &core.SubmissionPayload{})
	if err == nil || !strings.Contains(err.Error(), "oidc") {
		t.Errorf("want oidc error; got %v", err)
	}
}

func TestSubmit_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("nope")) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	_, err := Submit(context.Background(), Options{
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
		TokenProvider: &stubProvider{token: "x", provider: "github"},
	}, &core.SubmissionPayload{})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want 5xx error; got %v", err)
	}
}

func TestGitHubActionsProvider_FetchesTokenFromIDP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("bad bearer: %q", got)
		}
		if got := r.URL.Query().Get("audience"); got != "https://api.sigcomply.com" {
			t.Errorf("bad audience: %q", got)
		}
		_ = json.NewEncoder(w).Encode(ghActionsResponse{Value: "minted-jwt"}) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "secret")
	p := &githubActionsProvider{httpClient: srv.Client()}
	tok, name, err := p.Token(context.Background(), "https://api.sigcomply.com")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "minted-jwt" || name != "github" {
		t.Errorf("got token=%q provider=%q", tok, name)
	}
}

func TestGitHubActionsProvider_NoEnvIsNoToken(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	p := &githubActionsProvider{}
	_, _, err := p.Token(context.Background(), "")
	if err == nil {
		t.Fatal("want ErrNoToken")
	}
}

func TestGitHubActionsProvider_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied")) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x")
	p := &githubActionsProvider{httpClient: srv.Client()}
	_, _, err := p.Token(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("want 403; got %v", err)
	}
}

func TestGitLabCIProvider_ReadsSigComplyVarFirst(t *testing.T) {
	t.Setenv("SIGCOMPLY_ID_TOKEN", "first")
	t.Setenv("ID_TOKEN", "fallback")
	p := &gitlabCIProvider{}
	tok, name, err := p.Token(context.Background(), "")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "first" || name != "gitlab" {
		t.Errorf("got token=%q provider=%q", tok, name)
	}
}

func TestGitLabCIProvider_FallsBackToIDTOKEN(t *testing.T) {
	t.Setenv("SIGCOMPLY_ID_TOKEN", "")
	t.Setenv("ID_TOKEN", "fallback")
	p := &gitlabCIProvider{}
	tok, _, err := p.Token(context.Background(), "")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "fallback" {
		t.Errorf("got token=%q", tok)
	}
}

func TestGitLabCIProvider_NoEnv(t *testing.T) {
	t.Setenv("SIGCOMPLY_ID_TOKEN", "")
	t.Setenv("ID_TOKEN", "")
	p := &gitlabCIProvider{}
	_, _, err := p.Token(context.Background(), "")
	if err == nil {
		t.Fatal("want ErrNoToken")
	}
}

func TestChainProvider_PicksFirstSuccess(t *testing.T) {
	c := &chainProvider{
		providers: []TokenProvider{
			&stubProvider{err: ErrNoToken},
			&stubProvider{token: "second", provider: "gitlab"},
		},
	}
	tok, name, err := c.Token(context.Background(), "")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "second" || name != "gitlab" {
		t.Errorf("got tok=%q name=%q", tok, name)
	}
}

func TestChainProvider_AllFailReturnsLastError(t *testing.T) {
	c := &chainProvider{
		providers: []TokenProvider{
			&stubProvider{err: ErrNoToken},
			&stubProvider{err: ErrNoToken},
		},
	}
	_, _, err := c.Token(context.Background(), "")
	if err == nil {
		t.Fatal("want error")
	}
}

func TestHasOIDC(t *testing.T) {
	cases := []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"SIGCOMPLY_ID_TOKEN": "x"}, true},
		{map[string]string{"ID_TOKEN": "x"}, true},
		{map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "u", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"}, true},
		{map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "u"}, false},
	}
	for i, c := range cases {
		t.Run("", func(t *testing.T) {
			for _, k := range []string{"SIGCOMPLY_ID_TOKEN", "ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
				t.Setenv(k, "")
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := HasOIDC(); got != c.want {
				t.Errorf("case %d: HasOIDC = %v; want %v", i, got, c.want)
			}
		})
	}
}

func TestInCI(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	if InCI() {
		t.Errorf("InCI true with no env")
	}
	t.Setenv("CI", "true")
	if !InCI() {
		t.Errorf("InCI false with CI=true")
	}
}

func TestSubmit_NilPayload(t *testing.T) {
	_, err := Submit(context.Background(), Options{BaseURL: "https://x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "nil payload") {
		t.Errorf("want nil-payload error; got %v", err)
	}
}

func TestSubmit_NetworkFailure(t *testing.T) {
	// Point at a server that is immediately closed so the dial fails.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	_, err := Submit(context.Background(), Options{
		BaseURL:       url,
		HTTPClient:    &http.Client{},
		TokenProvider: &stubProvider{token: "x", provider: "github"},
	}, &core.SubmissionPayload{})
	if err == nil || !strings.Contains(err.Error(), "post ") {
		t.Errorf("want post/network error; got %v", err)
	}
}

func TestSubmit_TrimsTrailingSlashInBaseURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_, err := Submit(context.Background(), Options{
		BaseURL:       srv.URL + "/",
		HTTPClient:    srv.Client(),
		TokenProvider: &stubProvider{token: "x", provider: "github"},
	}, &core.SubmissionPayload{})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotPath != Path {
		t.Errorf("path = %q; want %q (trailing slash should be trimmed)", gotPath, Path)
	}
}

func TestSubmit_SuccessReturnsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"run-99"}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	resp, err := Submit(context.Background(), Options{
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
		TokenProvider: &stubProvider{token: "x", provider: "gitlab"},
	}, &core.SubmissionPayload{})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "run-99") {
		t.Errorf("body = %q; want it to carry the server response", resp.Body)
	}
}

// TestSubmit_NoCLIVersionHeaderWhenUnset confirms the optional header is
// omitted rather than sent empty.
func TestSubmit_NoCLIVersionHeaderWhenUnset(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Sigcomply-Cli-Version"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_, err := Submit(context.Background(), Options{
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
		TokenProvider: &stubProvider{token: "x", provider: "github"},
	}, &core.SubmissionPayload{})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if present {
		t.Error("X-Sigcomply-CLI-Version sent despite empty CLIVersion")
	}
}

// TestSubmit_BodyIsCountsOnly is the wire-level companion to the
// structural guard in core/cloud_test.go: it inspects the actual bytes
// on the wire and asserts that fields capable of carrying identity are
// absent. A regression that smuggled identifiers into the payload would
// surface here even if the Go type somehow allowed it.
func TestSubmit_BodyIsCountsOnly(t *testing.T) {
	var raw map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)  //nolint:errcheck // test handler
		_ = json.Unmarshal(body, &raw) //nolint:errcheck // asserted below
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	payload := &core.SubmissionPayload{
		Schema:    "sigcomply.cloud.v3",
		RunID:     "r1",
		Framework: "soc2",
		Summary:   core.RunSummary{PoliciesTotal: 2, PoliciesPassed: 1, PoliciesFailed: 1},
		Policies: []core.AggregatedPolicy{{
			PolicyID:           "soc2.cc6.1.mfa_enforced",
			Status:             core.StatusFail,
			ResourcesEvaluated: 10,
			ResourcesFailed:    3,
			Message:            "3 of 10 resources failed.",
		}},
	}
	_, err := Submit(context.Background(), Options{
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
		TokenProvider: &stubProvider{token: "x", provider: "github"},
	}, payload)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	for _, forbidden := range []string{"violations", "resources", "identifiers", "raw", "details", "arns", "emails"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("submitted payload carries forbidden top-level key %q", forbidden)
		}
	}
	// The body must carry the counts the dashboard needs.
	if _, ok := raw["summary"]; !ok {
		t.Error("payload missing summary counts")
	}
	if _, ok := raw["policies"]; !ok {
		t.Error("payload missing policies")
	}
}

func TestDefaultTokenProvider_ReturnsChain(t *testing.T) {
	p := DefaultTokenProvider()
	cp, ok := p.(*chainProvider)
	if !ok {
		t.Fatalf("DefaultTokenProvider returned %T; want *chainProvider", p)
	}
	if len(cp.providers) != 2 {
		t.Errorf("chain has %d providers; want 2 (github, gitlab)", len(cp.providers))
	}
}

func TestGitHubActionsProvider_AppendsAudienceToURLWithQuery(t *testing.T) {
	var gotAudience string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience = r.URL.Query().Get("audience")
		if r.URL.Query().Get("existing") != "1" {
			t.Errorf("pre-existing query param lost: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(ghActionsResponse{Value: "tok"}) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"?existing=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "secret")
	p := &githubActionsProvider{httpClient: srv.Client()}
	_, _, err := p.Token(context.Background(), "aud://x")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if gotAudience != "aud://x" {
		t.Errorf("audience = %q; want aud://x (appended with & joiner)", gotAudience)
	}
}

func TestGitHubActionsProvider_EmptyTokenInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ghActionsResponse{Value: ""}) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x")
	p := &githubActionsProvider{httpClient: srv.Client()}
	_, _, err := p.Token(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Errorf("want empty-token error; got %v", err)
	}
}

func TestGitHubActionsProvider_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json")) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x")
	p := &githubActionsProvider{httpClient: srv.Client()}
	_, _, err := p.Token(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("want decode error; got %v", err)
	}
}
