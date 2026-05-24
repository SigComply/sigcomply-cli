// Package submitter is L8 of the SigComply CLI: optional cloud
// submission. Acquires an OIDC token from the CI provider (GitHub
// Actions or GitLab CI) and POSTs the core.SubmissionPayload — and
// only the SubmissionPayload — to {cloud_base_url}/api/v1/runs.
// Submission failures are logged, never fatal.
//
// See docs/architecture/02-layers.md §L8 and 06-aggregation.md.
package submitter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// DefaultAudience is the OIDC token audience the CLI requests when
// running in CI. Self-hosted deployments override via the
// OIDC.Audience field.
const DefaultAudience = "https://api.sigcomply.com"

// Path is the cloud endpoint relative to base_url.
const Path = "/api/v1/runs"

// Decision is the result of evaluating whether to submit.
type Decision int

// Decision values.
const (
	DecisionSubmit       Decision = iota
	DecisionSkip                  // no cloud URL, no CI, or user passed --no-cloud
	DecisionMissingToken          // explicit --cloud but OIDC unavailable
)

// Options control whether and where to submit.
type Options struct {
	BaseURL string // e.g. "https://api.sigcomply.com" — empty disables submission.
	Force   bool   // true if --cloud was passed; require submission.
	Disable bool   // true if --no-cloud was passed; never submit.
	// HTTPClient is injected by tests; nil defaults to a 30s-timeout
	// http.Client.
	HTTPClient *http.Client
	// TokenProvider is injected by tests; nil uses the auto-detected
	// CI providers (GitHub Actions, GitLab CI).
	TokenProvider TokenProvider
	// CLIVersion is stamped in the X-Sigcomply-CLI-Version header.
	CLIVersion string
}

// TokenProvider returns an OIDC token suitable for cloud authentication.
// The returned providerName drives the X-OIDC-Provider header.
type TokenProvider interface {
	Token(ctx context.Context, audience string) (token, providerName string, err error)
}

// Decide encapsulates the policy described in 06-aggregation.md
// §Decision matrix. The orchestrator calls Decide first to choose
// whether to call Submit and to surface the right diagnostic.
func Decide(opts Options, hasOIDC, inCI bool) Decision {
	if opts.Disable {
		return DecisionSkip
	}
	if opts.BaseURL == "" {
		return DecisionSkip
	}
	if opts.Force {
		if !hasOIDC {
			return DecisionMissingToken
		}
		return DecisionSubmit
	}
	if !inCI || !hasOIDC {
		return DecisionSkip
	}
	return DecisionSubmit
}

// Submit POSTs the payload to {BaseURL}{Path}. Failures are returned
// as errors so the caller can log them; the caller is responsible for
// the "submission failures are non-fatal" policy.
func Submit(ctx context.Context, opts Options, payload *core.SubmissionPayload) (Response, error) {
	if opts.BaseURL == "" {
		return Response{}, fmt.Errorf("submitter: BaseURL empty")
	}
	if payload == nil {
		return Response{}, fmt.Errorf("submitter: nil payload")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("submitter: marshal payload: %w", err)
	}
	tokenProvider := opts.TokenProvider
	if tokenProvider == nil {
		tokenProvider = DefaultTokenProvider()
	}
	token, providerName, err := tokenProvider.Token(ctx, DefaultAudience)
	if err != nil {
		return Response{}, fmt.Errorf("submitter: acquire oidc token: %w", err)
	}
	url := strings.TrimRight(opts.BaseURL, "/") + Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("submitter: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OIDC-Provider", providerName)
	if opts.CLIVersion != "" {
		req.Header.Set("X-Sigcomply-CLI-Version", opts.CLIVersion)
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req) //nolint:gosec // url is from project config (cfg.cloud.base_url), not user input; vetted at config-load time
	if err != nil {
		return Response{}, fmt.Errorf("submitter: post %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort cleanup
	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return Response{StatusCode: resp.StatusCode}, fmt.Errorf("submitter: read response body: %w", readErr)
	}
	out := Response{StatusCode: resp.StatusCode, Body: respBody}
	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("submitter: %s returned %d: %s", url, resp.StatusCode, string(respBody))
	}
	return out, nil
}

// Response is the parsed cloud response.
type Response struct {
	StatusCode int
	Body       []byte
}

// DefaultTokenProvider returns a TokenProvider that tries GitHub
// Actions then GitLab CI, returning ErrNoToken if neither is
// available.
func DefaultTokenProvider() TokenProvider {
	return &chainProvider{
		providers: []TokenProvider{
			&githubActionsProvider{httpClient: &http.Client{Timeout: 10 * time.Second}},
			&gitlabCIProvider{},
		},
	}
}

// HasOIDC reports whether any provider in the default chain can
// produce a token. The orchestrator uses this before calling Submit
// so the decision matrix can be evaluated upfront.
func HasOIDC() bool {
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "" {
		return true
	}
	if os.Getenv("SIGCOMPLY_ID_TOKEN") != "" || os.Getenv("ID_TOKEN") != "" {
		return true
	}
	return false
}

// InCI reports whether the current process is running in any
// recognized CI environment.
func InCI() bool {
	return os.Getenv("CI") != "" ||
		os.Getenv("GITHUB_ACTIONS") != "" ||
		os.Getenv("GITLAB_CI") != ""
}

// ErrNoToken is returned by providers when no token source is
// available in the environment.
var ErrNoToken = fmt.Errorf("submitter: no OIDC token source detected")

type chainProvider struct {
	providers []TokenProvider
}

func (c *chainProvider) Token(ctx context.Context, audience string) (token, providerName string, err error) {
	for _, p := range c.providers {
		t, name, e := p.Token(ctx, audience)
		if e == nil {
			return t, name, nil
		}
		err = e
	}
	if err == nil {
		err = ErrNoToken
	}
	return "", "", err
}

// githubActionsProvider mints an OIDC token via the GitHub Actions
// workload-identity endpoint. The endpoint URL and bearer auth token
// are injected by Actions as ACTIONS_ID_TOKEN_REQUEST_URL and
// ACTIONS_ID_TOKEN_REQUEST_TOKEN respectively.
type githubActionsProvider struct {
	httpClient *http.Client
}

type ghActionsResponse struct {
	Value string `json:"value"`
}

//nolint:gocritic // signature matches TokenProvider; named returns add noise here
func (p *githubActionsProvider) Token(ctx context.Context, audience string) (string, string, error) {
	tokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if tokenURL == "" || bearer == "" {
		return "", "", ErrNoToken
	}
	if audience != "" {
		joiner := "?"
		if strings.Contains(tokenURL, "?") {
			joiner = "&"
		}
		tokenURL = tokenURL + joiner + "audience=" + audience
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil) //nolint:gosec // tokenURL is from ACTIONS_ID_TOKEN_REQUEST_URL, provided by the GitHub Actions runner — not user input
	if err != nil {
		return "", "", fmt.Errorf("github actions: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	client := p.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req) //nolint:gosec // tokenURL is provided by the GitHub Actions runner via ACTIONS_ID_TOKEN_REQUEST_URL — not user input
	if err != nil {
		return "", "", fmt.Errorf("github actions: get oidc token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", "", fmt.Errorf("github actions: oidc endpoint returned %d (and response body read failed: %w)", resp.StatusCode, readErr)
		}
		return "", "", fmt.Errorf("github actions: oidc endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	var out ghActionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("github actions: decode oidc response: %w", err)
	}
	if out.Value == "" {
		return "", "", fmt.Errorf("github actions: empty token in oidc response")
	}
	return out.Value, providerGitHub, nil
}

// gitlabCIProvider reads a pre-minted JWT from the environment. GitLab
// CI workflows configure `id_tokens:` in `.gitlab-ci.yml` and the
// resulting JWT lands in an env var the customer names — by default
// SIGCOMPLY_ID_TOKEN, falling back to ID_TOKEN.
type gitlabCIProvider struct{}

func (p *gitlabCIProvider) Token(_ context.Context, _ string) (token, providerName string, err error) {
	if t := os.Getenv("SIGCOMPLY_ID_TOKEN"); t != "" {
		return t, providerGitLab, nil
	}
	if t := os.Getenv("ID_TOKEN"); t != "" {
		return t, providerGitLab, nil
	}
	return "", "", ErrNoToken
}

const (
	providerGitHub = "github"
	providerGitLab = "gitlab"
)
