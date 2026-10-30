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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/endpoint"
	"github.com/sigcomply/sigcomply-cli/internal/log"
)

// DefaultAudience is the OIDC token audience the CLI requests when
// running in CI. It is an identifier, not a host: Rails checks it
// (Oidc::TokenValidator). Not configurable. It belongs to SigComply
// Cloud alone: an AWS role (or any other cloud) must never trust it,
// because SigComply Cloud receives every token minted for it
// (AGENTS.md, "OIDC audiences"); AWS uses sts.amazonaws.com.
const DefaultAudience = "https://api.sigcomply.com"

// Path is the cloud endpoint relative to base_url.
const Path = "/api/v1/runs"

// ProjectHeader carries cloud.project_id. SigComply Cloud accepts a run
// only when this ID and the OIDC token's repository claims name the same
// project. The header keeps the ID out of the counts-only payload.
const ProjectHeader = "X-SigComply-Project"

// GitLabIDTokenEnv is the variable a GitLab job's `id_tokens:` block
// must name for the CLI to find its OIDC token. It is the only one read:
// a generic name such as ID_TOKEN often holds a token minted for another
// receiver. The init-ci GitLab template declares it, and a test in
// cmd/sigcomply checks the two agree.
const GitLabIDTokenEnv = "SIGCOMPLY_ID_TOKEN"

// awsWebIdentityTokenFileEnv names the file the AWS SDKs read a web
// identity token from.
const awsWebIdentityTokenFileEnv = "AWS_WEB_IDENTITY_TOKEN_FILE"

// Decision is the result of evaluating whether to submit.
type Decision int

// Decision values.
const (
	DecisionSubmit         Decision = iota
	DecisionSkip                    // no cloud URL, no CI, or user passed --no-cloud
	DecisionMissingToken            // explicit --cloud but OIDC unavailable
	DecisionMissingBaseURL          // explicit --cloud but no cloud.base_url / --cloud-url configured
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
	// ProjectID (cloud.project_id) is sent in the ProjectHeader header;
	// empty omits the header.
	ProjectID string
}

// TokenProvider returns an OIDC token suitable for cloud authentication.
// The returned providerName drives the X-OIDC-Provider header.
type TokenProvider interface {
	Token(ctx context.Context, audience string) (token, providerName string, err error)
}

// Decide encapsulates the policy described in 06-aggregation.md
// §Decision matrix. The orchestrator calls Decide first to choose
// whether to call Submit and to surface the right diagnostic.
func Decide(opts *Options, hasOIDC, inCI bool) Decision {
	if opts.Disable {
		return DecisionSkip
	}
	// When the operator explicitly asked to submit (--cloud), a missing
	// base_url is a mistake worth surfacing, not a silent no-op. Check it
	// before the general empty-URL skip so the caller can warn.
	if opts.Force {
		if opts.BaseURL == "" {
			return DecisionMissingBaseURL
		}
		if !hasOIDC {
			return DecisionMissingToken
		}
		return DecisionSubmit
	}
	if opts.BaseURL == "" {
		return DecisionSkip
	}
	if !inCI || !hasOIDC {
		return DecisionSkip
	}
	return DecisionSubmit
}

// Submit POSTs the payload to {BaseURL}{Path}. Failures are returned
// as errors so the caller can log them; the caller is responsible for
// the "submission failures are non-fatal" policy.
func Submit(ctx context.Context, opts *Options, payload *core.SubmissionPayload) (Response, error) {
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
	if err := ValidateBaseURL(opts.BaseURL); err != nil {
		return Response{}, err
	}
	tokenProvider := opts.TokenProvider
	if tokenProvider == nil {
		tokenProvider = DefaultTokenProvider()
	}
	token, providerName, err := tokenProvider.Token(ctx, DefaultAudience)
	if err != nil {
		return Response{}, fmt.Errorf("submitter: acquire oidc token: %w", err)
	}
	// GitLab tokens are minted by the job's id_tokens block, not on
	// request, so the CLI cannot choose their audience. A token minted for
	// another receiver is a credential for that receiver; never forward it.
	if err := requireAudience(token, DefaultAudience); err != nil {
		return Response{}, fmt.Errorf("submitter: %s OIDC token: %w", providerName, err)
	}
	url := strings.TrimRight(opts.BaseURL, "/") + Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("submitter: new request: %w", err)
	}
	setHeaders(req.Header, opts, token, providerName)
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect: Go turns a POST into a GET on 301/302 and
	// forwards the Authorization header, so the bearer token would go to
	// the redirect target and no payload would arrive. Copying the client
	// keeps a caller's transport and timeout.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &noRedirect
	resp, err := client.Do(req) //nolint:gosec // #nosec G107 -- url is from project config (cfg.cloud.base_url), not user input; vetted at config-load time
	if err != nil {
		return Response{}, fmt.Errorf("submitter: post %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort cleanup
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if readErr != nil {
		return Response{StatusCode: resp.StatusCode}, fmt.Errorf("submitter: read response body: %w", readErr)
	}
	out := Response{StatusCode: resp.StatusCode, Body: respBody}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return out, fmt.Errorf("submitter: %s answered %d with a redirect to %q; nothing was submitted. "+
			"Set cloud.base_url to the final https URL", url, resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("submitter: %s returned %d: %s", url, resp.StatusCode, bodyExcerpt(respBody))
	}
	return out, nil
}

// setHeaders sets the request headers SigComply Cloud reads. The
// optional ones are omitted rather than sent empty.
func setHeaders(h http.Header, opts *Options, token, providerName string) {
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer "+token)
	h.Set("X-OIDC-Provider", providerName)
	if opts.CLIVersion != "" {
		h.Set("X-Sigcomply-CLI-Version", opts.CLIVersion)
	}
	if opts.ProjectID != "" {
		h.Set(ProjectHeader, opts.ProjectID)
	}
}

// ValidateBaseURL applies endpoint.ValidateHTTPS to the cloud base URL:
// https, or http to localhost only, so the OIDC bearer token never
// crosses the network in cleartext.
func ValidateBaseURL(raw string) error {
	return endpoint.ValidateHTTPS("cloud base URL", raw)
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
	if os.Getenv(GitLabIDTokenEnv) != "" {
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
	// A provider that found its environment but failed (GitHub refusing
	// the audience, say) carries the error worth reporting; a later
	// provider that is simply absent must not replace it with ErrNoToken.
	for _, p := range c.providers {
		t, name, e := p.Token(ctx, audience)
		if e == nil {
			return t, name, nil
		}
		if err == nil || (errors.Is(err, ErrNoToken) && !errors.Is(e, ErrNoToken)) {
			err = e
		}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil) // #nosec G104 G107 G704 -- tokenURL is from ACTIONS_ID_TOKEN_REQUEST_URL, provided by the GitHub Actions runner — not user input
	if err != nil {
		return "", "", fmt.Errorf("github actions: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	client := p.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req) // #nosec G104 G107 G704 -- tokenURL is provided by the GitHub Actions runner via ACTIONS_ID_TOKEN_REQUEST_URL — not user input
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
// resulting JWT lands in SIGCOMPLY_ID_TOKEN. Submit checks its audience.
type gitlabCIProvider struct{}

func (p *gitlabCIProvider) Token(_ context.Context, _ string) (token, providerName string, err error) {
	if t := os.Getenv(GitLabIDTokenEnv); t != "" {
		return t, providerGitLab, nil
	}
	return "", "", ErrNoToken
}

// tokenAudiences reads the `aud` claim of a JWT without verifying its
// signature. The CLI only routes the token; SigComply Cloud verifies it.
func tokenAudiences(token string) ([]string, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, errors.New("JWT payload is not base64url")
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, errors.New("JWT payload is not JSON")
	}
	if len(claims.Aud) == 0 {
		return nil, nil
	}
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(claims.Aud, &many); err != nil {
		return nil, errors.New("JWT aud claim is neither a string nor a list")
	}
	return many, nil
}

// requireAudience fails unless the token's aud claim contains want. The
// error never includes the token.
func requireAudience(token, want string) error {
	auds, err := tokenAudiences(token)
	if err != nil {
		return fmt.Errorf("cannot read its audience (%v); refusing to send it", err)
	}
	if !slices.Contains(auds, want) {
		return fmt.Errorf("audience %q does not include %q; refusing to send a token minted for another receiver. "+
			"On GitLab, set `aud: %s` on the %s entry under id_tokens", auds, want, want, GitLabIDTokenEnv)
	}
	return nil
}

// AWSWebIdentityAudienceWarning returns a warning when the token file
// the AWS SDK reads (AWS_WEB_IDENTITY_TOKEN_FILE) holds a token minted
// for SigComply Cloud. An AWS role that accepts that audience trusts a
// token SigComply Cloud receives on every submission. It returns "" when
// the variable is unset, the file is unreadable or not a JWT, or the
// audience is another one: the AWS SDK reports those itself.
func AWSWebIdentityAudienceWarning() string {
	path := os.Getenv(awsWebIdentityTokenFileEnv)
	if path == "" {
		return ""
	}
	body, err := os.ReadFile(path) //nolint:gosec // #nosec G304 G703 -- path is the AWS SDK's own token file variable
	if err != nil {
		return ""
	}
	auds, err := tokenAudiences(string(body))
	if err != nil || !slices.Contains(auds, DefaultAudience) {
		return ""
	}
	return fmt.Sprintf("%s holds a token with the SigComply Cloud audience %s. "+
		"Mint the AWS token with the audience sts.amazonaws.com and make the IAM role trust only that audience: "+
		"a role that trusts %s accepts tokens SigComply Cloud receives", awsWebIdentityTokenFileEnv, DefaultAudience, DefaultAudience)
}

const (
	providerGitHub = "github"
	providerGitLab = "gitlab"
)

// LegacyIDTokenWarning returns a warning when a GitLab job sets
// ID_TOKEN but not SIGCOMPLY_ID_TOKEN: the CLI used to read ID_TOKEN, so
// such a job submitted before and now skips without a word.
func LegacyIDTokenWarning() string {
	if os.Getenv("GITLAB_CI") == "" || os.Getenv("ID_TOKEN") == "" || os.Getenv(GitLabIDTokenEnv) != "" {
		return ""
	}
	return "ID_TOKEN is set but " + GitLabIDTokenEnv + " is not; the CLI reads only " + GitLabIDTokenEnv +
		", so this run cannot submit to SigComply Cloud. Rename the id_tokens entry to " + GitLabIDTokenEnv
}

// maxResponseBody caps what Submit reads from cloud.base_url: a run answer is
// a small JSON object, and the host is whatever the config names.
const maxResponseBody = 1 << 20

// bodyExcerpt is the part of an error response that goes into the error
// `check` prints: its first 512 bytes, with newlines, control characters and
// workflow-command prefixes neutralized, since the host is untrusted.
func bodyExcerpt(body []byte) string {
	const limit = 512
	if len(body) > limit {
		return log.Sanitize(string(body[:limit])) + "…"
	}
	return log.Sanitize(string(body))
}
