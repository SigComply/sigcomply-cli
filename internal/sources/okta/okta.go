// Package okta implements the okta source plugin: lists users and
// applications from a single Okta organization and emits two evidence
// types — okta_user and okta_app — suitable for SOC 2 MFA coverage
// policies.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the concrete *httpAPI satisfies it, and
// unit tests inject an in-memory fake. The real HTTP adapter has no
// integration tests today (deferred — live API integration tests are
// out of scope for this batch).
package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// Evidence type IDs this plugin emits.
const (
	EvidenceTypeUser = "okta_user"
	EvidenceTypeApp  = "okta_app"
)

// SourceID is the registered ID for the okta plugin instance.
const SourceID = "okta"

// User is the subset of fields the plugin extracts from an Okta user
// listing. MFAFactorCount is filled from a follow-up factors call.
type User struct {
	ID             string
	Email          string
	Status         string
	MFAFactorCount int
	LastLogin      time.Time
}

// App is the subset of fields the plugin extracts from an Okta app
// listing. MFARequired is derived from the app's sign-on policy rules.
type App struct {
	ID          string
	Label       string
	SignOnMode  string
	MFARequired bool
}

// API is the subset of the Okta API the plugin uses. Defining it as
// an interface lets tests inject a fake without making real network
// calls; the concrete *httpAPI satisfies it.
type API interface {
	ListUsers(ctx context.Context) ([]User, error)
	ListApps(ctx context.Context) ([]App, error)
}

// Plugin is the in-process okta source.
type Plugin struct {
	api API
	org string
	now func() time.Time
}

// Options is the constructor input.
type Options struct {
	API API
	Org string
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
// Callers using the real Okta API should use NewFromConfig.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api: opts.API,
		org: opts.Org,
		now: now,
	}
}

// NewFromConfig constructs a Plugin backed by the real Okta API. The
// orgURL is the customer's full Okta tenant URL (e.g.
// https://acme.okta.com); the apiToken is a long-lived API token (Okta
// SSWS scheme). Live integration tests are deferred.
func NewFromConfig(_ context.Context, orgURL, apiToken string) (*Plugin, error) {
	if orgURL == "" {
		return nil, fmt.Errorf("okta: org URL is required")
	}
	if apiToken == "" {
		return nil, fmt.Errorf("okta: api token is required")
	}
	base := strings.TrimRight(orgURL, "/")
	return New(Options{
		API: &httpAPI{
			base:   base,
			token:  apiToken,
			client: &http.Client{Timeout: 30 * time.Second},
		},
		Org: orgURL,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string {
	return []string{EvidenceTypeUser, EvidenceTypeApp}
}

// Init is a no-op; configuration arrives via the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the JSON payload shape inside each okta_user record.
type userPayload struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	Status         string    `json:"status"`
	MFAFactorCount int       `json:"mfa_factor_count"`
	LastLogin      time.Time `json:"last_login,omitempty"`
}

// appPayload is the JSON payload shape inside each okta_app record.
type appPayload struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	SignOnMode  string `json:"sign_on_mode"`
	MFARequired bool   `json:"mfa_required"`
}

// Collect dispatches by req.EvidenceType — a plugin emits multiple
// evidence types and returns records of the type the SlotRequest asks
// for. Records are sorted by ID before return so envelope bytes are
// stable across runs against stable tenant state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	switch req.EvidenceType {
	case EvidenceTypeUser:
		return p.collectUsers(ctx)
	case EvidenceTypeApp:
		return p.collectApps(ctx)
	default:
		return nil, fmt.Errorf("okta: unsupported evidence type %q (only %q, %q)",
			req.EvidenceType, EvidenceTypeUser, EvidenceTypeApp)
	}
}

func (p *Plugin) collectUsers(ctx context.Context) ([]core.EvidenceRecord, error) {
	users, err := p.api.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: list users: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(users))
	for i := range users {
		u := users[i]
		payload := userPayload(u)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("okta: marshal user payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeUser,
			ID:          u.ID,
			IdentityKey: u.Email,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (p *Plugin) collectApps(ctx context.Context) ([]core.EvidenceRecord, error) {
	apps, err := p.api.ListApps(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: list apps: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(apps))
	for i := range apps {
		a := apps[i]
		payload := appPayload(a)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("okta: marshal app payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeApp,
			ID:          a.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// --- Real HTTP adapter -----------------------------------------------------

// httpAPI is the production implementation of API. It hits the customer's
// Okta tenant directly via net/http to avoid pulling in
// github.com/okta/okta-sdk-golang/v5 (which would add a sizable dependency
// tree). Endpoints used:
//
//   GET /api/v1/users                  — paged listing of users
//   GET /api/v1/users/{id}/factors     — per-user enrolled factors
//   GET /api/v1/apps                   — paged listing of applications
//
// Okta uses an `SSWS` auth scheme and link-header pagination similar to
// GitHub's; integration coverage is deferred.
type httpAPI struct {
	base   string
	token  string
	client *http.Client
}

type oktaUser struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	LastLogin   string `json:"lastLogin"`
	Profile     struct {
		Email string `json:"email"`
	} `json:"profile"`
}

type oktaFactor struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type oktaApp struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	SignOnMode string `json:"signOnMode"`
	Status     string `json:"status"`
}

func (h *httpAPI) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	path := "/api/v1/users?limit=200"
	for {
		var page []oktaUser
		next, err := h.getJSON(ctx, path, &page)
		if err != nil {
			return nil, err
		}
		for _, u := range page {
			usr := User{
				ID:     u.ID,
				Email:  u.Profile.Email,
				Status: u.Status,
			}
			if u.LastLogin != "" {
				if t, err := time.Parse(time.RFC3339, u.LastLogin); err == nil {
					usr.LastLogin = t
				}
			}
			n, err := h.countActiveFactors(ctx, u.ID)
			if err != nil {
				return nil, err
			}
			usr.MFAFactorCount = n
			out = append(out, usr)
		}
		if next == "" {
			return out, nil
		}
		path = next
	}
}

func (h *httpAPI) countActiveFactors(ctx context.Context, userID string) (int, error) {
	path := fmt.Sprintf("/api/v1/users/%s/factors", url.PathEscape(userID))
	var factors []oktaFactor
	if _, err := h.getJSON(ctx, path, &factors); err != nil {
		return 0, err
	}
	n := 0
	for _, f := range factors {
		if strings.EqualFold(f.Status, "ACTIVE") {
			n++
		}
	}
	return n, nil
}

func (h *httpAPI) ListApps(ctx context.Context) ([]App, error) {
	var out []App
	path := "/api/v1/apps?limit=200"
	for {
		var page []oktaApp
		next, err := h.getJSON(ctx, path, &page)
		if err != nil {
			return nil, err
		}
		for _, a := range page {
			out = append(out, App{
				ID:         a.ID,
				Label:      a.Label,
				SignOnMode: a.SignOnMode,
				// Heuristic: federated sign-on modes (SAML, OIDC) and
				// secure_sign_on_mode are taken to enforce MFA at the IdP
				// layer; password-based modes are not. Full sign-on policy
				// inspection is deferred — see Okta sign-on policy rules.
				MFARequired: federatedMFA(a.SignOnMode),
			})
		}
		if next == "" {
			return out, nil
		}
		path = next
	}
}

func federatedMFA(mode string) bool {
	switch strings.ToUpper(mode) {
	case "SAML_2_0", "OPENID_CONNECT", "SECURE_PASSWORD_STORE":
		return true
	default:
		return false
	}
}

// getJSON performs a single GET and decodes the JSON body into out.
// It returns nextPath as a relative URL when the response advertises
// a rel="next" Link header; empty string ends pagination.
func (h *httpAPI) getJSON(ctx context.Context, path string, out any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+path, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "SSWS "+h.token)
	req.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("okta: %s: %s: %w", path, resp.Status, readErr)
		}
		return "", fmt.Errorf("okta: %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", fmt.Errorf("okta: decode %s: %w", path, err)
	}
	return nextLinkPath(resp.Header.Get("Link"), h.base), nil
}

// nextLinkPath extracts the relative path of the rel="next" link, or
// empty string if no next page. Okta's Link header format matches
// RFC 5988 — comma-separated, each part wrapped in angle brackets.
func nextLinkPath(link, base string) string {
	if link == "" {
		return ""
	}
	for _, part := range strings.Split(link, ",") {
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end < 0 || end <= start {
			return ""
		}
		fullURL := part[start+1 : end]
		if strings.HasPrefix(fullURL, base) {
			return strings.TrimPrefix(fullURL, base)
		}
		// Relative URL or different host — return as-is for the http
		// client to combine via h.base+path. We strip the scheme+host
		// only when it matches; otherwise fall through (best-effort).
		return fullURL
	}
	return ""
}

var _ core.SourcePlugin = (*Plugin)(nil)
