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
//
// EvidenceTypeDirectoryUser is the cross-vendor directory_user shape;
// Okta is one of several substitutable directory sources (AWS IAM,
// GitHub, future Azure AD/LDAP). EvidenceTypeApp is Okta-specific —
// SAML/OIDC app catalogs differ enough across vendors that no
// cross-vendor abstraction exists yet.
const (
	EvidenceTypeDirectoryUser = "directory_user"
	EvidenceTypeApp           = "okta_app"
)

// SourceID is the registered ID for the okta plugin instance.
const SourceID = "okta"

// User is the subset of fields the plugin extracts from an Okta user
// listing. MFAFactorCount is filled from a follow-up factors call;
// AdminRoles from a follow-up admin-role-assignments call.
type User struct {
	ID             string
	Email          string
	Status         string
	MFAFactorCount int
	LastLogin      time.Time
	// AdminRoles holds the `type` of each admin role assigned to the
	// user (e.g. SUPER_ADMIN, ORG_ADMIN, READ_ONLY_ADMIN). Okta's
	// /users/{id}/roles endpoint only ever returns admin-role grants, so
	// a non-empty slice means the user is an administrator. Empty/nil →
	// not an admin.
	AdminRoles []string
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
	return []string{EvidenceTypeDirectoryUser, EvidenceTypeApp}
}

// Init is a no-op; configuration arrives via the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the directory_user shape this plugin emits. Cross-
// vendor fields map to Okta concepts as follows:
//   - mfa_enabled: derived from MFAFactorCount > 0
//   - is_active:   derived from Status == "ACTIVE"
//   - is_admin:    derived from len(AdminRoles) > 0 (any Okta admin-role
//     assignment — SUPER_ADMIN, ORG_ADMIN, READ_ONLY_ADMIN, …)
//   - display_name: best-effort, falls back to email
//
// is_admin is mandatory for every directory_user emitter (WU-0.2,
// docs/architecture/12-multicloud-sources.md): the admin-MFA policies are
// phrased as none(is_admin AND no-MFA), and a missing is_admin surfaces as
// status=error (a coverage gap), not a vacuous pass. Populating it from
// admin-role assignments is what makes those policies fire for an
// Okta-only deployment.
//
// Known v1 limitation: AdminRoles is sourced from the per-user
// /users/{id}/roles endpoint, which by default returns *directly-assigned*
// admin roles. Admin privileges inherited via group-role assignments are
// not yet resolved (would require a group-first enumeration); a user who
// is admin *only* through a group could read as is_admin=false. Documented
// in docs/configuration.md; closing it is deferred to the testing revamp.
//
// is_service_account is still NOT populated (Okta has no first-class
// service-account flag on users; deferred).
type userPayload struct {
	ID             string    `json:"id"`
	DisplayName    string    `json:"display_name,omitempty"`
	Email          string    `json:"email,omitempty"`
	MFAEnabled     bool      `json:"mfa_enabled"`
	MFAFactorCount int       `json:"mfa_factor_count"`
	IsActive       bool      `json:"is_active"`
	IsAdmin        bool      `json:"is_admin"`
	LastLoginAt    time.Time `json:"last_login_at,omitempty"`
}

// appPayload is the JSON payload shape inside each okta_app record.
type appPayload struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	SignOnMode  string `json:"sign_on_mode"`
	MFARequired bool   `json:"mfa_required"`
}

// Collect returns records for every evidence type in req.AcceptedTypes
// that this plugin emits. A slot whose Accepts list includes both
// okta types gets records for both in a single call. Records are
// sorted by ID within each type group; the collector splits them by
// Type for envelope writing.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantUsers := req.Accepts(EvidenceTypeDirectoryUser)
	wantApps := req.Accepts(EvidenceTypeApp)
	if !wantUsers && !wantApps {
		return nil, fmt.Errorf("okta: AcceptedTypes %v does not include emitted types %q,%q",
			req.AcceptedTypes, EvidenceTypeDirectoryUser, EvidenceTypeApp)
	}
	var out []core.EvidenceRecord
	if wantUsers {
		rs, err := p.collectUsers(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if wantApps {
		rs, err := p.collectApps(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
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
		displayName := u.Email
		payload := userPayload{
			ID:             u.ID,
			DisplayName:    displayName,
			Email:          u.Email,
			MFAEnabled:     u.MFAFactorCount > 0,
			MFAFactorCount: u.MFAFactorCount,
			IsActive:       strings.EqualFold(u.Status, "ACTIVE"),
			IsAdmin:        len(u.AdminRoles) > 0,
			LastLoginAt:    u.LastLogin,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("okta: marshal user payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeDirectoryUser,
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
//	GET /api/v1/users                  — paged listing of users
//	GET /api/v1/users/{id}/factors     — per-user enrolled factors
//	GET /api/v1/users/{id}/roles       — per-user admin-role assignments
//	GET /api/v1/apps                   — paged listing of applications
//
// Okta uses an `SSWS` auth scheme and link-header pagination similar to
// GitHub's; integration coverage is deferred.
//
// Rate limits: the factors and roles calls are per-user (N+1 over the
// user list), drawing from the org-wide /api/v1/users/* bucket
// (~600 req/min on developer orgs, higher on production). v1 relies on
// the user listing's limit=200 paging and Okta's own 429 responses
// (surfaced as errors via getJSON) rather than proactive backoff; a
// budget-aware throttle is deferred to the testing revamp. Reading roles
// requires an admin token / okta.roles.read scope.
type httpAPI struct {
	base   string
	token  string
	client *http.Client
}

type oktaUser struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	LastLogin string `json:"lastLogin"`
	Profile   struct {
		Email string `json:"email"`
	} `json:"profile"`
}

type oktaFactor struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type oktaRole struct {
	ID   string `json:"id"`
	Type string `json:"type"`
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
			roles, err := h.listAdminRoles(ctx, u.ID)
			if err != nil {
				return nil, err
			}
			usr.AdminRoles = roles
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

// listAdminRoles returns the `type` of each admin role assigned to the
// user. Okta's /users/{id}/roles endpoint only returns admin-role grants,
// so any returned role makes the user an administrator. Returns nil when
// the user holds no admin roles. See the rate-limit / group-inheritance
// notes on httpAPI and userPayload.
func (h *httpAPI) listAdminRoles(ctx context.Context, userID string) ([]string, error) {
	path := fmt.Sprintf("/api/v1/users/%s/roles", url.PathEscape(userID))
	var roles []oktaRole
	if _, err := h.getJSON(ctx, path, &roles); err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, nil
	}
	types := make([]string, 0, len(roles))
	for _, r := range roles {
		types = append(types, r.Type)
	}
	return types, nil
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
