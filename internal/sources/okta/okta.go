// Package okta implements the okta source plugin: lists users and
// applications from a single Okta organization and emits three evidence
// types — directory_user and okta_app (SOC 2 MFA coverage policies) and
// roster_entry (Okta as the organization's authoritative workforce roster,
// including deprovisioned users).
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
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// Evidence type IDs this plugin emits.
//
// EvidenceTypeDirectoryUser is the cross-vendor directory_user shape;
// Okta is one of several substitutable directory sources (AWS IAM,
// GitHub, future Azure AD/LDAP). EvidenceTypeApp is Okta-specific —
// SAML/OIDC app catalogs differ enough across vendors that no
// cross-vendor abstraction exists yet. EvidenceTypeRosterEntry is the
// cross-vendor workforce-roster shape (one entry per person, with a
// normalized lifecycle status).
const (
	EvidenceTypeDirectoryUser  = "directory_user"
	EvidenceTypeApp            = "okta_app"
	EvidenceTypeRosterEntry    = "roster_entry"
	EvidenceTypePasswordPolicy = "password_policy.v2"
)

// Normalized roster_entry status values (the schema's closed enum).
const (
	rosterActive   = "active"
	rosterPending  = "pending"
	rosterInactive = "inactive"
)

// oktaPolicyActive is the lifecycle status of a policy that is actually in
// force; passwordPolicyProvider is the schema's short name for this IdP.
const (
	oktaPolicyActive       = "ACTIVE"
	passwordPolicyProvider = "okta"
)

// Canonical password_policy.v2 vocabulary this plugin emits.
const (
	scopeAccount       = "account"
	scopeGroup         = "group"
	complexityPerClass = "per_class"
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

// RosterUser is the subset of an Okta user the roster_entry mapping reads.
// It is deliberately lean (no factors, no roles): the roster path makes no
// per-user calls. Status is Okta's raw lifecycle status (ACTIVE, STAGED,
// DEPROVISIONED, …).
type RosterUser struct {
	ID             string
	Status         string
	Email          string
	FirstName      string
	LastName       string
	Login          string
	EmployeeNumber string
	UserType       string
}

// RosterAPI lists every user in the org for the roster, including
// DEPROVISIONED users (which Okta's default user listing omits). It is a
// separate interface from API so existing API implementations (test stubs in
// other packages) keep compiling; the concrete *httpAPI satisfies both, and
// Collect type-asserts for it only when a slot accepts roster_entry.
type RosterAPI interface {
	ListRosterUsers(ctx context.Context) ([]RosterUser, error)
}

// API is the subset of the Okta API the plugin uses. Defining it as
// an interface lets tests inject a fake without making real network
// calls; the concrete *httpAPI satisfies it.
//
// ListPasswordPolicies is deliberately part of API rather than a narrow
// opt-in interface like RosterAPI. A type assertion would turn a stub that
// predates the method into a *runtime* "cannot list" error, which the
// collector classifies as retryable and the evaluator reports as a policy
// error (exit 2) — for a plugin whose job is producing evidence, that is a
// worse failure than a compile error in the one place a stub is defined.
type API interface {
	ListUsers(ctx context.Context) ([]User, error)
	ListApps(ctx context.Context) ([]App, error)
	ListPasswordPolicies(ctx context.Context) ([]PasswordPolicy, error)
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
	return []string{EvidenceTypeDirectoryUser, EvidenceTypeApp, EvidenceTypeRosterEntry, EvidenceTypePasswordPolicy}
}

// Init is a no-op; configuration arrives via the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the directory_user shape this plugin emits. Cross-
// vendor fields map to Okta concepts as follows:
//   - mfa_enabled: derived from MFAFactorCount > 0
//   - is_active:   true when Status is one in which the user can still sign
//     in — ACTIVE, RECOVERY, PASSWORD_EXPIRED, LOCKED_OUT — the same set that
//     maps to roster_entry status=active (see rosterStatus). A locked-out or
//     password-expired account is still a live credential; STAGED,
//     PROVISIONED, SUSPENDED and DEPROVISIONED are not active.
//   - is_admin:    derived from len(AdminRoles) > 0 (any Okta admin-role
//     assignment — SUPER_ADMIN, ORG_ADMIN, READ_ONLY_ADMIN, …)
//   - display_name: best-effort, falls back to email
//
// is_admin is mandatory for every directory_user emitter (WU-0.2,
// docs/architecture/12-multicloud-sources.md): the admin-MFA policies are
// phrased as none(is_admin AND no-MFA), and a missing is_admin surfaces as
// status=error (a coverage gap), not a vacuous pass. That now holds
// wherever the field is read — a clause filter reading an absent field
// errors as well, rather than dropping the record. Populating it from
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

// rosterPayload is the roster_entry shape this plugin emits. Optional
// strings are omitted when empty: the schema requires minLength 1 and
// forbids additional properties (data minimisation).
type rosterPayload struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Email        string `json:"email,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	EmployeeID   string `json:"employee_id,omitempty"`
	EmployeeType string `json:"employee_type,omitempty"`
	SourceStatus string `json:"source_status,omitempty"`
}

// Collect returns records for every evidence type in req.AcceptedTypes
// that this plugin emits. A slot whose Accepts list includes several
// okta types gets records for each in a single call. Records are
// sorted by ID within each type group; the collector splits them by
// Type for envelope writing.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	collectors := []struct {
		typ     string
		collect func(context.Context) ([]core.EvidenceRecord, error)
	}{
		{EvidenceTypeDirectoryUser, p.collectUsers},
		{EvidenceTypeApp, p.collectApps},
		{EvidenceTypeRosterEntry, p.collectRoster},
		{EvidenceTypePasswordPolicy, p.collectPasswordPolicies},
	}
	var out []core.EvidenceRecord
	matched := false
	for _, c := range collectors {
		if !req.Accepts(c.typ) {
			continue
		}
		matched = true
		rs, err := c.collect(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if !matched {
		return nil, fmt.Errorf("okta: AcceptedTypes %v does not include emitted types %q",
			req.AcceptedTypes, p.Emits())
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
			IsActive:       rosterStatus(u.Status) == rosterActive,
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

func (p *Plugin) collectRoster(ctx context.Context) ([]core.EvidenceRecord, error) {
	ra, ok := p.api.(RosterAPI)
	if !ok {
		return nil, fmt.Errorf("okta: API implementation %T cannot list roster users", p.api)
	}
	users, err := ra.ListRosterUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: list roster users: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(users))
	for i := range users {
		rec, err := rosterRecord(&users[i], now)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// rosterRecord maps one Okta user to a roster_entry record. email is the
// join key, so IdentityKey is its lowercased form (empty when absent).
func rosterRecord(u *RosterUser, now time.Time) (core.EvidenceRecord, error) {
	email := strings.TrimSpace(u.Email)
	displayName := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
	if displayName == "" {
		displayName = strings.TrimSpace(u.Login)
	}
	payload := rosterPayload{
		ID:           u.ID,
		Status:       rosterStatus(u.Status),
		Email:        email,
		DisplayName:  displayName,
		EmployeeID:   strings.TrimSpace(u.EmployeeNumber),
		EmployeeType: strings.TrimSpace(u.UserType),
		SourceStatus: strings.TrimSpace(u.Status),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("okta: marshal roster payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeRosterEntry,
		ID:          u.ID,
		IdentityKey: strings.ToLower(email),
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
	}, nil
}

// rosterStatus normalizes Okta's raw user status to the roster_entry enum.
// active = the user can still sign in (a locked-out or password-expired
// account is a live credential awaiting self-service); pending = created or
// provisioned but never activated (a joiner); everything else — SUSPENDED,
// DEPROVISIONED, and any status Okta adds later — is inactive (fail-safe:
// an unknown status never vouches for an account).
func rosterStatus(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT":
		return rosterActive
	case "STAGED", "PROVISIONED":
		return rosterPending
	default:
		return rosterInactive
	}
}

// --- Real HTTP adapter -----------------------------------------------------

// httpAPI is the production implementation of API. It hits the customer's
// Okta tenant directly via net/http to avoid pulling in
// github.com/okta/okta-sdk-golang/v5 (which would add a sizable dependency
// tree). Endpoints used:
//
//	GET /api/v1/users                  — paged listing of users (omits DEPROVISIONED)
//	GET /api/v1/users?filter=status eq "DEPROVISIONED"
//	                                   — roster only: the deprovisioned users
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
// requires an admin token / okta.roles.read scope. The roster path
// (ListRosterUsers) makes only the two paged listing calls — no per-user
// requests — and needs only okta.users.read.
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
		Email          string `json:"email"`
		FirstName      string `json:"firstName"`
		LastName       string `json:"lastName"`
		Login          string `json:"login"`
		EmployeeNumber string `json:"employeeNumber"`
		UserType       string `json:"userType"`
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

// usersQuery is the default user listing query. rosterDeprovisionedQuery is
// the roster's second pass: Okta's default listing omits DEPROVISIONED users,
// so they are fetched explicitly with a status filter.
var (
	usersQuery               = url.Values{"limit": {"200"}}
	rosterDeprovisionedQuery = url.Values{"limit": {"200"}, "filter": {`status eq "DEPROVISIONED"`}}
)

// pageAll GETs path and every rel="next" page after it, decoding each page
// as a JSON array and handing each element to visit in order.
func pageAll[T any](ctx context.Context, h *httpAPI, path string, visit func(T) error) error {
	for path != "" {
		var page []T
		next, err := h.getJSON(ctx, path, &page)
		if err != nil {
			return err
		}
		for _, item := range page {
			if err := visit(item); err != nil {
				return err
			}
		}
		path = next
	}
	return nil
}

func (h *httpAPI) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	err := pageAll(ctx, h, "/api/v1/users?"+usersQuery.Encode(), func(u oktaUser) error {
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
			return err
		}
		usr.MFAFactorCount = n
		roles, err := h.listAdminRoles(ctx, u.ID)
		if err != nil {
			return err
		}
		usr.AdminRoles = roles
		out = append(out, usr)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListRosterUsers lists every user for the roster in two paged passes — the
// default listing, then the DEPROVISIONED users it omits — de-duplicated by
// id (first occurrence wins). No per-user factor or role calls are made.
func (h *httpAPI) ListRosterUsers(ctx context.Context) ([]RosterUser, error) {
	var out []RosterUser
	seen := map[string]bool{}
	visit := func(u oktaUser) error {
		if seen[u.ID] {
			return nil
		}
		seen[u.ID] = true
		out = append(out, RosterUser{
			ID:             u.ID,
			Status:         u.Status,
			Email:          u.Profile.Email,
			FirstName:      u.Profile.FirstName,
			LastName:       u.Profile.LastName,
			Login:          u.Profile.Login,
			EmployeeNumber: u.Profile.EmployeeNumber,
			UserType:       u.Profile.UserType,
		})
		return nil
	}
	for _, q := range []url.Values{usersQuery, rosterDeprovisionedQuery} {
		if err := pageAll(ctx, h, "/api/v1/users?"+q.Encode(), visit); err != nil {
			return nil, err
		}
	}
	return out, nil
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
	err := pageAll(ctx, h, "/api/v1/apps?limit=200", func(a oktaApp) error {
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
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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
			return "", &sources.APIError{
				Source:     SourceID,
				StatusCode: resp.StatusCode,
				Message:    fmt.Sprintf("%s: %s: %v", path, resp.Status, readErr),
				Err:        readErr,
			}
		}
		return "", &sources.APIError{
			Source:     SourceID,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(body))),
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", fmt.Errorf("okta: decode %s: %w", path, err)
	}
	return nextLinkFromHeader(resp.Header, h.base), nil
}

// nextLinkPath extracts the relative path of the rel="next" link, or
// empty string if no next page. Okta's Link header format matches
// RFC 5988 — comma-separated, each part wrapped in angle brackets.
// nextLinkFromHeader finds the rel="next" link across every Link header on
// the response.
//
// Okta documents sending the pagination links as separate header lines —
//
//	link: <…?limit=20>; rel="self"
//	link: <…?after=…>; rel="next"
//
// — and http.Header.Get returns only the first of those. Reading just that
// one ends pagination after page one whenever "self" is sent first, which
// truncates collection silently: the run looks complete, and an `all`
// quantifier passes on the records it never saw. Both encodings (separate
// lines and one comma-joined value) are legal HTTP, so scan all of them.
func nextLinkFromHeader(h http.Header, base string) string {
	for _, link := range h.Values("Link") {
		if next := nextLinkPath(link, base); next != "" {
			return next
		}
	}
	return ""
}

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

var (
	_ core.SourcePlugin = (*Plugin)(nil)
	_ API               = (*httpAPI)(nil)
	_ RosterAPI         = (*httpAPI)(nil)
)

// PasswordPolicy is the subset of an Okta PASSWORD policy the plugin reads.
// Okta returns the settings inline on the list response, so one paged call
// answers the whole org.
//
// Every complexity and age field is a pointer because Okta's own published
// example returns `"minNumber": null`. The difference matters for
// MinLength: a null read as 0 would sign "this org has no minimum" into
// evidence when what we actually know is that Okta reported nothing.
// Under password_policy.v1 that distinction could be described but not
// emitted — all eight fields were required, so the plugin had to write the
// 0 it had just argued against. v2 makes absence expressible and the
// mapping below now omits what Okta did not report.
//
// System marks Okta's undeletable default policy, the one that governs
// every user not matched by a higher-priority group-assigned policy. It is
// how the plugin answers v2's `scope` honestly without a second API call:
// system true is org-wide (account scope), everything else is assigned to
// groups.
type PasswordPolicy struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Status   string                 `json:"status"`
	Priority int                    `json:"priority"`
	System   bool                   `json:"system"`
	Settings passwordPolicySettings `json:"settings"`
}

type passwordPolicySettings struct {
	Password passwordSettings `json:"password"`
}

type passwordSettings struct {
	Complexity passwordComplexity `json:"complexity"`
	Age        passwordAge        `json:"age"`
}

// Okta documents each min* field as a count in which 0 means "no" and 1
// means "yes", so the canonical booleans are a faithful read rather than a
// squeeze.
type passwordComplexity struct {
	MinLength    *int `json:"minLength"`
	MinLowerCase *int `json:"minLowerCase"`
	MinUpperCase *int `json:"minUpperCase"`
	MinNumber    *int `json:"minNumber"`
	MinSymbol    *int `json:"minSymbol"`
}

// Okta documents 0 as "no limit" for MaxAgeDays and "none" for
// HistoryCount — the same meaning password_policy.v1 gives them, and the
// same meaning an unset AWS policy carries.
type passwordAge struct {
	MaxAgeDays   *int `json:"maxAgeDays"`
	HistoryCount *int `json:"historyCount"`
}

// passwordPolicyPayload is the canonical password_policy.v2 shape. The
// json tags match the AWS emitter's exactly — policies bind to the type,
// never to a vendor.
//
// Like the AWS plugin this emits v2 and only v2. A binding's Collect is
// called once with every accepted type it can satisfy and all the records
// it returns land in the same slot, so emitting both versions would put
// two records describing one Okta policy into one slot: double the
// resources_evaluated count on the wire and two signed envelopes for one
// fact. The six consuming policies accept both IDs so a project-local
// plugin still emitting v1 keeps binding.
//
// The optional numeric fields are pointers so that "Okta reported null"
// stays distinguishable from "Okta reported zero". Zero is a real answer
// in this API — maxAgeDays 0 means no expiry, historyCount 0 means no
// history — which is precisely why a null must not collapse into it.
type passwordPolicyPayload struct {
	ID                   string `json:"id"`
	Name                 string `json:"name,omitempty"`
	Provider             string `json:"provider"`
	Scope                string `json:"scope"`
	Precedence           *int   `json:"precedence,omitempty"`
	MinLength            *int   `json:"min_length,omitempty"`
	MaxAgeDays           *int   `json:"max_age_days,omitempty"`
	ReusePrevented       *bool  `json:"reuse_prevented,omitempty"`
	ReusePreventionCount *int   `json:"reuse_prevention_count,omitempty"`
	ComplexityModel      string `json:"complexity_model"`
	RequiresUppercase    bool   `json:"requires_uppercase"`
	RequiresLowercase    bool   `json:"requires_lowercase"`
	RequiresNumbers      bool   `json:"requires_numbers"`
	RequiresSymbols      bool   `json:"requires_symbols"`
}

// collectPasswordPolicies emits one record per ACTIVE password policy.
//
// An Okta org legitimately has several, group-assigned and ranked by
// priority, where an AWS account has exactly one. That is fine as evidence:
// the consuming policies quantify `all` over the slot, so N records read as
// "every password policy in this org meets the bar" — the verdict an
// auditor wants, and true by construction. Emitting only the default policy
// would hide a weaker override; synthesizing one worst-case record would be
// fabricating evidence rather than reading it.
//
// INACTIVE policies are skipped: an inactive policy governs nobody, so
// failing a control on a rule that is not in force would be a false finding.
func (p *Plugin) collectPasswordPolicies(ctx context.Context) ([]core.EvidenceRecord, error) {
	policies, err := p.api.ListPasswordPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: list password policies: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(policies))
	for i := range policies {
		pol := &policies[i]
		if !strings.EqualFold(pol.Status, oktaPolicyActive) {
			continue
		}
		c := pol.Settings.Password.Complexity
		body, err := json.Marshal(passwordPolicyPayload{
			ID:                   pol.ID,
			Name:                 pol.Name,
			Provider:             passwordPolicyProvider,
			Scope:                policyScope(pol.System),
			Precedence:           precedence(pol.Priority),
			MinLength:            c.MinLength,
			MaxAgeDays:           pol.Settings.Password.Age.MaxAgeDays,
			ReusePrevented:       reusePrevented(pol.Settings.Password.Age.HistoryCount),
			ReusePreventionCount: pol.Settings.Password.Age.HistoryCount,
			// Okta answers complexity as character-class counts, so
			// per_class is a faithful description of what it told us —
			// including the classes it says are not required.
			ComplexityModel:   complexityPerClass,
			RequiresUppercase: requiredClass(c.MinUpperCase),
			RequiresLowercase: requiredClass(c.MinLowerCase),
			RequiresNumbers:   requiredClass(c.MinNumber),
			RequiresSymbols:   requiredClass(c.MinSymbol),
		})
		if err != nil {
			return nil, fmt.Errorf("okta: marshal password policy payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypePasswordPolicy,
			ID:          pol.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// requiredClass reads Okta's 0/1 count as the canonical boolean. A field
// Okta did not report is not a requirement we can claim.
func requiredClass(v *int) bool { return v != nil && *v >= 1 }

// policyScope maps Okta's `system` flag onto the v2 scope vocabulary.
// The system policy is the org's undeletable default and governs everyone
// no higher-priority policy claims; every other PASSWORD policy is
// assigned through group conditions.
func policyScope(system bool) string {
	if system {
		return scopeAccount
	}
	return scopeGroup
}

// precedence carries Okta's priority through unchanged: Okta evaluates
// priority 1 first, which is exactly what v2's precedence means, so no
// inversion is needed (a vendor ordering the other way, as Google's
// sortOrder does, would be inverted in its own plugin). A missing or
// non-positive priority is not ranked rather than reported as rank zero.
func precedence(priority int) *int {
	if priority < 1 {
		return nil
	}
	return &priority
}

// reusePrevented derives the canonical boolean from the history depth
// Okta discloses. A depth Okta did not report answers nothing — neither
// "reuse is prevented" nor "it is not" — so the boolean is omitted with
// the count rather than defaulted to false, which would report an unread
// setting as a finding.
func reusePrevented(historyCount *int) *bool {
	if historyCount == nil {
		return nil
	}
	prevented := *historyCount >= 1
	return &prevented
}

// ListPasswordPolicies returns the org's PASSWORD policies. Okta requires
// the type filter and pages the result like every other collection.
func (h *httpAPI) ListPasswordPolicies(ctx context.Context) ([]PasswordPolicy, error) {
	var out []PasswordPolicy
	err := pageAll(ctx, h, "/api/v1/policies?type=PASSWORD&limit=200", func(pol PasswordPolicy) error {
		out = append(out, pol)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
