// Package entra implements the azure.entra source plugin: lists Microsoft
// Entra ID (Azure AD) users via Microsoft Graph and emits one cross-vendor
// directory_user record per user, so MFA, admin, and lifecycle policies
// (e.g. mfa_enforced_admins) evaluate against Entra identities exactly as
// they do against AWS IAM, Okta, GitHub, GitLab, and GCP — zero policy
// changes (Invariant #4, substitutability). It also emits roster_entry, so
// Entra can be the organization's authoritative workforce roster.
//
// Two Graph reads, joined on the user object id:
//   - GET /reports/authenticationMethods/userRegistrationDetails — Microsoft's
//     own per-user computed flags isMfaRegistered (→ mfa_enabled) and isAdmin
//     (→ is_admin). One report covers both, so no directoryRoles traversal.
//   - GET /users — accountEnabled (→ is_active), mail (→ email), displayName,
//     and signInActivity.lastSignInDateTime (→ last_login_at).
//
// Raw REST (net/http) rather than github.com/microsoftgraph/msgraph-sdk-go:
// the Kiota-generated SDK adds minutes to build/test/lint and a large
// transitive tree, against the repo's minimal-dependency, httptest-able
// convention (same reason github/okta call REST directly). The only Azure
// dependency is azidentity, already vendored, for the bearer token.
//
// roster_entry uses a third, independent read — GET /users with the
// roster fields (accountEnabled, userType, employeeId, employeeType) — and
// never touches the registration report, so it needs only User.Read.All and
// works on tenants without an Entra ID P1/P2 license. Guests are excluded:
// they are external identities, not workforce.
//
// Auth: a DefaultAzureCredential (azcommon.NewCredential) mints a token for
// the Microsoft Graph ".default" scope. The app registration needs the
// application permissions User.Read.All + AuditLog.Read.All consented, and
// per-user MFA registration / signInActivity require an Entra ID P1/P2
// license. When those are missing the report read fails with a clear hint;
// see the licensing note on Collect and docs/configuration.md §Azure.
//
// Test injection: the API interface is the single seam; the real adapter
// (realGraph) wraps an *http.Client + credential and unit tests inject an
// in-memory fake. Real-adapter HTTP behavior is covered with httptest;
// deeper integration coverage is deferred to the testing strategy revamp.
package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the cross-vendor directory_user evidence type this plugin
// emits; EvidenceTypeRosterEntry is the cross-vendor workforce-roster type.
const (
	EvidenceTypeID          = "directory_user"
	EvidenceTypeRosterEntry = "roster_entry"
)

// SourceID is the registered ID for the azure.entra plugin instance.
const SourceID = "azure.entra"

// graphBaseURL is the Microsoft Graph v1.0 endpoint. Overridable on the real
// adapter so httptest can stand in for Graph.
const graphBaseURL = "https://graph.microsoft.com/v1.0"

// User is the merged, cross-vendor view of one Entra identity — the join of
// a /users entry with its userRegistrationDetails report row.
type User struct {
	ID          string
	UPN         string // userPrincipalName; the email fallback for IdentityKey
	Email       string // from mail only (a real mailbox address); may be empty
	DisplayName string
	IsActive    bool
	IsAdmin     bool
	MFAEnabled  bool
	LastLoginAt time.Time // zero when never signed in / unavailable without P1/P2
}

// RosterUser is one /users entry as the roster_entry mapping reads it. Mail
// and UPN are kept separately so the mapping owns the email fallback.
type RosterUser struct {
	ID             string
	Mail           string
	UPN            string
	DisplayName    string
	AccountEnabled bool
	UserType       string // "Member" or "Guest"
	EmployeeID     string
	EmployeeType   string
}

// API is the subset of Microsoft Graph this plugin uses. Defining it as an
// interface lets tests inject a fake without hitting Graph; the real adapter
// (realGraph) handles auth, pagination, and the two-endpoint join.
type API interface {
	ListUsers(ctx context.Context) ([]User, error)
	// TenantID returns the directory the credential actually reads, as
	// Graph reports it. It is the observed half of the provenance check
	// in newVerifiedPlugin.
	TenantID(ctx context.Context) (string, error)
	// ListRosterUsers lists every user with the roster fields. It must not
	// read the P1/P2-gated registration report.
	ListRosterUsers(ctx context.Context) ([]RosterUser, error)
}

// Plugin is the in-process azure.entra source.
type Plugin struct {
	api    API
	tenant string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API API
	// Tenant is the Entra tenant id (optional). When set it tags each
	// record's scope.Account — the directory boundary the identity belongs
	// to. The Graph token itself is scoped by the credential's home tenant
	// (see the package doc), so this is provenance metadata, not auth.
	Tenant string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers
// using the real Graph endpoint should use NewFromGraph.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:    opts.API,
		tenant: opts.Tenant,
		now:    now,
	}
}

// NewFromGraph constructs a Plugin backed by the real Microsoft Graph API
// using the given credential (a DefaultAzureCredential) for bearer tokens.
// NewFromGraph builds the plugin against real Graph and resolves the
// tenant it will actually read before returning.
func NewFromGraph(ctx context.Context, cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	return newVerifiedPlugin(ctx, Options{
		API: &realGraph{
			base:   graphBaseURL,
			client: &http.Client{Timeout: 30 * time.Second},
			cred:   cred,
		},
	}, cfg)
}

// newVerifiedPlugin resolves the tenant the credential actually reads and
// stamps that on every record, rather than whatever the operator declared.
//
// The Graph plane makes this necessary in a way the ARM plane does not. An
// ARM plugin passes subscription_id into its client, so the label and the
// data are the same string by construction and a wrong value 403s. Graph's
// /v1.0 base carries no tenant segment — the token decides the directory —
// so a declared tenant_id was pure metadata that nothing compared against
// anything. Set it to a tenant your credential does not belong to and the
// run read directory Y, stamped the records "X", schema-validated them and
// Ed25519-signed them into the vault, with no error, no warning and no log
// line. That is signed evidence asserting a false directory boundary, which
// is worse than not supporting multiple tenants at all.
//
// A declared tenant_id is now an assertion that gets checked: it must equal
// what Graph reports, or the run stops as a config error (exit 3) before it
// signs anything. This is the idiom planner.VendorWarnings calls "an
// observed baseline checking a declared one" — except here disagreement is
// fatal rather than advisory, because the artifact is signed.
func newVerifiedPlugin(ctx context.Context, opts Options, cfg azcommon.Config) (*Plugin, error) {
	observed, err := opts.API.TenantID(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.entra: resolve tenant from credential: %w", err)
	}
	if observed == "" {
		return nil, fmt.Errorf("azure.entra: Graph reported no tenant for this credential")
	}
	// Never fall back to the declared value on failure: that unverified
	// string is exactly what stopped being trustworthy.
	if declared := strings.TrimSpace(cfg.TenantID); declared != "" && !strings.EqualFold(declared, observed) {
		return nil, fmt.Errorf(
			"azure.entra: configured tenant_id %q is not the tenant these credentials read (%q); "+
				"evidence would be signed with a directory boundary it did not come from — "+
				"correct tenant_id, or drop it and let the credential speak for itself",
			declared, observed)
	}
	opts.Tenant = observed
	return New(opts), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID, EvidenceTypeRosterEntry} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the cross-vendor directory_user shape this plugin emits.
// The policy-read booleans (mfa_enabled/is_admin/is_active) are emitted
// unconditionally so a policy filtering on them always finds them present on
// every Entra record (null-trap guard, Invariant #4 / WU-0.2). email is set
// only from a real mailbox address (never UPN, which can be non-email-shaped
// for guests and would fail the schema's format:email). last_login_at is a
// pointer so an unknown sign-in time is omitted, not reported as year 0001.
type userPayload struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	IsAdmin     bool       `json:"is_admin"`
	IsActive    bool       `json:"is_active"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// rosterPayload is the roster_entry shape this plugin emits. Optional strings
// are omitted when empty: the schema requires minLength 1 and forbids
// additional properties (data minimisation).
type rosterPayload struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Email        string `json:"email,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	EmployeeID   string `json:"employee_id,omitempty"`
	EmployeeType string `json:"employee_type,omitempty"`
	SourceStatus string `json:"source_status,omitempty"`
}

// Collect returns records for every evidence type in req.AcceptedTypes that
// this plugin emits (directory_user and/or roster_entry), each group sorted by
// ID so envelope bytes are stable across runs against stable directory state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	collectors := []struct {
		typ     string
		collect func(context.Context) ([]core.EvidenceRecord, error)
	}{
		{EvidenceTypeID, p.collectUsers},
		{EvidenceTypeRosterEntry, p.collectRoster},
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
		return nil, fmt.Errorf("azure.entra: slot AcceptedTypes %v does not include any of %q", req.AcceptedTypes, p.Emits())
	}
	return out, nil
}

// collectUsers lists the tenant's users and emits one directory_user record
// each.
//
// Licensing: mfa_enabled and is_admin come from the userRegistrationDetails
// report, which requires the AuditLog.Read.All permission and an Entra ID
// P1/P2 license. If that read fails the plugin returns an error (which tags
// only the Entra-bound policies `error` — not a run crash) rather than
// fabricating mfa_enabled=false for every user, which would be misleading
// evidence. last_login_at degrades silently (omitted) when signInActivity is
// unavailable.
func (p *Plugin) collectUsers(ctx context.Context) ([]core.EvidenceRecord, error) {
	users, err := p.api.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.entra: list users: %w", err)
	}
	scope := p.scope()
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(users))
	for _, u := range users {
		displayName := u.DisplayName
		if displayName == "" {
			displayName = u.UPN
		}
		payload := userPayload{
			ID:          u.ID,
			DisplayName: displayName,
			Email:       u.Email,
			MFAEnabled:  u.MFAEnabled,
			IsAdmin:     u.IsAdmin,
			IsActive:    u.IsActive,
		}
		if !u.LastLoginAt.IsZero() {
			t := u.LastLoginAt
			payload.LastLoginAt = &t
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("azure.entra: marshal user payload: %w", err)
		}
		// IdentityKey is the cross-source dedup key: prefer the mailbox
		// address, fall back to the userPrincipalName when no mail exists.
		identity := u.Email
		if identity == "" {
			identity = u.UPN
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          u.ID,
			IdentityKey: identity,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       scope,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// scope tags records with the tenant when one is configured.
func (p *Plugin) scope() *core.RecordScope {
	if p.tenant == "" {
		return nil
	}
	return &core.RecordScope{Account: p.tenant}
}

// collectRoster lists the tenant's users and emits one roster_entry record per
// member (guests excluded), sorted by ID.
func (p *Plugin) collectRoster(ctx context.Context) ([]core.EvidenceRecord, error) {
	users, err := p.api.ListRosterUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.entra: list roster users: %w", err)
	}
	scope := p.scope()
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(users))
	for i := range users {
		u := &users[i]
		if strings.EqualFold(strings.TrimSpace(u.UserType), "Guest") {
			continue
		}
		payload := rosterPayloadFor(u)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("azure.entra: marshal roster payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeRosterEntry,
			ID:          u.ID,
			IdentityKey: strings.ToLower(payload.Email),
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       scope,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// rosterPayloadFor maps one Entra user to roster_entry: email is the mailbox
// address, falling back to the userPrincipalName; status follows
// accountEnabled (Entra has no pending state).
func rosterPayloadFor(u *RosterUser) rosterPayload {
	email := strings.TrimSpace(u.Mail)
	if email == "" {
		email = strings.TrimSpace(u.UPN)
	}
	status, sourceStatus := "inactive", "disabled"
	if u.AccountEnabled {
		status, sourceStatus = "active", "enabled"
	}
	return rosterPayload{
		ID:           u.ID,
		Status:       status,
		Email:        email,
		DisplayName:  strings.TrimSpace(u.DisplayName),
		EmployeeID:   strings.TrimSpace(u.EmployeeID),
		EmployeeType: strings.TrimSpace(u.EmployeeType),
		SourceStatus: sourceStatus,
	}
}

// --- real Microsoft Graph adapter ---

// graphPage is the standard Graph collection envelope: a value array plus an
// absolute @odata.nextLink that is empty on the last page.
type graphPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

type graphUser struct {
	ID                string          `json:"id"`
	UserPrincipalName string          `json:"userPrincipalName"`
	Mail              *string         `json:"mail"`
	DisplayName       string          `json:"displayName"`
	AccountEnabled    bool            `json:"accountEnabled"`
	SignInActivity    *signInActivity `json:"signInActivity"`
}

// graphRosterUser is the /users projection the roster reads. Nullable Graph
// strings decode to "" (a JSON null leaves a Go string at its zero value).
type graphRosterUser struct {
	ID                string `json:"id"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
	AccountEnabled    bool   `json:"accountEnabled"`
	UserType          string `json:"userType"`
	EmployeeID        string `json:"employeeId"`
	EmployeeType      string `json:"employeeType"`
}

// rosterUsersPath is the roster listing: only the fields roster_entry needs,
// at Graph's maximum page size.
const rosterUsersPath = "/users?$select=id,mail,userPrincipalName,displayName,accountEnabled,userType,employeeId,employeeType&$top=999"

type signInActivity struct {
	LastSignInDateTime *time.Time `json:"lastSignInDateTime"`
}

type userRegistrationDetail struct {
	ID              string `json:"id"`
	IsAdmin         bool   `json:"isAdmin"`
	IsMfaRegistered bool   `json:"isMfaRegistered"`
}

// realGraph is the production implementation of API. It mints a Graph token
// from the credential and pages through the two endpoints, joining them.
type realGraph struct {
	base   string
	client *http.Client
	cred   azcore.TokenCredential
}

// token mints a Microsoft Graph bearer token from the credential.
func (r *realGraph) token(ctx context.Context) (string, error) {
	tok, err := r.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azcommon.ScopeGraph}})
	if err != nil {
		return "", fmt.Errorf("graph token: %w", err)
	}
	return tok.Token, nil
}

// graphList GETs url and follows @odata.nextLink to the end, handing each
// element to visit in order.
// TenantID reads the directory the token belongs to. Graph answers this
// for the caller's own tenant with no tenant id in the request, which is
// the point: the response cannot be steered by configuration.
func (r *realGraph) TenantID(ctx context.Context) (string, error) {
	token, err := r.token(ctx)
	if err != nil {
		return "", err
	}
	var page graphPage[struct {
		ID string `json:"id"`
	}]
	if err := r.get(ctx, token, r.base+"/organization?$select=id", &page); err != nil {
		return "", err
	}
	if len(page.Value) == 0 {
		return "", fmt.Errorf("azure.entra: /organization returned no tenant")
	}
	return page.Value[0].ID, nil
}

func graphList[T any](ctx context.Context, r *realGraph, token, url string, visit func(*T)) error {
	for url != "" {
		var page graphPage[T]
		if err := r.get(ctx, token, url, &page); err != nil {
			return err
		}
		for i := range page.Value {
			visit(&page.Value[i])
		}
		url = page.NextLink
	}
	return nil
}

// ListRosterUsers pages /users with the roster projection. It deliberately
// never reads userRegistrationDetails, so it needs only User.Read.All and no
// Entra ID P1/P2 license.
func (r *realGraph) ListRosterUsers(ctx context.Context) ([]RosterUser, error) {
	token, err := r.token(ctx)
	if err != nil {
		return nil, err
	}
	var out []RosterUser
	err = graphList(ctx, r, token, r.base+rosterUsersPath, func(u *graphRosterUser) {
		out = append(out, RosterUser{
			ID:             u.ID,
			Mail:           u.Mail,
			UPN:            u.UserPrincipalName,
			DisplayName:    u.DisplayName,
			AccountEnabled: u.AccountEnabled,
			UserType:       u.UserType,
			EmployeeID:     u.EmployeeID,
			EmployeeType:   u.EmployeeType,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("list roster users (needs the User.Read.All permission): %w", err)
	}
	return out, nil
}

func (r *realGraph) ListUsers(ctx context.Context) ([]User, error) {
	token, err := r.token(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Per-user MFA + admin flags, keyed by user object id. Fetched first
	//    so a missing AuditLog.Read.All / P1/P2 fails fast with a clear hint.
	reg := map[string]userRegistrationDetail{}
	err = graphList(ctx, r, token, r.base+"/reports/authenticationMethods/userRegistrationDetails", func(d *userRegistrationDetail) {
		reg[d.ID] = *d
	})
	if err != nil {
		return nil, fmt.Errorf("user registration details (needs the AuditLog.Read.All permission and an Entra ID P1/P2 license): %w", err)
	}

	// 2. Users, joined to the report on object id.
	var out []User
	err = graphList(ctx, r, token, r.base+"/users?$select=id,userPrincipalName,mail,displayName,accountEnabled,signInActivity&$top=500", func(u *graphUser) {
		usr := User{
			ID:          u.ID,
			UPN:         u.UserPrincipalName,
			DisplayName: u.DisplayName,
			IsActive:    u.AccountEnabled,
		}
		if u.Mail != nil {
			usr.Email = strings.TrimSpace(*u.Mail)
		}
		if u.SignInActivity != nil && u.SignInActivity.LastSignInDateTime != nil {
			usr.LastLoginAt = u.SignInActivity.LastSignInDateTime.UTC()
		}
		// Users absent from the report (e.g. disabled accounts, which
		// the report omits) keep the zero-value mfa_enabled/is_admin —
		// an honest "not registered" rather than a fabricated value.
		if d, ok := reg[u.ID]; ok {
			usr.MFAEnabled = d.IsMfaRegistered
			usr.IsAdmin = d.IsAdmin
		}
		out = append(out, usr)
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}

// get performs a single authenticated GET and decodes the JSON body into out.
// url is absolute (the first request is built from base; subsequent ones are
// the @odata.nextLink Graph returns verbatim).
func (r *realGraph) get(ctx context.Context, token, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return &sources.APIError{
				Source:     SourceID,
				StatusCode: resp.StatusCode,
				Message:    fmt.Sprintf("%s: %v", resp.Status, readErr),
				Err:        readErr,
			}
		}
		return &sources.APIError{
			Source:     SourceID,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("%s: %s", resp.Status, strings.TrimSpace(string(body))),
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
