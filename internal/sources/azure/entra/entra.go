// Package entra implements the azure.entra source plugin: lists Microsoft
// Entra ID (Azure AD) users via Microsoft Graph and emits one cross-vendor
// directory_user record per user, so MFA, admin, and lifecycle policies
// (e.g. mfa_enforced_admins) evaluate against Entra identities exactly as
// they do against AWS IAM, Okta, GitHub, GitLab, and GCP — zero policy
// changes (Invariant #4, substitutability).
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
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "directory_user"

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

// API is the subset of Microsoft Graph this plugin uses. Defining it as an
// interface lets tests inject a fake without hitting Graph; the real adapter
// (realGraph) handles auth, pagination, and the two-endpoint join.
type API interface {
	ListUsers(ctx context.Context) ([]User, error)
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
func NewFromGraph(cred azcore.TokenCredential, cfg azcommon.Config) *Plugin {
	return New(Options{
		API: &realGraph{
			base:   graphBaseURL,
			client: &http.Client{Timeout: 30 * time.Second},
			cred:   cred,
		},
		Tenant: cfg.TenantID,
	})
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

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

// Collect lists the tenant's users and emits one directory_user record each,
// sorted by ID so envelope bytes are stable across runs against stable
// directory state.
//
// Licensing: mfa_enabled and is_admin come from the userRegistrationDetails
// report, which requires the AuditLog.Read.All permission and an Entra ID
// P1/P2 license. If that read fails the plugin returns an error (which tags
// only the Entra-bound policies `error` — not a run crash) rather than
// fabricating mfa_enabled=false for every user, which would be misleading
// evidence. last_login_at degrades silently (omitted) when signInActivity is
// unavailable.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.entra: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	users, err := p.api.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.entra: list users: %w", err)
	}
	var scope *core.RecordScope
	if p.tenant != "" {
		scope = &core.RecordScope{Account: p.tenant}
	}
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

func (r *realGraph) ListUsers(ctx context.Context) ([]User, error) {
	tok, err := r.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azcommon.ScopeGraph}})
	if err != nil {
		return nil, fmt.Errorf("graph token: %w", err)
	}
	token := tok.Token

	// 1. Per-user MFA + admin flags, keyed by user object id. Fetched first
	//    so a missing AuditLog.Read.All / P1/P2 fails fast with a clear hint.
	reg := map[string]userRegistrationDetail{}
	next := r.base + "/reports/authenticationMethods/userRegistrationDetails"
	for next != "" {
		var page graphPage[userRegistrationDetail]
		if err := r.get(ctx, token, next, &page); err != nil {
			return nil, fmt.Errorf("user registration details (needs the AuditLog.Read.All permission and an Entra ID P1/P2 license): %w", err)
		}
		for _, d := range page.Value {
			reg[d.ID] = d
		}
		next = page.NextLink
	}

	// 2. Users, joined to the report on object id.
	var out []User
	next = r.base + "/users?$select=id,userPrincipalName,mail,displayName,accountEnabled,signInActivity&$top=500"
	for next != "" {
		var page graphPage[graphUser]
		if err := r.get(ctx, token, next, &page); err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		for _, u := range page.Value {
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
		}
		next = page.NextLink
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
			return fmt.Errorf("%s: %w", resp.Status, readErr)
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
