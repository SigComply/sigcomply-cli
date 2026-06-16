// Package directory implements the gcp.directory source plugin: lists
// Google Workspace / Cloud Identity users via the Admin SDK Directory
// API and emits one cross-vendor directory_user record per user so MFA,
// admin, and lifecycle policies (e.g. mfa_enforced_admins) evaluate
// against Google identities exactly as they do against AWS IAM, Okta,
// GitHub, and GitLab — zero policy changes (Invariant #4, substitutability).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
//
// Auth: Application Default Credentials with the read-only directory
// scope. The Admin SDK has no anonymous service-account access — ADC must
// resolve to a Workspace admin, or to a service account with domain-wide
// delegation impersonating an admin. See docs/configuration.md §GCP.
//
// Test injection: the API interface is the single seam; the real adapter
// wraps *admin.Service and unit tests inject an in-memory fake. The real
// adapter has no integration tests in this plan (deferred to the testing
// strategy revamp).
package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "directory_user"

// SourceID is the registered ID for the gcp.directory plugin instance.
const SourceID = "gcp.directory"

// defaultCustomer is the Admin SDK magic alias that resolves to the
// caller account's own customerId — i.e. "all users in my organization".
const defaultCustomer = "my_customer"

// API is the subset of the Admin SDK Directory client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// Google; the real adapter wraps *admin.Service and handles pagination.
type API interface {
	ListUsers(ctx context.Context, customer string) ([]*admin.User, error)
}

// Plugin is the in-process gcp.directory source.
type Plugin struct {
	api      API
	customer string
	now      func() time.Time
}

// Options is the constructor input.
type Options struct {
	API API
	// Customer is the Admin SDK customer to enumerate; empty defaults to
	// the "my_customer" alias (the caller account's own organization).
	Customer string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers
// using the real GCP SDK should use NewFromGCP.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	customer := opts.Customer
	if customer == "" {
		customer = defaultCustomer
	}
	return &Plugin{
		api:      opts.API,
		customer: customer,
		now:      now,
	}
}

// NewFromGCP constructs a Plugin backed by the real Admin SDK Directory
// API using Application Default Credentials with the read-only user
// scope. The credentials must carry a Workspace admin context (see the
// package doc). An empty customer defaults to the "my_customer" alias.
func NewFromGCP(ctx context.Context, customer string) (*Plugin, error) {
	svc, err := admin.NewService(ctx, option.WithScopes(admin.AdminDirectoryUserReadonlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.directory: new service: %w", err)
	}
	return New(Options{
		API:      &realDirectory{svc: svc},
		Customer: customer,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
// Preserved for symmetry with other plugins.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the cross-vendor directory_user shape this plugin emits.
// The policy-read booleans (mfa_enabled/is_admin/is_active) are emitted
// unconditionally so a policy filtering on them always finds them present
// on every Google record (null-trap guard, Invariant #4).
type userPayload struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	MFAEnabled  bool   `json:"mfa_enabled"`
	IsAdmin     bool   `json:"is_admin"`
	IsActive    bool   `json:"is_active"`
}

// Collect lists the customer's users and emits one directory_user record
// each. Records are sorted by ID before return so envelope bytes are
// stable across runs against stable directory state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.directory: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	users, err := p.api.ListUsers(ctx, p.customer)
	if err != nil {
		return nil, fmt.Errorf("gcp.directory: list users: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(users))
	for _, u := range users {
		if u == nil {
			continue
		}
		displayName := ""
		if u.Name != nil {
			displayName = u.Name.FullName
		}
		payload := userPayload{
			ID:          u.Id,
			DisplayName: displayName,
			Email:       u.PrimaryEmail,
			// IsEnrolledIn2Sv is Google's 2-step-verification enrollment
			// flag — the directory_user MFA signal for Workspace.
			MFAEnabled: u.IsEnrolledIn2Sv,
			// Super-admins (IsAdmin) and delegated admins both hold
			// account-wide elevated privileges, so both count as is_admin
			// for admin-MFA / least-privilege policies.
			IsAdmin: u.IsAdmin || u.IsDelegatedAdmin,
			// Suspended accounts cannot authenticate; invert for is_active.
			IsActive: !u.Suspended,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.directory: marshal user payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          u.Id,
			IdentityKey: u.PrimaryEmail,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// realDirectory is the production implementation of API. It wraps
// *admin.Service and pages through the full user list.
type realDirectory struct {
	svc *admin.Service
}

func (r *realDirectory) ListUsers(ctx context.Context, customer string) ([]*admin.User, error) {
	var users []*admin.User
	// MaxResults caps at 500 per page; page until NextPageToken is empty.
	call := r.svc.Users.List().Customer(customer).MaxResults(500)
	for {
		resp, err := call.Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		users = append(users, resp.Users...)
		if resp.NextPageToken == "" {
			break
		}
		call = call.PageToken(resp.NextPageToken)
	}
	return users, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
