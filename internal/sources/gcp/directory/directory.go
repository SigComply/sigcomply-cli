// Package directory implements the gcp.directory source plugin: lists
// Google Workspace / Cloud Identity users via the Admin SDK Directory
// API and emits one cross-vendor directory_user record per user so MFA,
// admin, and lifecycle policies (e.g. mfa_enforced_admins) evaluate
// against Google identities exactly as they do against AWS IAM, Okta,
// GitHub, and GitLab — zero policy changes (Invariant #4, substitutability).
//
// From the same user listing it also emits roster_entry (roster.go) when a
// project designates Google Workspace as its workforce roster: status
// inactive for suspended or archived users, employee_id from the first
// "organization" external ID.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
//
// Auth: Application Default Credentials with the read-only directory
// scope. The Admin SDK needs a Workspace admin context: either the ADC
// identity holds an admin role itself, or (config target_service_account
// + impersonate_subject) ADC impersonates a service account that uses
// domain-wide delegation to act as an admin user. See AuthConfig and
// docs/configuration.md §GCP.
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
// API with the read-only user scope, authenticating per auth (see
// AuthConfig). The credentials must carry a Workspace admin context (see
// the package doc). An empty customer defaults to the "my_customer" alias.
func NewFromGCP(ctx context.Context, customer string, auth AuthConfig) (*Plugin, error) {
	opts, err := clientOptions(ctx, auth)
	if err != nil {
		return nil, err
	}
	svc, err := admin.NewService(ctx, opts...)
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
func (*Plugin) Emits() []string { return []string{EvidenceTypeID, RosterEvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
// Preserved for symmetry with other plugins.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// scope stamps every record with the Workspace customer it came from — the
// account boundary for a directory, the same role a subscription plays for
// azure.entra. The defaultCustomer alias is deliberately NOT stamped: it means
// "whoever this credential is", so signing it into evidence would assert a
// directory boundary that names nothing. Provenance is recorded only when the
// operator declared which customer they audit.
func (p *Plugin) scope() *core.RecordScope {
	if p.customer == "" || p.customer == defaultCustomer {
		return nil
	}
	return &core.RecordScope{Account: p.customer}
}

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

// Collect lists the customer's users once and emits, per accepted type,
// one directory_user and/or one roster_entry record each. Records are
// stably sorted by ID before return so envelope bytes are stable across
// runs against stable directory state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantUsers := req.Accepts(EvidenceTypeID)
	wantRoster := req.Accepts(RosterEvidenceTypeID)
	if !wantUsers && !wantRoster {
		return nil, fmt.Errorf("gcp.directory: slot AcceptedTypes %v does not include %q or %q",
			req.AcceptedTypes, EvidenceTypeID, RosterEvidenceTypeID)
	}
	users, err := p.api.ListUsers(ctx, p.customer)
	if err != nil {
		return nil, fmt.Errorf("gcp.directory: list users: %w", err)
	}
	now := p.now()
	scope := p.scope()
	records := make([]core.EvidenceRecord, 0, len(users))
	for _, u := range users {
		if u == nil {
			continue
		}
		if wantUsers {
			r, err := directoryUserRecord(u, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, r)
		}
		if wantRoster {
			r, err := rosterRecord(u, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, r)
		}
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// directoryUserRecord builds one directory_user record from a Workspace user.
func directoryUserRecord(u *admin.User, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	status, _ := userStatus(u)
	payload := userPayload{
		ID:          u.Id,
		DisplayName: userDisplayName(u),
		Email:       u.PrimaryEmail,
		// IsEnrolledIn2Sv is Google's 2-step-verification enrollment
		// flag — the directory_user MFA signal for Workspace.
		MFAEnabled: u.IsEnrolledIn2Sv,
		// Super-admins (IsAdmin) and delegated admins both hold
		// account-wide elevated privileges, so both count as is_admin
		// for admin-MFA / least-privilege policies.
		IsAdmin: u.IsAdmin || u.IsDelegatedAdmin,
		// Suspended and archived accounts cannot authenticate — the same
		// rule that makes them inactive in the roster.
		IsActive: status == rosterActive,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("gcp.directory: marshal user payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeID,
		ID:          u.Id,
		IdentityKey: u.PrimaryEmail,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       scope,
	}, nil
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
