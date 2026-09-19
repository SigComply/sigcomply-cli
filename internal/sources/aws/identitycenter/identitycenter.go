// Package identitycenter implements the aws.identity_center source plugin:
// lists the users of an AWS IAM Identity Center (formerly AWS SSO) identity
// store and emits the two cross-vendor identity shapes — directory_user (v1)
// and roster_entry — so an estate whose human access runs through Identity
// Center rather than long-lived IAM users is evaluated against the same
// policies, with zero policy changes (Invariant #4, substitutability).
//
// Why v1 and not directory_user.v2: v2 is the AWS-IAM-shaped extension whose
// required is_root / has_console_access / has_programmatic_access fields back
// the root-account and direct-policy policies. An Identity Center user has no
// root account and no access keys, so emitting v2 would make those policies
// evaluate SSO identities and pass trivially — inflating the compliance score,
// the failure mode this codebase treats as the worst one. v1 is also what
// every other non-AWS-IAM identity source emits (see
// docs/architecture/12-multicloud-sources.md §Decision 1).
//
// Why this plugin matters for the roster: Identity Center users carry real
// email addresses, so they join internal/frameworks' identity-roster policies
// directly on payload.email. AWS IAM users do not — linking an IAM username to
// a person needs experimental.roster.aliases, which is hand-maintained and
// whose typos fail silently.
//
// API surface (two AWS JSON-protocol services):
//
//	identitystore:ListUsers   — the identity store's users (paginated)
//	sso-admin:ListInstances   — used ONLY to discover IdentityStoreId when the
//	                            operator did not configure identity_store_id
//
// The discovery call is deliberately lazy (inside Collect, not the factory):
// the factory stays credential-resolve-only, so the plugin constructs on a
// bare runner and needs no static-Emits() carve-out in the builtin coverage
// test.
//
// What this plugin cannot answer, and why it never guesses:
//   - mfa_enabled — Identity Center exposes no per-user MFA enrollment state
//     in any public API. MFA is enforced either at the instance level or, when
//     the identity source is an external IdP, by that IdP. The field is
//     required by the schema, so it is emitted best-effort false (the same
//     convention internal/sources/gitlab uses for a 2FA flag its token cannot
//     read). False can only ever fail a policy, never pass one — the safe
//     direction. Operators wanting a real MFA verdict bind the identity source
//     itself (okta, azure.entra, gcp.directory).
//   - is_admin — would need a permission-set traversal (ListPermissionSets →
//     ListManagedPoliciesInPermissionSet → ListAccountAssignments). Omitted
//     rather than fabricated as false; a policy filtering on it therefore
//     ERRORS, which is this codebase's intended way to surface a coverage gap.
//   - last_login_at, mfa_factor_count, is_external, is_service_account,
//     employee_id — no signal in the identity store. Omitted, never
//     null/sentinel (the null trap).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md §The
// plugin contract) the plugin caches nothing across Collect calls — including
// the discovered identity store id.
//
// Test injection: the API interface is the single seam; the real adapter wraps
// an *identitystore.Client plus an *ssoadmin.Client, and unit tests inject an
// in-memory fake. L2 replays a go-vcr cassette through the real SDK
// deserializer.
package identitycenter

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	istypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awscfg"
)

// The cross-vendor evidence types this plugin emits. directory_user is the v1
// shape (see the package doc for why not v2); roster_entry lets Identity
// Center serve as the project's authoritative workforce roster.
const (
	EvidenceTypeDirectoryUser = "directory_user"
	EvidenceTypeRosterEntry   = "roster_entry"
)

// SourceID is the registered ID for the aws.identity_center plugin instance.
// The package directory is identitycenter/: multi-word AWS source IDs drop the
// separator in the directory name (cf. aws.password_policy in passwordpolicy/).
const SourceID = "aws.identity_center"

// roster_entry status values (the schema's closed enum).
const (
	rosterActive   = "active"
	rosterInactive = "inactive"
)

// API is the subset of the AWS SDK this plugin uses. Defining it as an
// interface lets tests inject a fake without hitting AWS; the real adapter
// (awsAPI) fans the two methods out to the identitystore and sso-admin
// clients.
type API interface {
	ListUsers(ctx context.Context, params *identitystore.ListUsersInput, optFns ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error)
	ListInstances(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
}

// Plugin is the in-process aws.identity_center source.
type Plugin struct {
	api             API
	region          string
	identityStoreID string
	now             func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	// IdentityStoreID is the `identity_store_id` config key (e.g.
	// "d-1234567890"). Optional: when empty, Collect discovers it via
	// sso-admin:ListInstances. Set it explicitly when the caller's
	// credentials can see more than one Identity Center instance.
	IdentityStoreID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers using
// the real AWS SDK should use NewFromAWS.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:             opts.API,
		region:          opts.Region,
		identityStoreID: strings.TrimSpace(opts.IdentityStoreID),
		now:             now,
	}
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK. The variadic opts
// carry per-instance credential settings (see internal/sources/aws/awscfg);
// credentials are resolved eagerly here so a source listed in `sources:` with
// no usable credentials is a config error before collection, never an empty
// account afterwards.
func NewFromAWS(ctx context.Context, region, identityStoreID string, opts ...awscfg.Options) (*Plugin, error) {
	o := awscfg.Options{Region: region}
	if len(opts) > 0 {
		o = opts[0]
		if o.Region == "" {
			o.Region = region
		}
	}
	cfg, region, err := awscfg.Load(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("aws.identity_center: %w", err)
	}
	return New(Options{
		API: &awsAPI{
			store: identitystore.NewFromConfig(cfg),
			admin: ssoadmin.NewFromConfig(cfg),
		},
		Region:          region,
		IdentityStoreID: identityStoreID,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string {
	return []string{EvidenceTypeDirectoryUser, EvidenceTypeRosterEntry}
}

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the cross-vendor directory_user (v1) shape this plugin emits.
// is_active and mfa_enabled are emitted unconditionally so a policy filtering
// on them always finds them present on every Identity Center record (null-trap
// guard, Invariant #4); every field the identity store cannot answer is
// omitted rather than sentinel-filled. created_at is a pointer so an unknown
// creation time is absent, not reported as year 0001.
type userPayload struct {
	ID          string     `json:"id"`
	Username    string     `json:"username,omitempty"`
	DisplayName string     `json:"display_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

// rosterPayload is the roster_entry shape this plugin emits. Optional strings
// are omitted when empty: the schema requires minLength 1 on each and forbids
// additional properties (data minimisation).
type rosterPayload struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Email        string `json:"email,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	EmployeeType string `json:"employee_type,omitempty"`
	SourceStatus string `json:"source_status,omitempty"`
}

// Collect lists the identity store's users once and emits, per accepted type,
// one directory_user and/or one roster_entry record each. Records are stably
// sorted by ID before return so envelope bytes are stable across runs against
// stable directory state (the two types share a record ID, hence SliceStable).
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantUsers := req.Accepts(EvidenceTypeDirectoryUser)
	wantRoster := req.Accepts(EvidenceTypeRosterEntry)
	if !wantUsers && !wantRoster {
		return nil, fmt.Errorf("aws.identity_center: slot AcceptedTypes %v does not include any of %q",
			req.AcceptedTypes, p.Emits())
	}
	storeID, err := p.resolveIdentityStoreID(ctx)
	if err != nil {
		return nil, err
	}
	users, err := p.listAllUsers(ctx, storeID)
	if err != nil {
		return nil, fmt.Errorf("aws.identity_center: list users: %w", err)
	}
	scope := &core.RecordScope{Account: storeID, Region: p.region}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(users)*2)
	for i := range users {
		u := &users[i]
		id := deref(u.UserId)
		if id == "" {
			continue
		}
		if wantUsers {
			r, err := directoryUserRecord(u, id, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, r)
		}
		if wantRoster {
			r, err := rosterRecord(u, id, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, r)
		}
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// directoryUserRecord builds one directory_user (v1) record from an identity
// store user.
func directoryUserRecord(u *istypes.User, id string, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	email := primaryEmail(u)
	payload := userPayload{
		ID:          id,
		Username:    strings.TrimSpace(deref(u.UserName)),
		DisplayName: displayName(u),
		// The schema constrains email with format:email, so only a
		// plausibly-addressable value is emitted; a non-address identifier is
		// dropped rather than failing schema validation for the whole binding.
		Email: emailOrEmpty(email),
		// See the package doc: Identity Center publishes no per-user MFA
		// state. Best-effort false — it can only fail a policy, never pass one.
		MFAEnabled: false,
		IsActive:   u.UserStatus != istypes.UserStatusDisabled,
		CreatedAt:  u.CreatedAt,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("aws.identity_center: marshal user payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeDirectoryUser,
		ID:          id,
		IdentityKey: strings.ToLower(payload.Email),
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       scope,
	}, nil
}

// rosterRecord builds one roster_entry record from an identity store user.
// A user with no email is still emitted: per the roster_entry contract an
// entry without one cannot vouch for an account, so the accounts that would
// have matched surface as unlinked rather than silently passing.
func rosterRecord(u *istypes.User, id string, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	email := primaryEmail(u)
	raw := string(u.UserStatus)
	payload := rosterPayload{
		ID:          id,
		Status:      rosterStatus(raw),
		Email:       email,
		DisplayName: displayName(u),
		// UserType is the identity store's free-form "kind of user" attribute
		// (SCIM userType) — the same field Okta maps to employee_type.
		EmployeeType: strings.TrimSpace(deref(u.UserType)),
		SourceStatus: strings.TrimSpace(raw),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("aws.identity_center: marshal roster payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeRosterEntry,
		ID:          id,
		IdentityKey: strings.ToLower(payload.Email),
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       scope,
	}, nil
}

// rosterStatus normalizes the identity store's UserStatus to the roster_entry
// enum. ENABLED = the user can sign in. An empty status is what a store that
// predates the attribute returns for every user, and "the whole directory is
// inactive" is not a useful verdict — it is reported active, matching the
// is_active default in directory_user ("absent means assume active").
// Everything else — DISABLED, and any status AWS adds later — is inactive
// (fail-safe: an unknown status never vouches for an account).
func rosterStatus(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(istypes.UserStatusEnabled), "":
		return rosterActive
	default:
		return rosterInactive
	}
}

// resolveIdentityStoreID returns the configured identity store id, or
// discovers it from the single Identity Center instance the caller's
// credentials can see. Discovery lives here rather than in the factory so the
// factory stays credential-resolve-only (see the package doc).
func (p *Plugin) resolveIdentityStoreID(ctx context.Context) (string, error) {
	if p.identityStoreID != "" {
		return p.identityStoreID, nil
	}
	out, err := p.api.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		return "", fmt.Errorf("aws.identity_center: discover identity store: %w", err)
	}
	ids := make([]string, 0, len(out.Instances))
	for i := range out.Instances {
		if id := strings.TrimSpace(deref(out.Instances[i].IdentityStoreId)); id != "" {
			ids = append(ids, id)
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("aws.identity_center: no IAM Identity Center instance found in region %q "+
			"(set sources.\"aws.identity_center\".identity_store_id, or point region at the instance's region)", p.region)
	case 1:
		return ids[0], nil
	default:
		sort.Strings(ids)
		return "", fmt.Errorf("aws.identity_center: %d IAM Identity Center instances visible in region %q; "+
			"set sources.\"aws.identity_center\".identity_store_id to choose one", len(ids), p.region)
	}
}

// listAllUsers pages identitystore:ListUsers to completion.
func (p *Plugin) listAllUsers(ctx context.Context, storeID string) ([]istypes.User, error) {
	var (
		out   []istypes.User
		token *string
	)
	for {
		page, err := p.api.ListUsers(ctx, &identitystore.ListUsersInput{
			IdentityStoreId: &storeID,
			NextToken:       token,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Users...)
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		return out, nil
	}
}

// primaryEmail returns the user's primary email address, falling back to the
// first address carrying a value. Empty when the user has none.
func primaryEmail(u *istypes.User) string {
	var first string
	for i := range u.Emails {
		v := strings.TrimSpace(deref(u.Emails[i].Value))
		if v == "" {
			continue
		}
		if u.Emails[i].Primary {
			return v
		}
		if first == "" {
			first = v
		}
	}
	return first
}

// emailOrEmpty keeps a value only when it is plausibly an email address. The
// directory_user schema declares format:email and the collector validates
// every payload before signing, so a non-address identifier here would fail
// the whole binding rather than one field.
func emailOrEmpty(v string) string {
	at := strings.IndexByte(v, '@')
	if at <= 0 || at == len(v)-1 || strings.ContainsAny(v, " \t") {
		return ""
	}
	if !strings.Contains(v[at+1:], ".") {
		return ""
	}
	return v
}

// displayName picks the most useful single human-readable string, in the order
// the identity store populates them: the explicit display name, the formatted
// name, given+family, then the user name.
func displayName(u *istypes.User) string {
	if v := strings.TrimSpace(deref(u.DisplayName)); v != "" {
		return v
	}
	if u.Name != nil {
		if v := strings.TrimSpace(deref(u.Name.Formatted)); v != "" {
			return v
		}
		v := strings.TrimSpace(strings.TrimSpace(deref(u.Name.GivenName)) + " " + strings.TrimSpace(deref(u.Name.FamilyName)))
		if v != "" {
			return v
		}
	}
	return strings.TrimSpace(deref(u.UserName))
}

// deref dereferences an SDK string pointer, treating nil as empty.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- real AWS SDK adapter ---

// awsAPI fans the plugin's two operations out to the two AWS clients they
// belong to: the identity store's data plane and the Identity Center control
// plane (used only for instance discovery).
type awsAPI struct {
	store *identitystore.Client
	admin *ssoadmin.Client
}

func (a *awsAPI) ListUsers(ctx context.Context, in *identitystore.ListUsersInput, optFns ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error) {
	return a.store.ListUsers(ctx, in, optFns...)
}

func (a *awsAPI) ListInstances(ctx context.Context, in *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	return a.admin.ListInstances(ctx, in, optFns...)
}

var _ core.SourcePlugin = (*Plugin)(nil)
