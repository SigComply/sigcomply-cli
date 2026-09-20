// Package identitycenter implements the aws.identity_center source plugin:
// lists the users of an AWS IAM Identity Center (formerly AWS SSO) identity
// store, traverses its permission-set assignments, and emits three
// cross-vendor shapes — directory_user (v1), roster_entry and iam_binding —
// so an estate whose human access runs through Identity Center rather than
// long-lived IAM users is evaluated against the same policies, with zero
// policy changes (Invariant #4, substitutability).
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
// whose typos fail silently. The iam_binding records join on the same email
// through payload.principal_id, so an SSO grant is roster-checkable too.
//
// API surface (two AWS JSON-protocol services):
//
//	identitystore:ListUsers            — the identity store's users (paginated)
//	identitystore:DescribeGroup        — display name of an assigned group
//	identitystore:ListGroupMemberships — members of a group assigned a broadly
//	                                     administrative permission set (only
//	                                     is_admin reads membership, so a
//	                                     non-admin grant never triggers it)
//	sso:ListInstances                  — discovers IdentityStoreId + InstanceArn
//	sso:ListPermissionSets             — the instance's permission sets
//	sso:DescribePermissionSet          — a permission set's name
//	sso:ListManagedPoliciesInPermissionSet          — its AWS managed policies
//	sso:ListAccountsForProvisionedPermissionSet     — accounts it is deployed to
//	sso:ListAccountAssignments         — who holds it in each account
//
// Instance discovery is deliberately lazy (inside Collect, not the factory):
// the factory stays credential-resolve-only, so the plugin constructs on a
// bare runner and needs no static-Emits() carve-out in the builtin coverage
// test.
//
// # The grant traversal, and the two questions it answers separately
//
// A permission set is the Identity Center unit of privilege; an *assignment*
// binds one to a (principal, AWS account) pair. The traversal is
// ListPermissionSets → DescribePermissionSet + ListManagedPoliciesInPermissionSet
// (is this permission set broadly administrative?) → ListAccountsForProvisionedPermissionSet
// → ListAccountAssignments (who holds it, where?).
//
// Two consumers read that traversal, and they want different things:
//
//   - iam_binding records mirror each assignment **as it was made**:
//     principal_type is "user" for a direct assignment and "group" for a group
//     assignment. Group assignments are NOT expanded into per-member records.
//     That is not laziness — the least-privilege policies
//     (iso27001.5.3.no_broad_admin_bindings, iso27001.8.3.no_broad_admin_iam_bindings)
//     are phrased none(principal_type == "user" AND is_broad_admin_role AND
//     NOT has_condition) and their remediation text says to grant admin through
//     groups. Expanding a group grant into member records would report the
//     recommended pattern as a violation of the policy that recommends it.
//     It would also mis-key the roster join, whose account.non_human is derived
//     from principal_type (internal/evaluator/accountlink.go).
//   - directory_user.is_admin asks a different question — "does this person
//     hold elevated privileges?" — which does not care how the grant was made.
//     So is_admin DOES resolve group membership, exactly as
//     internal/sources/aws/iam does (userPrivilege consults group-attached
//     policies for is_admin while direct_policy_count counts only direct ones).
//
// Cost: the traversal is O(permission sets × accounts) API calls, which on a
// large organization is the slowest part of the collection. When the slot asks
// only for directory_user, permission sets that are not broadly administrative
// are skipped before their account/assignment fan-out, since they cannot change
// is_admin. Nothing is cached across Collect calls (KISS-no-DRY,
// docs/architecture/04-source-plugins.md §The plugin contract); the group
// membership and permission-set lookups are memoized only *within* one call,
// the same sanctioned exception aws.iam makes.
//
// Record ids are (permission set, account, principal name), and a principal
// NAME is not unique — Identity Store enforces uniqueness on UserName, not on
// email. Two users sharing a primary email and holding the same permission set
// in the same account build byte-identical records, so the second is dropped:
// keeping both would let the collector's unstable sort reorder them between
// runs and change signed envelope bytes for unchanged directory state. Neither
// person is hidden — both still have their own directory_user record.
//
// A slot asking only for roster_entry skips the traversal entirely and needs
// none of the sso:* permissions — designating Identity Center as the roster
// stays a two-permission operation.
//
// # What this plugin cannot answer, and why it never guesses
//
//   - mfa_enabled — Identity Center exposes no per-user MFA enrollment state
//     in any public API. MFA is enforced either at the instance level or, when
//     the identity source is an external IdP, by that IdP. The field is
//     required by the schema, so it is emitted best-effort false (the same
//     convention internal/sources/gitlab uses for a 2FA flag its token cannot
//     read). False can only ever fail a policy, never pass one — the safe
//     direction. Operators wanting a real MFA verdict bind the identity source
//     itself (okta, azure.entra, gcp.directory).
//   - is_broad_admin_role is a heuristic over the AWS-managed policy named
//     AdministratorAccess (matching aws.iam's attachedHasAdmin) plus a
//     permission-set name containing "admin" (matching gcp.iam's
//     isBroadAdminRole). A permission set that reaches admin only through an
//     inline or customer-managed policy under a name that says nothing —
//     "break-glass", say — reads as not-broad. That is the one under-reporting
//     direction left here; closing it means parsing IAM policy documents, which
//     is a larger change than this type warrants. Documented in
//     docs/guides/configure-sources.md so an operator can name such a set
//     accordingly.
//   - has_condition is emitted false: an Identity Center assignment carries no
//     IAM condition expression the way a GCP binding does. False is the
//     unrestricted reading, so it fails rather than excuses a broad grant.
//   - last_login_at, mfa_factor_count, is_external, is_service_account,
//     employee_id — no signal in the identity store. Omitted, never
//     null/sentinel (the null trap).
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
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/awscfg"
)

// The cross-vendor evidence types this plugin emits. directory_user is the v1
// shape (see the package doc for why not v2); roster_entry lets Identity
// Center serve as the project's authoritative workforce roster; iam_binding
// is one permission-set assignment — the same neutral shape gcp.iam emits for
// a project IAM binding.
const (
	EvidenceTypeDirectoryUser = "directory_user"
	EvidenceTypeRosterEntry   = "roster_entry"
	EvidenceTypeIAMBinding    = "iam_binding"
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
	DescribeGroup(ctx context.Context, params *identitystore.DescribeGroupInput, optFns ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error)
	ListGroupMemberships(ctx context.Context, params *identitystore.ListGroupMembershipsInput, optFns ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error)
	ListInstances(ctx context.Context, params *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
	ListPermissionSets(ctx context.Context, params *ssoadmin.ListPermissionSetsInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error)
	DescribePermissionSet(ctx context.Context, params *ssoadmin.DescribePermissionSetInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error)
	ListManagedPoliciesInPermissionSet(ctx context.Context, params *ssoadmin.ListManagedPoliciesInPermissionSetInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error)
	ListAccountsForProvisionedPermissionSet(ctx context.Context, params *ssoadmin.ListAccountsForProvisionedPermissionSetInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error)
	ListAccountAssignments(ctx context.Context, params *ssoadmin.ListAccountAssignmentsInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error)
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
	return []string{EvidenceTypeDirectoryUser, EvidenceTypeRosterEntry, EvidenceTypeIAMBinding}
}

// Caveats declares the one field this plugin emits without observing it.
// See the package doc: Identity Center publishes no per-user MFA state in any
// public API, so mfa_enabled is emitted best-effort false. The planner turns
// this into a warning when an MFA policy binds this source — without it, an
// estate that SCIM-syncs an IdP into Identity Center silently grades its MFA
// controls on whichever of the two unioned records loses the tie.
//
// Unconditional, unlike the gitlab caveat: no credential and no permission
// makes this readable.
func (*Plugin) Caveats() []core.SourceCaveat {
	return []core.SourceCaveat{{
		EvidenceType: EvidenceTypeDirectoryUser,
		Field:        "mfa_enabled",
		Detail: "AWS publishes no per-user MFA API for Identity Center, so mfa_enabled is " +
			"emitted best-effort false and can only ever fail an MFA policy, never pass one",
	}}
}

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the cross-vendor directory_user (v1) shape this plugin emits.
// is_active, mfa_enabled and is_admin are emitted unconditionally so a policy
// filtering on them always finds them present on every Identity Center record
// (null-trap guard, Invariant #4); every field the identity store cannot
// answer is omitted rather than sentinel-filled. created_at is a pointer so an unknown
// creation time is absent, not reported as year 0001.
type userPayload struct {
	ID          string     `json:"id"`
	Username    string     `json:"username,omitempty"`
	DisplayName string     `json:"display_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	IsAdmin     bool       `json:"is_admin"`
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
// one directory_user and/or one roster_entry record each, plus one iam_binding
// per permission-set assignment when the slot accepts that type. Records are
// stably sorted by ID before return so envelope bytes are stable across runs
// against stable directory state (directory_user and roster_entry share a
// record ID, hence SliceStable).
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantUsers := req.Accepts(EvidenceTypeDirectoryUser)
	wantRoster := req.Accepts(EvidenceTypeRosterEntry)
	wantGrants := req.Accepts(EvidenceTypeIAMBinding)
	if !wantUsers && !wantRoster && !wantGrants {
		return nil, fmt.Errorf("aws.identity_center: slot AcceptedTypes %v does not include any of %q",
			req.AcceptedTypes, p.Emits())
	}
	// The permission-set traversal answers is_admin and produces the
	// iam_binding records, so it runs for either of those types and is
	// skipped entirely for a roster-only slot — designating Identity Center
	// as the roster needs none of the sso:* permissions.
	needGrants := wantUsers || wantGrants
	storeID, instanceARN, err := p.resolveInstance(ctx, needGrants)
	if err != nil {
		return nil, err
	}
	users, err := p.listAllUsers(ctx, storeID)
	if err != nil {
		return nil, fmt.Errorf("aws.identity_center: list users: %w", err)
	}
	now := p.now()
	scope := &core.RecordScope{Account: storeID, Region: p.region}

	grants := &grantIndex{admin: map[string]bool{}}
	if needGrants {
		if grants, err = p.collectGrants(ctx, storeID, instanceARN, users, now, wantGrants); err != nil {
			return nil, err
		}
	}

	records := make([]core.EvidenceRecord, 0, len(users)*2+len(grants.records))
	for i := range users {
		u := &users[i]
		id := deref(u.UserId)
		if id == "" {
			continue
		}
		if wantUsers {
			r, err := directoryUserRecord(u, id, grants.admin[id], now, scope)
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
	records = append(records, grants.records...)
	sort.SliceStable(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// directoryUserRecord builds one directory_user (v1) record from an identity
// store user.
func directoryUserRecord(u *istypes.User, id string, isAdmin bool, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
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
		// Resolved from the permission-set traversal, through group
		// membership as well as direct assignment — "does this person hold
		// elevated privileges" does not care how the grant was made.
		IsAdmin:   isAdmin,
		IsActive:  u.UserStatus != istypes.UserStatusDisabled,
		CreatedAt: u.CreatedAt,
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

// resolveInstance returns the identity store id and, when needARN is set, the
// Identity Center instance ARN that every sso-admin call is scoped by.
//
// With identity_store_id configured and no ARN needed (a roster-only slot)
// this makes no API call at all — the property the factory's
// credential-resolve-only design depends on. When the ARN *is* needed the
// ListInstances call happens regardless, because nothing else publishes the
// ARN; a configured store id then selects among the visible instances instead
// of short-circuiting.
func (p *Plugin) resolveInstance(ctx context.Context, needARN bool) (storeID, instanceARN string, err error) {
	if p.identityStoreID != "" && !needARN {
		return p.identityStoreID, "", nil
	}
	// Paged to completion, not read one page at a time: both decisions below
	// are about how MANY instances are visible, so a dropped page would turn
	// "two instances, refuse to guess" into "one instance, pick it" — the
	// run would then silently audit the wrong directory.
	type instance struct{ storeID, arn string }
	var (
		found []instance
		token *string
	)
	for {
		out, err := p.api.ListInstances(ctx, &ssoadmin.ListInstancesInput{NextToken: token})
		if err != nil {
			return "", "", fmt.Errorf("aws.identity_center: discover identity store: %w", err)
		}
		for i := range out.Instances {
			id := strings.TrimSpace(deref(out.Instances[i].IdentityStoreId))
			if id == "" {
				continue
			}
			found = append(found, instance{storeID: id, arn: strings.TrimSpace(deref(out.Instances[i].InstanceArn))})
		}
		if out.NextToken != nil && *out.NextToken != "" {
			token = out.NextToken
			continue
		}
		break
	}
	sort.Slice(found, func(i, j int) bool { return found[i].storeID < found[j].storeID })
	if p.identityStoreID != "" {
		for _, in := range found {
			if in.storeID == p.identityStoreID {
				return in.storeID, in.arn, nil
			}
		}
		return "", "", fmt.Errorf("aws.identity_center: configured identity_store_id %q is not among the %d instance(s) visible in region %q",
			p.identityStoreID, len(found), p.region)
	}
	switch len(found) {
	case 0:
		return "", "", fmt.Errorf("aws.identity_center: no IAM Identity Center instance found in region %q "+
			"(set sources.\"aws.identity_center\".identity_store_id, or point region at the instance's region)", p.region)
	case 1:
		return found[0].storeID, found[0].arn, nil
	default:
		return "", "", fmt.Errorf("aws.identity_center: %d IAM Identity Center instances visible in region %q; "+
			"set sources.\"aws.identity_center\".identity_store_id to choose one", len(found), p.region)
	}
}

// --- permission-set traversal ---

// adminPolicyName is the AWS-managed policy that grants full administrative
// access. Matched by name, the way internal/sources/aws/iam matches it on an
// IAM user's attached policies — the AWS-managed policy name is stable.
const adminPolicyName = "AdministratorAccess"

// iam_binding principal_type values. The evaluator's roster join derives
// account.non_human from this field (internal/evaluator/accountlink.go), and
// the least-privilege policies filter on principalTypeUser, so these strings
// are the contract — not decoration.
const (
	principalTypeUser  = "user"
	principalTypeGroup = "group"
)

// grantIndex is the output of one permission-set traversal: which identity
// store users hold a broadly-administrative permission set anywhere (directly
// or through a group), and the iam_binding records for the assignments
// themselves. It lives for one Collect call and is never cached across them.
type grantIndex struct {
	admin   map[string]bool
	records []core.EvidenceRecord
	// seen guards against two assignments producing the same record ID.
	// The id is (permission set, account, principal name), and a principal
	// NAME is not guaranteed unique: Identity Store enforces uniqueness on
	// UserName, not on email, and two users sharing a primary email holding
	// the same permission set in the same account would emit byte-identical
	// records. Identical, so dropping one loses nothing — but leaving both
	// would make the collector's (unstable) sort.Slice reorder them between
	// runs, changing signed envelope bytes for unchanged directory state.
	// Both people still appear individually as directory_user records.
	seen map[string]bool
}

// bindingPayload is the cross-vendor iam_binding shape. The four fields after
// has_condition are AWS-specific extras, legal because the schema sets
// additionalProperties: true — the same latitude gcp.iam uses for project_id.
type bindingPayload struct {
	ID               string `json:"id"`
	Role             string `json:"role"`
	PrincipalID      string `json:"principal_id"`
	PrincipalType    string `json:"principal_type"`
	IsBroadAdminRole bool   `json:"is_broad_admin_role"`
	HasCondition     bool   `json:"has_condition"`
	// AWS-specific extras
	AccountID        string `json:"account_id,omitempty"`
	PermissionSetARN string `json:"permission_set_arn,omitempty"`
	IdentityStoreID  string `json:"identity_store_id,omitempty"`
}

// permissionSet is one permission set plus the two derived facts the traversal
// needs: its display name (the iam_binding role) and whether it is broadly
// administrative.
type permissionSet struct {
	arn     string
	name    string
	isAdmin bool
}

// collectGrants walks ListPermissionSets → (DescribePermissionSet +
// ListManagedPoliciesInPermissionSet) → ListAccountsForProvisionedPermissionSet
// → ListAccountAssignments, building the admin set and, when emitRecords is
// set, the iam_binding records.
//
// When emitRecords is false the caller wants only is_admin, so a permission set
// that is not broadly administrative is dropped before its account fan-out —
// it cannot change the answer, and the fan-out is the expensive half.
func (p *Plugin) collectGrants(ctx context.Context, storeID, instanceARN string, users []istypes.User, now time.Time, emitRecords bool) (*grantIndex, error) {
	idx := &grantIndex{admin: map[string]bool{}, seen: map[string]bool{}}
	if instanceARN == "" {
		return nil, fmt.Errorf("aws.identity_center: identity store %q reports no instance ARN; "+
			"permission-set assignments cannot be read without it", storeID)
	}
	// Memoized for this call only (the sanctioned KISS-no-DRY exception that
	// internal/sources/aws/iam makes for its per-group admin lookup): many
	// assignments name the same group.
	emails := userEmails(users)

	sets, err := p.listPermissionSets(ctx, instanceARN)
	if err != nil {
		return nil, err
	}
	memo := &grantMemo{emails: emails, groupNames: map[string]string{}, groupMembers: map[string][]string{}}
	for _, ps := range sets {
		// A permission set that is not broadly administrative cannot change
		// is_admin, so when no iam_binding records are wanted it is dropped
		// before the account/assignment fan-out — the expensive half.
		if !emitRecords && !ps.isAdmin {
			continue
		}
		if err := p.collectSetGrants(ctx, storeID, instanceARN, ps, memo, now, emitRecords, idx); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// grantMemo carries the lookups shared across one traversal: the user id →
// roster-key map and the per-group name/membership caches. It lives for one
// Collect call and is never stored on the Plugin.
type grantMemo struct {
	emails       map[string]string
	groupNames   map[string]string
	groupMembers map[string][]string
}

// collectSetGrants walks one permission set's accounts and assignments,
// recording admin holders and, when asked, the iam_binding records.
func (p *Plugin) collectSetGrants(
	ctx context.Context,
	storeID, instanceARN string,
	ps permissionSet,
	memo *grantMemo,
	now time.Time,
	emitRecords bool,
	idx *grantIndex,
) error {
	accounts, err := p.listProvisionedAccounts(ctx, instanceARN, ps.arn)
	if err != nil {
		return err
	}
	for _, accountID := range accounts {
		assignments, err := p.listAccountAssignments(ctx, instanceARN, accountID, ps.arn)
		if err != nil {
			return err
		}
		for i := range assignments {
			pType, pName, holders, err := p.resolvePrincipal(ctx, storeID, &assignments[i], memo, ps.isAdmin)
			if err != nil {
				return err
			}
			if pType == "" {
				continue
			}
			if ps.isAdmin {
				for _, h := range holders {
					idx.admin[h] = true
				}
			}
			if !emitRecords {
				continue
			}
			rec, err := bindingRecord(ps, accountID, storeID, pType, pName, now, p.region)
			if err != nil {
				return err
			}
			if idx.seen[rec.ID] {
				continue
			}
			idx.seen[rec.ID] = true
			idx.records = append(idx.records, rec)
		}
	}
	return nil
}

// resolvePrincipal maps one assignment's principal to the iam_binding
// principal_type / principal_id pair and to the set of identity store user ids
// that actually hold the privilege. Those two answers differ for a group: the
// binding stays a GROUP principal while the holders are its members, which is
// the whole split described in the package doc.
//
// An empty pType means "skip this assignment": a principal kind AWS adds later
// must not be reported as a user, because "user" is the population the
// least-privilege policies evaluate.
//
// needHolders is false for a permission set that is not broadly
// administrative: nothing reads holders then, so a group's membership is not
// fetched. That keeps identitystore:ListGroupMemberships off the hot path for
// the ordinary non-admin grants that make up most of an estate.
func (p *Plugin) resolvePrincipal(
	ctx context.Context,
	storeID string,
	a *ssotypes.AccountAssignment,
	memo *grantMemo,
	needHolders bool,
) (pType, pName string, holders []string, err error) {
	principalID := strings.TrimSpace(deref(a.PrincipalId))
	if principalID == "" {
		return "", "", nil, nil
	}
	switch a.PrincipalType {
	case ssotypes.PrincipalTypeUser:
		name := memo.emails[principalID]
		if name == "" {
			name = principalID
		}
		return principalTypeUser, name, []string{principalID}, nil
	case ssotypes.PrincipalTypeGroup:
		var members []string
		if needHolders {
			members, err = p.groupMembers(ctx, storeID, principalID, memo.groupMembers)
			if err != nil {
				return "", "", nil, err
			}
		}
		name, err := p.groupName(ctx, storeID, principalID, memo.groupNames)
		if err != nil {
			return "", "", nil, err
		}
		return principalTypeGroup, name, members, nil
	default:
		return "", "", nil, nil
	}
}

// bindingRecord builds one iam_binding record from a permission-set assignment.
// Scope.Account is the AWS account the grant applies *in*, not the identity
// store — a grant belongs to the account it grants access to, and the store id
// is carried in the payload instead.
func bindingRecord(ps permissionSet, accountID, storeID, pType, pName string, now time.Time, region string) (core.EvidenceRecord, error) {
	id := fmt.Sprintf("%s|%s|%s:%s", ps.name, accountID, pType, pName)
	payload := bindingPayload{
		ID:            id,
		Role:          ps.name,
		PrincipalID:   pName,
		PrincipalType: pType,
		// Named AdministratorAccess-bearing or admin-named permission set;
		// see the package doc for the inline-policy gap this leaves.
		IsBroadAdminRole: ps.isAdmin,
		// An Identity Center assignment carries no IAM condition expression.
		// False is the unrestricted reading — it fails rather than excuses a
		// broad grant. Emitted unconditionally: the least-privilege policies
		// read it without an is_set guard, and the conformance harness
		// requires every declared property to be present.
		HasCondition:     false,
		AccountID:        accountID,
		PermissionSetARN: ps.arn,
		IdentityStoreID:  storeID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("aws.identity_center: marshal binding payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeIAMBinding,
		ID:          id,
		IdentityKey: strings.ToLower(pName),
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       &core.RecordScope{Account: accountID, Region: region},
	}, nil
}

// userEmails maps identity store user id → the roster join key: the primary
// email lowercased, absent when the user has none. The caller falls back to
// the user id, which keeps an emailless grant in the checked population as an
// unlinked account rather than dropping it (fail-safe, matching the roster
// contract).
//
// It filters through emailOrEmpty for the same reason directoryUserRecord
// does, and it matters that the two agree: a user whose stored "email" is a
// non-address identifier must present the SAME account.key from their
// directory_user record and from any grant they hold, or the roster join sees
// one person as two identities.
func userEmails(users []istypes.User) map[string]string {
	out := make(map[string]string, len(users))
	for i := range users {
		id := deref(users[i].UserId)
		if id == "" {
			continue
		}
		if email := strings.ToLower(emailOrEmpty(primaryEmail(&users[i]))); email != "" {
			out[id] = email
		}
	}
	return out
}

// listPermissionSets pages sso-admin:ListPermissionSets and resolves each ARN
// to its name and broad-admin verdict.
func (p *Plugin) listPermissionSets(ctx context.Context, instanceARN string) ([]permissionSet, error) {
	var (
		arns  []string
		token *string
	)
	for {
		page, err := p.api.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
			InstanceArn: &instanceARN,
			NextToken:   token,
		})
		if err != nil {
			return nil, fmt.Errorf("aws.identity_center: list permission sets: %w", err)
		}
		for _, arn := range page.PermissionSets {
			// A blank ARN would yield an empty role — the iam_binding id and
			// every violation message are built from it — and the schema has
			// no minLength to catch it.
			if arn = strings.TrimSpace(arn); arn != "" {
				arns = append(arns, arn)
			}
		}
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		break
	}
	sets := make([]permissionSet, 0, len(arns))
	for _, arn := range arns {
		name, err := p.permissionSetName(ctx, instanceARN, arn)
		if err != nil {
			return nil, err
		}
		policies, err := p.managedPolicyNames(ctx, instanceARN, arn)
		if err != nil {
			return nil, err
		}
		sets = append(sets, permissionSet{arn: arn, name: name, isAdmin: isBroadAdminSet(name, policies)})
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].arn < sets[j].arn })
	return sets, nil
}

// permissionSetName returns the permission set's display name, falling back to
// the ARN's last segment (the ps-… id) when the description call returns none —
// the name is the iam_binding role, so it must never be empty.
func (p *Plugin) permissionSetName(ctx context.Context, instanceARN, psARN string) (string, error) {
	out, err := p.api.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn:      &instanceARN,
		PermissionSetArn: &psARN,
	})
	if err != nil {
		return "", fmt.Errorf("aws.identity_center: describe permission set %s: %w", psARN, err)
	}
	if out.PermissionSet != nil {
		if name := strings.TrimSpace(deref(out.PermissionSet.Name)); name != "" {
			return name, nil
		}
	}
	if i := strings.LastIndexByte(psARN, '/'); i >= 0 && i < len(psARN)-1 {
		return psARN[i+1:], nil
	}
	return psARN, nil
}

// managedPolicyNames pages the AWS-managed policies attached to a permission
// set. Customer-managed and inline policies are deliberately not read — see the
// package doc for the gap that leaves.
func (p *Plugin) managedPolicyNames(ctx context.Context, instanceARN, psARN string) ([]string, error) {
	var (
		names []string
		token *string
	)
	for {
		page, err := p.api.ListManagedPoliciesInPermissionSet(ctx, &ssoadmin.ListManagedPoliciesInPermissionSetInput{
			InstanceArn:      &instanceARN,
			PermissionSetArn: &psARN,
			NextToken:        token,
		})
		if err != nil {
			return nil, fmt.Errorf("aws.identity_center: list managed policies for %s: %w", psARN, err)
		}
		for i := range page.AttachedManagedPolicies {
			names = append(names, strings.TrimSpace(deref(page.AttachedManagedPolicies[i].Name)))
		}
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		return names, nil
	}
}

// listProvisionedAccounts pages the AWS accounts a permission set is deployed
// to. This call is what makes ListAccountAssignments reachable without AWS
// Organizations access — that operation requires an account id, and this is the
// only read-only way to learn which ones apply.
func (p *Plugin) listProvisionedAccounts(ctx context.Context, instanceARN, psARN string) ([]string, error) {
	var (
		out   []string
		token *string
	)
	for {
		page, err := p.api.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{
			InstanceArn:      &instanceARN,
			PermissionSetArn: &psARN,
			NextToken:        token,
		})
		if err != nil {
			return nil, fmt.Errorf("aws.identity_center: list accounts for permission set %s: %w", psARN, err)
		}
		out = append(out, page.AccountIds...)
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		sort.Strings(out)
		return out, nil
	}
}

// listAccountAssignments pages the principals holding one permission set in one
// account.
func (p *Plugin) listAccountAssignments(ctx context.Context, instanceARN, accountID, psARN string) ([]ssotypes.AccountAssignment, error) {
	var (
		out   []ssotypes.AccountAssignment
		token *string
	)
	for {
		page, err := p.api.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
			InstanceArn:      &instanceARN,
			AccountId:        &accountID,
			PermissionSetArn: &psARN,
			NextToken:        token,
		})
		if err != nil {
			return nil, fmt.Errorf("aws.identity_center: list assignments for %s in account %s: %w", psARN, accountID, err)
		}
		out = append(out, page.AccountAssignments...)
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		return out, nil
	}
}

// groupMembers returns the identity store user ids in a group, memoized for the
// life of one Collect call.
func (p *Plugin) groupMembers(ctx context.Context, storeID, groupID string, memo map[string][]string) ([]string, error) {
	if members, ok := memo[groupID]; ok {
		return members, nil
	}
	var (
		members []string
		token   *string
	)
	for {
		page, err := p.api.ListGroupMemberships(ctx, &identitystore.ListGroupMembershipsInput{
			IdentityStoreId: &storeID,
			GroupId:         &groupID,
			NextToken:       token,
		})
		if err != nil {
			return nil, fmt.Errorf("aws.identity_center: list members of group %s: %w", groupID, err)
		}
		for i := range page.GroupMemberships {
			if m, ok := page.GroupMemberships[i].MemberId.(*istypes.MemberIdMemberUserId); ok && m != nil {
				if v := strings.TrimSpace(m.Value); v != "" {
					members = append(members, v)
				}
			}
		}
		if page.NextToken != nil && *page.NextToken != "" {
			token = page.NextToken
			continue
		}
		break
	}
	sort.Strings(members)
	memo[groupID] = members
	return members, nil
}

// groupName returns a group's display name, memoized for the life of one
// Collect call. It falls back to the group id: principal_id must never be
// empty, and a GUID is still an actionable pointer in a violation message.
func (p *Plugin) groupName(ctx context.Context, storeID, groupID string, memo map[string]string) (string, error) {
	if name, ok := memo[groupID]; ok {
		return name, nil
	}
	out, err := p.api.DescribeGroup(ctx, &identitystore.DescribeGroupInput{
		IdentityStoreId: &storeID,
		GroupId:         &groupID,
	})
	if err != nil {
		return "", fmt.Errorf("aws.identity_center: describe group %s: %w", groupID, err)
	}
	name := strings.TrimSpace(deref(out.DisplayName))
	if name == "" {
		name = groupID
	}
	memo[groupID] = name
	return name, nil
}

// isBroadAdminSet reports whether a permission set grants account-wide admin.
// Two signals, both deliberately conservative in the over-reporting direction:
// the AWS-managed AdministratorAccess policy attached (the aws.iam test), or a
// name containing "admin" (the gcp.iam test). Over-reporting fails a control;
// under-reporting would pass one, which is the direction this codebase treats
// as the worst available error.
func isBroadAdminSet(name string, managedPolicies []string) bool {
	for _, pol := range managedPolicies {
		if pol == adminPolicyName {
			return true
		}
	}
	return strings.Contains(strings.ToLower(name), "admin")
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

func (a *awsAPI) DescribeGroup(ctx context.Context, in *identitystore.DescribeGroupInput, optFns ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error) {
	return a.store.DescribeGroup(ctx, in, optFns...)
}

func (a *awsAPI) ListGroupMemberships(ctx context.Context, in *identitystore.ListGroupMembershipsInput, optFns ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error) {
	return a.store.ListGroupMemberships(ctx, in, optFns...)
}

func (a *awsAPI) ListInstances(ctx context.Context, in *ssoadmin.ListInstancesInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	return a.admin.ListInstances(ctx, in, optFns...)
}

func (a *awsAPI) ListPermissionSets(ctx context.Context, in *ssoadmin.ListPermissionSetsInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	return a.admin.ListPermissionSets(ctx, in, optFns...)
}

func (a *awsAPI) DescribePermissionSet(ctx context.Context, in *ssoadmin.DescribePermissionSetInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	return a.admin.DescribePermissionSet(ctx, in, optFns...)
}

func (a *awsAPI) ListManagedPoliciesInPermissionSet(ctx context.Context, in *ssoadmin.ListManagedPoliciesInPermissionSetInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error) {
	return a.admin.ListManagedPoliciesInPermissionSet(ctx, in, optFns...)
}

func (a *awsAPI) ListAccountsForProvisionedPermissionSet(ctx context.Context, in *ssoadmin.ListAccountsForProvisionedPermissionSetInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	return a.admin.ListAccountsForProvisionedPermissionSet(ctx, in, optFns...)
}

func (a *awsAPI) ListAccountAssignments(ctx context.Context, in *ssoadmin.ListAccountAssignmentsInput, optFns ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	return a.admin.ListAccountAssignments(ctx, in, optFns...)
}

var _ core.SourcePlugin = (*Plugin)(nil)
