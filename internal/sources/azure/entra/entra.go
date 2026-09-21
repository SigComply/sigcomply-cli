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
// password_policy.v2 uses a fourth, independent read — GET /domains — and
// needs the Domain.Read.All application permission (no P1/P2 license). It
// is the narrowest of the four: Entra exposes exactly ONE tenant-settable
// password attribute, the per-domain validity period, so a record carries
// expiry and a not_configurable list and nothing else. See
// collectPasswordPolicies for why nothing more may be emitted.
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
// emits; EvidenceTypeRosterEntry is the cross-vendor workforce-roster type;
// EvidenceTypePasswordPolicy is the cross-vendor password-rule type (v2 only
// — see collectPasswordPolicies for why v1 was unfillable here).
const (
	EvidenceTypeID             = "directory_user"
	EvidenceTypeRosterEntry    = "roster_entry"
	EvidenceTypePasswordPolicy = "password_policy.v2"
)

// The password_policy.v2 vocabulary this plugin writes. Spelled as named
// constants because each one is a claim: "entra" is the enforcing system,
// "domain" is the population one record governs (Entra's password validity
// period is a per-domain setting, unlike AWS's per-account singleton), and
// the three not_configurable entries name the attributes Microsoft Graph
// exposes no tenant setting for at all.
const (
	passwordPolicyProvider    = "entra"
	scopeDomain               = "domain"
	notConfigurableMinLength  = "min_length"
	notConfigurableReuse      = "reuse"
	notConfigurableComplexity = "complexity"
)

// Graph's two documented values for domain.authenticationType. "Managed"
// means Microsoft Entra ID itself authenticates the domain's users;
// "Federated" means an external identity provider (typically on-premises
// AD via AD FS) does, and therefore that the external provider — not
// Entra — enforces whatever password rule is in force there.
const (
	authTypeManaged   = "Managed"
	authTypeFederated = "Federated"
)

// passwordNeverExpiresSentinel is Microsoft's documented encoding of
// "passwords in this domain never expire": Int32.MaxValue, the value its
// own tooling tells an administrator to set
// (Update-MgDomain -PasswordValidityPeriodInDays 2147483647). It is a
// sentinel, not a duration, and must never reach a clause as one.
const passwordNeverExpiresSentinel = 2147483647

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

// Domain is one entry of GET /domains, reduced to the three fields that
// decide what — if anything — this tenant can be said to enforce about
// password expiry for the identities in that domain.
type Domain struct {
	// ID is the domain name; Graph keys the domain resource on it.
	ID string
	// IsVerified reports whether domain ownership was proven. An
	// unverified domain cannot be used to sign in, so its settings govern
	// nobody.
	IsVerified bool
	// AuthenticationType is "Managed" or "Federated" (see the constants).
	AuthenticationType string
	// PasswordValidityPeriodInDays is nil when Graph reported no value.
	// A pointer because the difference between "unset" and a number
	// matters: Microsoft documents a 90-day fallback for the unset case,
	// and that documented number is not a measurement of this tenant.
	PasswordValidityPeriodInDays *int32
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
	// ListDomains lists the tenant's domains, which is where Entra keeps
	// the one password attribute it lets a tenant configure. Needs the
	// Domain.Read.All application permission; no P1/P2 license.
	ListDomains(ctx context.Context) ([]Domain, error)
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
func (*Plugin) Emits() []string {
	return []string{EvidenceTypeID, EvidenceTypeRosterEntry, EvidenceTypePasswordPolicy}
}

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

// passwordPolicyPayload is the canonical password_policy.v2 shape as Entra
// can fill it, which is: barely. The json tags match the AWS and Okta
// emitters' exactly — policies bind to the evidence type, never to a
// vendor — and every field those two carry and this one does not is
// omitted rather than zeroed.
//
// MaxAgeDays is a pointer so "Graph reported no validity period" stays
// distinguishable from an observed zero. Zero is a real answer in this
// schema ("an observed no-expiry", which is how the never-expires
// sentinel below arrives), so a nil must not collapse into it.
//
// NotConfigurable is a constant for this source rather than something
// read: it is a statement about Graph's API surface, not a measurement,
// which is precisely why the VALUES it names stay absent.
type passwordPolicyPayload struct {
	ID              string   `json:"id"`
	Provider        string   `json:"provider"`
	Scope           string   `json:"scope"`
	MaxAgeDays      *int     `json:"max_age_days,omitempty"`
	NotConfigurable []string `json:"not_configurable"`
}

// collectPasswordPolicies emits one password_policy.v2 record per VERIFIED
// domain: Entra's password validity period is a per-domain setting, so a
// tenant with three verified domains genuinely has three answers, and the
// consuming clauses quantify `all` over them ("every password policy in
// force meets the bar"). Unverified domains are skipped — ownership was
// never proven, nobody can sign in with one, and a finding about a rule
// that is not in force is a false finding (the same reason Okta skips
// INACTIVE policies).
//
// WHAT THIS EMITS, AND WHY IT IS SO LITTLE.
//
// Microsoft Graph answers exactly one password question about a tenant:
// domain.passwordValidityPeriodInDays. Minimum length, password history
// and the character-class rule are not tenant settings at all for
// cloud-only accounts, so there is no API to read them from — which is
// what not_configurable records. The alternative, writing Microsoft's
// documented constants (8 characters, "3 of 4 character classes") into
// the payload, would sign a value read from a manual into an
// EvidenceEnvelope as though it had been measured in this tenant. That is
// the fabrication password_policy.v2 exists to make unnecessary: absence
// means THIS SOURCE DID NOT OBSERVE A VALUE, and not_configurable says
// why the absence is structural rather than an unread field.
//
// complexity_model: "fixed" was considered and deliberately NOT emitted,
// even though the schema names Entra's character-class rule as its
// example of the fixed arm. Two things rule it out. (a) It is legitimate
// only for a rule the tenant CANNOT change, and Entra's is changeable:
// user.passwordPolicies accepts the documented value
// "DisableStrongPassword", which turns the complexity requirement off for
// that account, and in a federated or password-hash-synced domain the
// rule in force is the external directory's, which Graph does not expose
// at all. A "constant true of every tenant by construction" it is not.
// (b) Emitting it would make both password_complexity policies (SOC 2
// CC6.1 and ISO 8.5) pass for every Entra tenant unconditionally — a
// green tick earned by a string constant in this file rather than by
// anything read from the customer. With complexity absent, those clauses
// filter the record out of scope and the run reports a vacuous clause,
// which is the honest "nothing here was examined".
//
// Lockout is not emitted either, and not because it is unreadable:
// Graph's groupSettings "Password Rule Settings" template does carry a
// lockout threshold and duration. password_policy.v2 has no lockout field
// and no shipped policy reads one, so emitting it would add a Graph call,
// a permission and signed bytes that nothing consumes — the same reason a
// source caveat nobody reads is noise. If a lockout clause is ever
// written, the schema gains the field first.
func (p *Plugin) collectPasswordPolicies(ctx context.Context) ([]core.EvidenceRecord, error) {
	domains, err := p.api.ListDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.entra: list domains: %w", err)
	}
	scope := p.scope()
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(domains))
	for i := range domains {
		d := &domains[i]
		if !d.IsVerified {
			continue
		}
		body, err := json.Marshal(passwordPolicyPayload{
			ID:         d.ID,
			Provider:   passwordPolicyProvider,
			Scope:      scopeDomain,
			MaxAgeDays: maxAgeDays(d),
			NotConfigurable: []string{
				notConfigurableMinLength, notConfigurableReuse, notConfigurableComplexity,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("azure.entra: marshal password policy payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypePasswordPolicy,
			ID:          d.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       scope,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// maxAgeDays translates Graph's validity period into the schema's
// max_age_days, or returns nil when there is nothing honest to say.
//
// Two translations happen here, both of them the plugin's job rather than
// a clause's (Invariant #4: vendor→canonical mapping lives in the source,
// and policy logic must never contain a vendor sentinel or a null guard).
//
//  1. The never-expires sentinel becomes 0. Microsoft encodes "passwords
//     in this domain never expire" as Int32.MaxValue; the schema encodes
//     the same fact as max_age_days 0 — "an observed no-expiry, not
//     unknown" — which is also what AWS and Okta emit for it. Passing the
//     sentinel through instead would report a 2-billion-day rotation
//     period and fail the 90-day clause, giving an Entra tenant a
//     different verdict from an AWS account in the identical posture,
//     which is exactly what a cloud-neutral type exists to prevent. It
//     does mean a never-expiring tenant PASSES soc2.cc6.1.password_expiry_90d
//     — deliberately, by that clause's own documented NIST 800-63B
//     rationale that event-driven rotation is the better practice.
//
//  2. A federated domain reports nothing. Its users authenticate against
//     an external identity provider, so whatever number sits in Entra's
//     field is not the rule in force, and emitting it would assert an
//     expiry that nothing enforces. The record is still emitted — the
//     domain exists and an auditor should see that Entra does not govern
//     its passwords — it simply carries no expiry claim, and the expiry
//     clause's is_set guard filters it out of scope.
//
// A nil period is likewise left absent: Microsoft documents 90 days as
// the fallback when the value is unset, and that documented number
// describes the product, not this tenant.
func maxAgeDays(d *Domain) *int {
	if d.PasswordValidityPeriodInDays == nil || !strings.EqualFold(d.AuthenticationType, authTypeManaged) {
		return nil
	}
	days := int(*d.PasswordValidityPeriodInDays)
	if days == passwordNeverExpiresSentinel {
		days = 0
	}
	return &days
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

// graphDomain is the /domains projection the password policy reads.
// passwordValidityPeriodInDays is a pointer so a JSON null stays nil
// rather than decoding to a zero that means "no expiry".
type graphDomain struct {
	ID                           string `json:"id"`
	IsVerified                   bool   `json:"isVerified"`
	AuthenticationType           string `json:"authenticationType"`
	PasswordValidityPeriodInDays *int32 `json:"passwordValidityPeriodInDays"`
}

// domainsPath is the domain listing. Deliberately no $select: the domain
// resource carries no identity (domain names and platform flags), so
// there is nothing to minimize, and which OData parameters /domains
// honors is not something this repo can verify without a tenant — an
// unsupported $select would fail the whole read for no benefit.
const domainsPath = "/domains"

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

// ListDomains pages GET /domains. It needs only the Domain.Read.All
// application permission and no Entra ID P1/P2 license, so it is
// independent of the registration report the directory_user read depends
// on — a tenant that cannot answer MFA can still answer expiry.
func (r *realGraph) ListDomains(ctx context.Context) ([]Domain, error) {
	token, err := r.token(ctx)
	if err != nil {
		return nil, err
	}
	var out []Domain
	err = graphList(ctx, r, token, r.base+domainsPath, func(d *graphDomain) {
		out = append(out, Domain{
			ID:                           d.ID,
			IsVerified:                   d.IsVerified,
			AuthenticationType:           d.AuthenticationType,
			PasswordValidityPeriodInDays: d.PasswordValidityPeriodInDays,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("list domains (needs the Domain.Read.All permission): %w", err)
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
