// Package iam implements the aws.iam source plugin: lists IAM users
// from one AWS account and emits user_record evidence records suitable
// for SOC 2 user-directory policies (MFA enforcement, inactive users,
// admin coverage, …).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/vault/s3 — the concrete *iam.Client satisfies it, and unit
// tests inject an in-memory fake. The real SDK adapter has no
// integration tests at M6 (deferred — see post-M6 work plan).
package iam

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor directory_user.v2 shape this plugin
// emits — the v1 identity fields plus privileged-access and access-key
// hygiene fields. AWS IAM is one of several substitutable directory
// sources (Okta, GitHub, future Azure AD/LDAP).
const EvidenceTypeID = "directory_user.v2"

// SourceID is the registered ID for the aws.iam plugin instance.
const SourceID = "aws.iam"

// API is the subset of the IAM client this plugin uses. Defining it as
// an interface lets tests inject a fake without hitting AWS; the
// concrete *iam.Client satisfies it.
type API interface {
	ListUsers(ctx context.Context, params *awsiam.ListUsersInput, optFns ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error)
	ListMFADevices(ctx context.Context, params *awsiam.ListMFADevicesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListMFADevicesOutput, error)
	ListAccessKeys(ctx context.Context, params *awsiam.ListAccessKeysInput, optFns ...func(*awsiam.Options)) (*awsiam.ListAccessKeysOutput, error)
	ListAttachedUserPolicies(ctx context.Context, params *awsiam.ListAttachedUserPoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListAttachedUserPoliciesOutput, error)
	ListGroupsForUser(ctx context.Context, params *awsiam.ListGroupsForUserInput, optFns ...func(*awsiam.Options)) (*awsiam.ListGroupsForUserOutput, error)
	ListAttachedGroupPolicies(ctx context.Context, params *awsiam.ListAttachedGroupPoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListAttachedGroupPoliciesOutput, error)
	// GenerateCredentialReport / GetCredentialReport back the synthetic
	// root-account record. The IAM root user is NOT returned by ListUsers,
	// so the only way to assert "root has MFA / root has no access keys"
	// is the account credential report, whose first row (user
	// "<root_account>") carries mfa_active and access_key_*_active.
	// Required IAM permissions: iam:GenerateCredentialReport,
	// iam:GetCredentialReport.
	GenerateCredentialReport(ctx context.Context, params *awsiam.GenerateCredentialReportInput, optFns ...func(*awsiam.Options)) (*awsiam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, params *awsiam.GetCredentialReportInput, optFns ...func(*awsiam.Options)) (*awsiam.GetCredentialReportOutput, error)
}

// adminPolicyName is the AWS-managed policy that grants full
// administrative access. A user holding it directly or via a group is
// treated as an admin for MFA-on-admins coverage.
const adminPolicyName = "AdministratorAccess"

// Plugin is the in-process aws.iam source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
	// sleep waits between credential-report poll attempts. Injectable so
	// tests don't pay real wall-clock delays; defaults to time.Sleep.
	sleep func(time.Duration)
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
	// Sleep is injected by tests to avoid real delays while polling for
	// the credential report. Production callers leave it nil → time.Sleep.
	Sleep func(time.Duration)
}

// New constructs a Plugin around an explicit API implementation.
// Callers using the real AWS SDK should use NewFromAWS.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	return &Plugin{
		api:    opts.API,
		region: opts.Region,
		now:    now,
		sleep:  sleep,
	}
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK using the
// default credential chain. M6 does not exercise this path under
// integration tests; that's tracked in the post-M6 work plan.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.iam: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsiam.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init accepts plugin config (currently just region) but the
// constructor already has it; this is a no-op preserved for symmetry.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// userPayload is the directory_user.v2 shape this plugin emits. The v1
// identity fields map to AWS IAM concepts as documented in Collect; the
// v2 fields (is_root, has_console_access, has_programmatic_access)
// derive from already-available ListUsers data plus a per-user
// ListAccessKeys call.
type userPayload struct {
	ID                    string    `json:"id"`
	DisplayName           string    `json:"display_name"`
	Email                 string    `json:"email,omitempty"`
	MFAEnabled            bool      `json:"mfa_enabled"`
	IsAdmin               bool      `json:"is_admin"`
	IsActive              bool      `json:"is_active"`
	IsRoot                bool      `json:"is_root"`
	HasConsoleAccess      bool      `json:"has_console_access"`
	HasProgrammaticAccess bool      `json:"has_programmatic_access"`
	DirectPolicyCount     int       `json:"direct_policy_count"`
	UnusedDays            int       `json:"unused_days"`
	LastLoginAt           time.Time `json:"last_login_at,omitempty"`
	CreatedAt             time.Time `json:"created_at,omitempty"`
}

// Collect lists IAM users in the configured account and returns one
// user_record per user. Records are sorted by ID before return so
// envelope bytes are stable across runs against stable account state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.iam: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	users, err := p.listAllUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.iam: list users: %w", err)
	}
	records := make([]core.EvidenceRecord, 0, len(users))
	now := p.now()
	// groupAdmin memoizes per-group admin lookups within this Collect call
	// (many users share groups); nothing is cached across Collect calls.
	groupAdmin := map[string]bool{}
	for i := range users {
		u := &users[i]
		mfa, err := p.userHasMFA(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("aws.iam: mfa for user %s: %w", safeUserName(u), err)
		}
		hasKeys, err := p.userHasActiveAccessKey(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("aws.iam: access keys for user %s: %w", safeUserName(u), err)
		}
		isAdmin, directCount, err := p.userPrivilege(ctx, u, groupAdmin)
		if err != nil {
			return nil, fmt.Errorf("aws.iam: privilege check for user %s: %w", safeUserName(u), err)
		}
		payload := userPayload{
			ID:          safeUserID(u),
			DisplayName: safeUserName(u),
			MFAEnabled:  mfa,
			IsAdmin:     isAdmin,
			IsActive:    true,  // IAM list calls only return active users
			IsRoot:      false, // ListUsers never returns root; the synthetic root record is added separately
			// HasConsoleAccess is approximated from PasswordLastUsed: a
			// non-nil value proves the user has (and has used) a console
			// login profile. It can under-report a user who has a login
			// profile but has never signed in. A precise signal needs a
			// per-user GetLoginProfile call; no shipped policy reads this
			// field yet, so the approximation is acceptable for now.
			HasConsoleAccess:      u.PasswordLastUsed != nil,
			HasProgrammaticAccess: hasKeys,
			DirectPolicyCount:     directCount,
			UnusedDays:            unusedDays(u, now),
			CreatedAt:             safeCreatedAt(u),
		}
		if u.PasswordLastUsed != nil {
			payload.LastLoginAt = *u.PasswordLastUsed
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.iam: marshal user payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          safeUserID(u),
			IdentityKey: payload.Email,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	// The IAM root user is not an IAM user and never appears in ListUsers,
	// so without this synthetic record the root-account policies (root MFA,
	// no root access keys — both Critical) filter to zero records and pass
	// vacuously. Emit one is_root:true record built from the account
	// credential report.
	rootRec, err := p.collectRootRecord(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("aws.iam: root account: %w", err)
	}
	records = append(records, rootRec)
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// rootAccountUser is the user-column value of the credential report's
// root-account row.
const rootAccountUser = "<root_account>"

// collectRootRecord builds the synthetic is_root:true directory_user.v2
// record from the account credential report. MFA and access-key state
// come from the report's "<root_account>" row; is_admin is always true
// (root has unrestricted access by definition).
func (p *Plugin) collectRootRecord(ctx context.Context, now time.Time) (core.EvidenceRecord, error) {
	report, err := p.credentialReport(ctx)
	if err != nil {
		return core.EvidenceRecord{}, err
	}
	row, err := parseRootRow(report)
	if err != nil {
		return core.EvidenceRecord{}, err
	}
	payload := userPayload{
		ID:                    rootAccountUser,
		DisplayName:           "root",
		MFAEnabled:            row.mfaActive,
		IsAdmin:               true,
		IsActive:              true,
		IsRoot:                true,
		HasConsoleAccess:      row.passwordEnabled,
		HasProgrammaticAccess: row.accessKey1Active || row.accessKey2Active,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("marshal root payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeID,
		ID:          rootAccountUser,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
	}, nil
}

// credentialReportMaxAttempts bounds the generate→poll loop. AWS caches
// the report for ~4h, so the steady-state path returns on the first Get.
const credentialReportMaxAttempts = 10

// credentialReport returns the raw CSV bytes of the account credential
// report, generating it first if AWS hasn't produced one yet. A report
// is typically ready within a few seconds of GenerateCredentialReport.
func (p *Plugin) credentialReport(ctx context.Context) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < credentialReportMaxAttempts; attempt++ {
		out, err := p.api.GetCredentialReport(ctx, &awsiam.GetCredentialReportInput{})
		if err == nil && len(out.Content) > 0 {
			return out.Content, nil
		}
		lastErr = err
		// No report yet (ReportNotPresent / ReportInProgress): ask AWS to
		// (re)generate, then wait before polling again. A hard permission
		// error here propagates so the policy errors rather than silently
		// skipping the root check.
		if _, gerr := p.api.GenerateCredentialReport(ctx, &awsiam.GenerateCredentialReportInput{}); gerr != nil {
			return nil, fmt.Errorf("generate credential report: %w", gerr)
		}
		p.sleep(2 * time.Second)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("credential report not ready after %d attempts: %w", credentialReportMaxAttempts, lastErr)
	}
	return nil, fmt.Errorf("credential report not ready after %d attempts", credentialReportMaxAttempts)
}

// rootRow is the parsed subset of the credential report's root row.
type rootRow struct {
	mfaActive        bool
	passwordEnabled  bool
	accessKey1Active bool
	accessKey2Active bool
}

// parseRootRow finds the "<root_account>" row in the credential-report
// CSV and extracts the fields the root policies care about. The report
// columns are stable and addressed by header name (order-independent).
func parseRootRow(content []byte) (rootRow, error) {
	r := csv.NewReader(bytes.NewReader(content))
	rows, err := r.ReadAll()
	if err != nil {
		return rootRow{}, fmt.Errorf("parse credential report: %w", err)
	}
	if len(rows) < 2 {
		return rootRow{}, fmt.Errorf("credential report has no data rows")
	}
	col := make(map[string]int, len(rows[0]))
	for i, name := range rows[0] {
		col[name] = i
	}
	field := func(row []string, name string) string {
		idx, ok := col[name]
		if !ok || idx >= len(row) {
			return ""
		}
		return row[idx]
	}
	for _, r := range rows[1:] {
		if field(r, "user") != rootAccountUser {
			continue
		}
		yes := func(name string) bool { return field(r, name) == "true" }
		return rootRow{
			mfaActive:        yes("mfa_active"),
			passwordEnabled:  yes("password_enabled"),
			accessKey1Active: yes("access_key_1_active"),
			accessKey2Active: yes("access_key_2_active"),
		}, nil
	}
	return rootRow{}, fmt.Errorf("credential report has no %q row", rootAccountUser)
}

func (p *Plugin) listAllUsers(ctx context.Context) ([]iamtypes.User, error) {
	var (
		out    []iamtypes.User
		marker *string
	)
	for {
		page, err := p.api.ListUsers(ctx, &awsiam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Users...)
		if page.IsTruncated && page.Marker != nil {
			marker = page.Marker
			continue
		}
		return out, nil
	}
}

func (p *Plugin) userHasMFA(ctx context.Context, u *iamtypes.User) (bool, error) {
	name := safeUserName(u)
	if name == "" {
		return false, nil
	}
	out, err := p.api.ListMFADevices(ctx, &awsiam.ListMFADevicesInput{UserName: &name})
	if err != nil {
		return false, err
	}
	return len(out.MFADevices) > 0, nil
}

// userHasActiveAccessKey reports whether the user has at least one
// active programmatic access key.
func (p *Plugin) userHasActiveAccessKey(ctx context.Context, u *iamtypes.User) (bool, error) {
	name := safeUserName(u)
	if name == "" {
		return false, nil
	}
	out, err := p.api.ListAccessKeys(ctx, &awsiam.ListAccessKeysInput{UserName: &name})
	if err != nil {
		return false, err
	}
	for i := range out.AccessKeyMetadata {
		if out.AccessKeyMetadata[i].Status == iamtypes.StatusTypeActive {
			return true, nil
		}
	}
	return false, nil
}

// userPrivilege returns whether the user holds AdministratorAccess
// (directly or via a group) and the count of policies attached DIRECTLY
// to the user (managed). directCount feeds the no-direct-policies hygiene
// check; group-attached policies are the recommended pattern and are not
// counted here.
func (p *Plugin) userPrivilege(ctx context.Context, u *iamtypes.User, groupAdmin map[string]bool) (isAdmin bool, directCount int, err error) {
	name := safeUserName(u)
	if name == "" {
		return false, 0, nil
	}
	directCount, directAdmin, err := p.userDirectPolicies(ctx, name)
	if err != nil {
		return false, 0, err
	}
	if directAdmin {
		return true, directCount, nil
	}
	viaGroup, err := p.userHasAdminViaGroup(ctx, name, groupAdmin)
	if err != nil {
		return false, 0, err
	}
	return viaGroup, directCount, nil
}

// userDirectPolicies lists the user's directly-attached managed policies,
// returning the count and whether AdministratorAccess is among them.
func (p *Plugin) userDirectPolicies(ctx context.Context, user string) (count int, hasAdmin bool, err error) {
	var marker *string
	for {
		out, err := p.api.ListAttachedUserPolicies(ctx, &awsiam.ListAttachedUserPoliciesInput{
			UserName: &user,
			Marker:   marker,
		})
		if err != nil {
			return 0, false, err
		}
		count += len(out.AttachedPolicies)
		if attachedHasAdmin(out.AttachedPolicies) {
			hasAdmin = true
		}
		if out.IsTruncated && out.Marker != nil {
			marker = out.Marker
			continue
		}
		return count, hasAdmin, nil
	}
}

func (p *Plugin) userHasAdminViaGroup(ctx context.Context, user string, groupAdmin map[string]bool) (bool, error) {
	var marker *string
	for {
		out, err := p.api.ListGroupsForUser(ctx, &awsiam.ListGroupsForUserInput{
			UserName: &user,
			Marker:   marker,
		})
		if err != nil {
			return false, err
		}
		for i := range out.Groups {
			g := safeGroupName(&out.Groups[i])
			if g == "" {
				continue
			}
			admin, ok := groupAdmin[g]
			if !ok {
				admin, err = p.groupHasAdminPolicy(ctx, g)
				if err != nil {
					return false, err
				}
				groupAdmin[g] = admin
			}
			if admin {
				return true, nil
			}
		}
		if out.IsTruncated && out.Marker != nil {
			marker = out.Marker
			continue
		}
		return false, nil
	}
}

func (p *Plugin) groupHasAdminPolicy(ctx context.Context, group string) (bool, error) {
	var marker *string
	for {
		out, err := p.api.ListAttachedGroupPolicies(ctx, &awsiam.ListAttachedGroupPoliciesInput{
			GroupName: &group,
			Marker:    marker,
		})
		if err != nil {
			return false, err
		}
		if attachedHasAdmin(out.AttachedPolicies) {
			return true, nil
		}
		if out.IsTruncated && out.Marker != nil {
			marker = out.Marker
			continue
		}
		return false, nil
	}
}

// attachedHasAdmin reports whether any attached managed policy is
// AdministratorAccess (by name — the AWS-managed policy name is stable).
func attachedHasAdmin(policies []iamtypes.AttachedPolicy) bool {
	for i := range policies {
		if policies[i].PolicyName != nil && *policies[i].PolicyName == adminPolicyName {
			return true
		}
	}
	return false
}

func safeGroupName(g *iamtypes.Group) string {
	if g == nil || g.GroupName == nil {
		return ""
	}
	return *g.GroupName
}

func safeUserName(u *iamtypes.User) string {
	if u == nil || u.UserName == nil {
		return ""
	}
	return *u.UserName
}

func safeUserID(u *iamtypes.User) string {
	if u == nil || u.UserId == nil {
		return safeUserName(u)
	}
	return *u.UserId
}

// unusedDays returns whole days since the user's last console
// authentication. Returns -1 when the user has never signed in to the
// console (PasswordLastUsed nil) — the inactive-accounts policy treats
// -1 (>= 0 false) as "never logged in" and flags it.
func unusedDays(u *iamtypes.User, now time.Time) int {
	if u == nil || u.PasswordLastUsed == nil {
		return -1
	}
	d := int(now.Sub(*u.PasswordLastUsed).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func safeCreatedAt(u *iamtypes.User) time.Time {
	if u == nil || u.CreateDate == nil {
		return time.Time{}
	}
	return *u.CreateDate
}

var _ core.SourcePlugin = (*Plugin)(nil)
