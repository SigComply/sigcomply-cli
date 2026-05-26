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
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today —
// the cross-vendor directory_user shape. AWS IAM is one of several
// substitutable directory sources (Okta, GitHub, future Azure AD/LDAP).
const EvidenceTypeID = "directory_user"

// SourceID is the registered ID for the aws.iam plugin instance.
const SourceID = "aws.iam"

// API is the subset of the IAM client this plugin uses. Defining it as
// an interface lets tests inject a fake without hitting AWS; the
// concrete *iam.Client satisfies it.
type API interface {
	ListUsers(ctx context.Context, params *awsiam.ListUsersInput, optFns ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error)
	ListMFADevices(ctx context.Context, params *awsiam.ListMFADevicesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListMFADevicesOutput, error)
}

// Plugin is the in-process aws.iam source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
// Callers using the real AWS SDK should use NewFromAWS.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:    opts.API,
		region: opts.Region,
		now:    now,
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

// userPayload is the directory_user shape this plugin emits. Cross-
// vendor fields (id, display_name, mfa_enabled, is_admin, is_active,
// last_login_at) map to AWS IAM concepts as documented in Collect.
// AWS-specific signals not covered by directory_user v1 (password
// configured vs. access keys only, MFA device serial numbers, attached
// policies) are intentionally not emitted — adding them would push
// vendor specifics back into the rule layer.
type userPayload struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email,omitempty"`
	MFAEnabled  bool      `json:"mfa_enabled"`
	IsAdmin     bool      `json:"is_admin"`
	IsActive    bool      `json:"is_active"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
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
	for i := range users {
		u := &users[i]
		mfa, err := p.userHasMFA(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("aws.iam: mfa for user %s: %w", safeUserName(u), err)
		}
		payload := userPayload{
			ID:          safeUserID(u),
			DisplayName: safeUserName(u),
			MFAEnabled:  mfa,
			IsAdmin:     false, // admin detection (admin group / AdministratorAccess) is deferred — see post-M6 work plan
			IsActive:    true,  // IAM list calls only return active users; pending-deletion is a separate concern not modeled here
			CreatedAt:   safeCreatedAt(u),
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
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
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

func safeCreatedAt(u *iamtypes.User) time.Time {
	if u == nil || u.CreateDate == nil {
		return time.Time{}
	}
	return *u.CreateDate
}

var _ core.SourcePlugin = (*Plugin)(nil)
