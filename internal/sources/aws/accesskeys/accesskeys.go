// Package accesskeys implements the aws.iam_access_key source plugin:
// lists IAM users in one AWS account, then their programmatic access
// keys, and emits one iam_access_key evidence record per key — suitable
// for SOC 2 CC6 key-hygiene policies (rotation age, unused-key
// detection, never-used-active keys).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the concrete *iam.Client satisfies it, and
// unit tests inject an in-memory fake.
package accesskeys

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

// EvidenceTypeID is the cross-vendor iam_access_key shape this plugin
// emits — one programmatic credential per record. AWS IAM is one of
// several substitutable key sources (GCP service-account keys, Azure
// service-principal credentials).
const EvidenceTypeID = "iam_access_key"

// SourceID is the registered ID for the aws.iam_access_key plugin
// instance.
const SourceID = "aws.iam_access_key"

// API is the subset of the IAM client this plugin uses. Defining it as
// an interface lets tests inject a fake without hitting AWS; the
// concrete *iam.Client satisfies it.
type API interface {
	ListUsers(ctx context.Context, params *awsiam.ListUsersInput, optFns ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error)
	ListAccessKeys(ctx context.Context, params *awsiam.ListAccessKeysInput, optFns ...func(*awsiam.Options)) (*awsiam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, params *awsiam.GetAccessKeyLastUsedInput, optFns ...func(*awsiam.Options)) (*awsiam.GetAccessKeyLastUsedOutput, error)
}

// Plugin is the in-process aws.iam_access_key source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	// Now is injected so tests can produce deterministic CollectedAt and
	// age values. Production callers leave it nil → time.Now().UTC().
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
// default credential chain.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.iam_access_key: load AWS config: %w", err)
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

// keyPayload is the iam_access_key shape this plugin emits.
//
// LastUsedDays is a pointer so it can be OMITTED entirely when the key
// has never been used (never_used == true). Policies that read
// last_used_days must guard on never_used == false; the evaluator errors
// on a referenced-but-absent field by design, so emitting a sentinel
// here would silently mask never-used keys. See the schema's
// last_used_days description.
type keyPayload struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	IsActive     bool   `json:"is_active"`
	AgeDays      int    `json:"age_days"`
	NeverUsed    bool   `json:"never_used"`
	LastUsedDays *int   `json:"last_used_days,omitempty"`
}

// Collect lists IAM users in the configured account, then each user's
// access keys, and returns one iam_access_key record per key. Records
// are sorted by ID before return so envelope bytes are stable across
// runs against stable account state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.iam_access_key: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	users, err := p.listAllUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.iam_access_key: list users: %w", err)
	}
	now := p.now()
	var records []core.EvidenceRecord
	for i := range users {
		u := &users[i]
		name := safeUserName(u)
		if name == "" {
			continue
		}
		keys, err := p.listAccessKeys(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("aws.iam_access_key: list access keys for user %s: %w", name, err)
		}
		for j := range keys {
			rec, err := p.recordForKey(ctx, &keys[j], name, now)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// recordForKey builds one evidence record for a single access key,
// enriching it with last-used data.
func (p *Plugin) recordForKey(ctx context.Context, k *iamtypes.AccessKeyMetadata, userName string, now time.Time) (core.EvidenceRecord, error) {
	keyID := safeKeyID(k)
	lastUsed, err := p.keyLastUsedDate(ctx, keyID)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("aws.iam_access_key: last-used for key %s: %w", keyID, err)
	}
	payload := keyPayload{
		ID:        keyID,
		UserID:    userName,
		IsActive:  k.Status == iamtypes.StatusTypeActive,
		AgeDays:   wholeDaysSince(safeCreateDate(k), now),
		NeverUsed: lastUsed == nil,
	}
	if lastUsed != nil {
		d := wholeDaysSince(*lastUsed, now)
		payload.LastUsedDays = &d
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("aws.iam_access_key: marshal key payload: %w", err)
	}
	return core.EvidenceRecord{
		Type:        EvidenceTypeID,
		ID:          keyID,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
	}, nil
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

func (p *Plugin) listAccessKeys(ctx context.Context, userName string) ([]iamtypes.AccessKeyMetadata, error) {
	var (
		out    []iamtypes.AccessKeyMetadata
		marker *string
	)
	for {
		page, err := p.api.ListAccessKeys(ctx, &awsiam.ListAccessKeysInput{UserName: &userName, Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.AccessKeyMetadata...)
		if page.IsTruncated && page.Marker != nil {
			marker = page.Marker
			continue
		}
		return out, nil
	}
}

// keyLastUsedDate returns the key's last-used timestamp, or nil if the
// key has never been used since IAM began tracking usage.
func (p *Plugin) keyLastUsedDate(ctx context.Context, keyID string) (*time.Time, error) {
	out, err := p.api.GetAccessKeyLastUsed(ctx, &awsiam.GetAccessKeyLastUsedInput{AccessKeyId: &keyID})
	if err != nil {
		return nil, err
	}
	if out == nil || out.AccessKeyLastUsed == nil {
		return nil, nil
	}
	return out.AccessKeyLastUsed.LastUsedDate, nil
}

// wholeDaysSince returns the whole days between t and now. A zero or
// future t yields 0.
func wholeDaysSince(t, now time.Time) int {
	if t.IsZero() {
		return 0
	}
	d := now.Sub(t)
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

func safeKeyID(k *iamtypes.AccessKeyMetadata) string {
	if k == nil || k.AccessKeyId == nil {
		return ""
	}
	return *k.AccessKeyId
}

func safeCreateDate(k *iamtypes.AccessKeyMetadata) time.Time {
	if k == nil || k.CreateDate == nil {
		return time.Time{}
	}
	return *k.CreateDate
}

func safeUserName(u *iamtypes.User) string {
	if u == nil || u.UserName == nil {
		return ""
	}
	return *u.UserName
}

var _ core.SourcePlugin = (*Plugin)(nil)
