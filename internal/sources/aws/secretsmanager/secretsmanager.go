// Package secretsmanager implements the aws.secretsmanager source plugin:
// lists AWS Secrets Manager secrets and emits secret evidence records with
// cross-vendor rotation and encryption attributes.
package secretsmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "secret"

// SourceID is the registered ID for the aws.secretsmanager plugin instance.
const SourceID = "aws.secretsmanager"

// hoursPerDay converts a duration to whole days.
const hoursPerDay = 24

// API is the subset of the Secrets Manager client this plugin uses.
type API interface {
	ListSecrets(ctx context.Context, params *awssm.ListSecretsInput, optFns ...func(*awssm.Options)) (*awssm.ListSecretsOutput, error)
}

// Plugin is the in-process aws.secretsmanager source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	Now    func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
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

// NewFromAWS constructs a Plugin backed by the real AWS SDK.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.secretsmanager: load AWS config: %w", err)
	}
	return New(Options{
		API:    awssm.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// secretPayload is the cross-vendor secret shape.
type secretPayload struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	RotationEnabled bool   `json:"rotation_enabled"`
	// KMSEncrypted is true only when the secret is bound to a
	// customer-managed CMK. AWS always encrypts at rest with the default
	// aws/secretsmanager key, but an empty KmsKeyId means "no
	// customer-managed key", which a consuming policy treats as false.
	KMSEncrypted bool `json:"kms_encrypted"`
	NeverRotated bool `json:"never_rotated"`
	// LastRotatedDays is a pointer so it is omitted (not emitted as 0)
	// when the secret has never been rotated; NeverRotated then carries
	// the signal, and the schema no longer uses a -1 sentinel.
	LastRotatedDays *int `json:"last_rotated_days,omitempty"`
}

// Collect lists secrets and returns one secret record per secret.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.secretsmanager: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	secrets, err := p.listAllSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.secretsmanager: list secrets: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(secrets))
	for i := range secrets {
		entry := &secrets[i]
		id := secretID(entry)
		if id == "" {
			continue
		}
		neverRotated := entry.LastRotatedDate == nil
		payload := secretPayload{
			ID:              id,
			Name:            safeString(entry.Name),
			Provider:        "aws",
			RotationEnabled: safeBool(entry.RotationEnabled),
			KMSEncrypted:    safeString(entry.KmsKeyId) != "",
			NeverRotated:    neverRotated,
			LastRotatedDays: lastRotatedDays(entry, now),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.secretsmanager: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (p *Plugin) listAllSecrets(ctx context.Context) ([]smtypes.SecretListEntry, error) {
	var (
		out       []smtypes.SecretListEntry
		nextToken *string
	)
	for {
		page, err := p.api.ListSecrets(ctx, &awssm.ListSecretsInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		out = append(out, page.SecretList...)
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return out, nil
	}
}

// lastRotatedDays returns days since the secret's last rotation, or nil when
// it has never been rotated (the field is then omitted from the payload).
func lastRotatedDays(entry *smtypes.SecretListEntry, now time.Time) *int {
	if entry == nil || entry.LastRotatedDate == nil {
		return nil
	}
	days := int(now.Sub(*entry.LastRotatedDate).Hours() / hoursPerDay)
	return &days
}

// secretID prefers the ARN; some entries only carry a Name.
func secretID(entry *smtypes.SecretListEntry) string {
	if entry == nil {
		return ""
	}
	if arn := safeString(entry.ARN); arn != "" {
		return arn
	}
	return safeString(entry.Name)
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

var _ core.SourcePlugin = (*Plugin)(nil)
