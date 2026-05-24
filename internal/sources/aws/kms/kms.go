// Package kms implements the aws.kms source plugin: lists KMS keys in
// one AWS account and emits kms_key evidence records carrying the
// rotation and manager attributes that SOC 2 CC6.7 policies consume.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by the
// aws.iam plugin — the concrete *kms.Client satisfies it, and unit tests
// inject an in-memory fake. The real SDK adapter has no integration
// tests at M7 (deferred — see post-M6 work plan).
package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "kms_key"

// SourceID is the registered ID for the aws.kms plugin instance.
const SourceID = "aws.kms"

// API is the subset of the KMS client this plugin uses.
type API interface {
	ListKeys(ctx context.Context, params *awskms.ListKeysInput, optFns ...func(*awskms.Options)) (*awskms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, params *awskms.DescribeKeyInput, optFns ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *awskms.GetKeyRotationStatusInput, optFns ...func(*awskms.Options)) (*awskms.GetKeyRotationStatusOutput, error)
}

// Plugin is the in-process aws.kms source.
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

// NewFromAWS constructs a Plugin backed by the real AWS SDK.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.kms: load AWS config: %w", err)
	}
	return New(Options{
		API:    awskms.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// keyPayload is the shape of the JSON payload inside each kms_key.
type keyPayload struct {
	KeyID             string `json:"key_id"`
	ARN               string `json:"arn,omitempty"`
	KeyManager        string `json:"key_manager"`
	IsCustomerManaged bool   `json:"is_customer_managed"`
	Enabled           bool   `json:"enabled"`
	RotationEnabled   bool   `json:"rotation_enabled"`
}

// Collect lists KMS keys in the configured account and returns one
// kms_key record per key.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.kms: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	keys, err := p.listAllKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.kms: list keys: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(keys))
	for i := range keys {
		k := &keys[i]
		keyID := safeKeyID(k)
		if keyID == "" {
			continue
		}
		desc, err := p.api.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: &keyID})
		if err != nil {
			return nil, fmt.Errorf("aws.kms: describe key %s: %w", keyID, err)
		}
		md := safeKeyMetadata(desc)
		payload := keyPayload{
			KeyID:             keyID,
			ARN:               safeARN(md),
			KeyManager:        string(safeKeyManager(md)),
			IsCustomerManaged: safeKeyManager(md) == kmstypes.KeyManagerTypeCustomer,
			Enabled:           md != nil && md.Enabled,
		}
		// Rotation is only meaningful for customer-managed keys; for AWS-
		// managed keys the API rejects the call. Skipping the call there
		// keeps the plugin from emitting confusing errors.
		if payload.IsCustomerManaged {
			rot, err := p.api.GetKeyRotationStatus(ctx, &awskms.GetKeyRotationStatusInput{KeyId: &keyID})
			if err != nil {
				return nil, fmt.Errorf("aws.kms: rotation status for %s: %w", keyID, err)
			}
			payload.RotationEnabled = rot != nil && rot.KeyRotationEnabled
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.kms: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          keyID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (p *Plugin) listAllKeys(ctx context.Context) ([]kmstypes.KeyListEntry, error) {
	var (
		out    []kmstypes.KeyListEntry
		marker *string
	)
	for {
		page, err := p.api.ListKeys(ctx, &awskms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Keys...)
		if page.Truncated && page.NextMarker != nil {
			marker = page.NextMarker
			continue
		}
		return out, nil
	}
}

func safeKeyID(k *kmstypes.KeyListEntry) string {
	if k == nil || k.KeyId == nil {
		return ""
	}
	return *k.KeyId
}

func safeKeyMetadata(out *awskms.DescribeKeyOutput) *kmstypes.KeyMetadata {
	if out == nil {
		return nil
	}
	return out.KeyMetadata
}

func safeARN(md *kmstypes.KeyMetadata) string {
	if md == nil || md.Arn == nil {
		return ""
	}
	return *md.Arn
}

func safeKeyManager(md *kmstypes.KeyMetadata) kmstypes.KeyManagerType {
	if md == nil {
		return ""
	}
	return md.KeyManager
}

var _ core.SourcePlugin = (*Plugin)(nil)
