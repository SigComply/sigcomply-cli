// Package s3 implements the aws.s3 source plugin: lists S3 buckets in
// one AWS account and emits s3_bucket evidence records carrying the
// security-relevant default-encryption attributes that SOC 2 CC6.7
// policies consume.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by the
// aws.iam plugin — the concrete *s3.Client satisfies it, and unit tests
// inject an in-memory fake. The real SDK adapter has no integration
// tests at M7 (deferred — see post-M6 work plan).
package s3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "s3_bucket"

// SourceID is the registered ID for the aws.s3 plugin instance.
const SourceID = "aws.s3"

// API is the subset of the S3 client this plugin uses. Defining it as an
// interface lets tests inject a fake without hitting AWS.
type API interface {
	ListBuckets(ctx context.Context, params *awss3.ListBucketsInput, optFns ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, params *awss3.GetBucketEncryptionInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error)
}

// Plugin is the in-process aws.s3 source.
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
// default credential chain. No integration test exercises this path.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.s3: load AWS config: %w", err)
	}
	return New(Options{
		API:    awss3.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// bucketPayload is the shape of the JSON payload inside each s3_bucket.
type bucketPayload struct {
	Name              string    `json:"name"`
	Region            string    `json:"region,omitempty"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	EncryptionEnabled bool      `json:"encryption_enabled"`
	SSEAlgorithm      string    `json:"sse_algorithm,omitempty"`
	KMSKeyID          string    `json:"kms_key_id,omitempty"`
}

// Collect lists S3 buckets in the configured account and returns one
// s3_bucket record per bucket. Records are sorted by ID before return
// so envelope bytes are stable across runs against stable account
// state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.s3: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	out, err := p.api.ListBuckets(ctx, &awss3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.s3: list buckets: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(out.Buckets))
	for i := range out.Buckets {
		b := &out.Buckets[i]
		name := safeBucketName(b)
		if name == "" {
			continue
		}
		enc, alg, keyID, err := p.bucketEncryption(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("aws.s3: encryption for bucket %s: %w", name, err)
		}
		payload := bucketPayload{
			Name:              name,
			Region:            safeBucketRegion(b, p.region),
			CreatedAt:         safeCreatedAt(b),
			EncryptionEnabled: enc,
			SSEAlgorithm:      alg,
			KMSKeyID:          keyID,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.s3: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          name,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// bucketEncryption returns (enabled, algorithm, kmsKeyID, error). A
// missing default-encryption configuration is reported as
// `ServerSideEncryptionConfigurationNotFoundError` by S3; we treat that
// as "encryption disabled" rather than a fatal error so policies see a
// clean fail signal.
func (p *Plugin) bucketEncryption(ctx context.Context, name string) (enabled bool, algorithm, kmsKeyID string, err error) {
	out, err := p.api.GetBucketEncryption(ctx, &awss3.GetBucketEncryptionInput{Bucket: &name})
	if err != nil {
		if isEncryptionNotFound(err) {
			return false, "", "", nil
		}
		return false, "", "", err
	}
	if out == nil || out.ServerSideEncryptionConfiguration == nil {
		return false, "", "", nil
	}
	for i := range out.ServerSideEncryptionConfiguration.Rules {
		rule := &out.ServerSideEncryptionConfiguration.Rules[i]
		if rule.ApplyServerSideEncryptionByDefault == nil {
			continue
		}
		def := rule.ApplyServerSideEncryptionByDefault
		alg := string(def.SSEAlgorithm)
		keyID := ""
		if def.KMSMasterKeyID != nil {
			keyID = *def.KMSMasterKeyID
		}
		return alg != "", alg, keyID, nil
	}
	return false, "", "", nil
}

// isEncryptionNotFound recognizes the documented "no default encryption"
// API error and lets us model it as a payload boolean rather than a
// hard error. We avoid depending on a typed error variant since the v2
// SDK exposes this as a generic API error code.
func isEncryptionNotFound(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError"
	}
	return false
}

func safeBucketName(b *s3types.Bucket) string {
	if b == nil || b.Name == nil {
		return ""
	}
	return *b.Name
}

func safeBucketRegion(b *s3types.Bucket, fallback string) string {
	if b != nil && b.BucketRegion != nil && *b.BucketRegion != "" {
		return *b.BucketRegion
	}
	return fallback
}

func safeCreatedAt(b *s3types.Bucket) time.Time {
	if b == nil || b.CreationDate == nil {
		return time.Time{}
	}
	return *b.CreationDate
}

var _ core.SourcePlugin = (*Plugin)(nil)
