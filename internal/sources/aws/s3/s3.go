// Package s3 implements the aws.s3 source plugin: lists S3 buckets in
// one AWS account and emits object_storage_bucket evidence records
// — the cross-vendor shape policies use across S3, GCS, Azure Blob,
// and S3-compatible stores. AWS-specific encryption, public-access,
// and versioning configuration is normalized into the boolean fields
// the cross-vendor schema declares.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by the
// aws.iam plugin — the concrete *s3.Client satisfies it, and unit tests
// inject an in-memory fake. The real SDK adapter has no integration
// tests today (deferred — see post-M6 work plan).
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

// EvidenceTypeID is the cross-vendor object_storage_bucket shape.
// AWS S3 is one of several substitutable object-storage sources (GCS,
// Azure Blob, MinIO/S3-compatible).
const EvidenceTypeID = "object_storage_bucket"

// SourceID is the registered ID for the aws.s3 plugin instance.
const SourceID = "aws.s3"

// API is the subset of the S3 client this plugin uses. Defining it as an
// interface lets tests inject a fake without hitting AWS.
type API interface {
	ListBuckets(ctx context.Context, params *awss3.ListBucketsInput, optFns ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, params *awss3.GetBucketEncryptionInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *awss3.GetPublicAccessBlockInput, optFns ...func(*awss3.Options)) (*awss3.GetPublicAccessBlockOutput, error)
	GetBucketVersioning(ctx context.Context, params *awss3.GetBucketVersioningInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketVersioningOutput, error)
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

// bucketPayload is the object_storage_bucket shape this plugin emits.
// AWS-specific signals not covered by the cross-vendor schema v1
// (Object Ownership controls, bucket policy text, ACL details) are
// intentionally omitted; adding them is additive.
type bucketPayload struct {
	Name                    string    `json:"name"`
	RegionOrLocation        string    `json:"region_or_location,omitempty"`
	EncryptionAtRestEnabled bool      `json:"encryption_at_rest_enabled"`
	KMSManaged              bool      `json:"kms_managed,omitempty"`
	KMSKeyID                string    `json:"kms_key_id,omitempty"`
	PublicAccessBlocked     bool      `json:"public_access_blocked"`
	VersioningEnabled       bool      `json:"versioning_enabled,omitempty"`
	CreatedAt               time.Time `json:"created_at,omitempty"`
}

// Collect lists S3 buckets in the configured account and returns one
// object_storage_bucket record per bucket. Records are sorted by ID
// before return so envelope bytes are stable across runs against
// stable account state.
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
		enc, kmsManaged, keyID, err := p.bucketEncryption(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("aws.s3: encryption for bucket %s: %w", name, err)
		}
		blocked, err := p.bucketPublicAccessBlocked(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("aws.s3: public-access-block for bucket %s: %w", name, err)
		}
		versioning, err := p.bucketVersioningEnabled(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("aws.s3: versioning for bucket %s: %w", name, err)
		}
		payload := bucketPayload{
			Name:                    name,
			RegionOrLocation:        safeBucketRegion(b, p.region),
			EncryptionAtRestEnabled: enc,
			KMSManaged:              kmsManaged,
			KMSKeyID:                keyID,
			PublicAccessBlocked:     blocked,
			VersioningEnabled:       versioning,
			CreatedAt:               safeCreatedAt(b),
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

// bucketEncryption returns (encryptionEnabled, kmsManaged, kmsKeyID, error).
// A missing default-encryption configuration is reported as
// `ServerSideEncryptionConfigurationNotFoundError` by S3; treat that
// as "encryption disabled" rather than fatal so policies see a clean
// fail signal. kmsManaged is true when the configured algorithm is
// SSE-KMS (aws:kms or aws:kms:dsse).
func (p *Plugin) bucketEncryption(ctx context.Context, name string) (enabled, kmsManaged bool, kmsKeyID string, err error) {
	out, err := p.api.GetBucketEncryption(ctx, &awss3.GetBucketEncryptionInput{Bucket: &name})
	if err != nil {
		if isAPIErrorCode(err, "ServerSideEncryptionConfigurationNotFoundError") {
			return false, false, "", nil
		}
		return false, false, "", err
	}
	if out == nil || out.ServerSideEncryptionConfiguration == nil {
		return false, false, "", nil
	}
	for i := range out.ServerSideEncryptionConfiguration.Rules {
		rule := &out.ServerSideEncryptionConfiguration.Rules[i]
		if rule.ApplyServerSideEncryptionByDefault == nil {
			continue
		}
		def := rule.ApplyServerSideEncryptionByDefault
		alg := string(def.SSEAlgorithm)
		if alg == "" {
			continue
		}
		keyID := ""
		if def.KMSMasterKeyID != nil {
			keyID = *def.KMSMasterKeyID
		}
		kms := alg == "aws:kms" || alg == "aws:kms:dsse"
		return true, kms, keyID, nil
	}
	return false, false, "", nil
}

// bucketPublicAccessBlocked returns true iff the bucket has a Public
// Access Block configuration with all four flags set. Missing
// configuration (`NoSuchPublicAccessBlockConfiguration`) → false, the
// safe-for-policies signal that public access is NOT blocked.
func (p *Plugin) bucketPublicAccessBlocked(ctx context.Context, name string) (bool, error) {
	out, err := p.api.GetPublicAccessBlock(ctx, &awss3.GetPublicAccessBlockInput{Bucket: &name})
	if err != nil {
		if isAPIErrorCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return false, nil
		}
		return false, err
	}
	if out == nil || out.PublicAccessBlockConfiguration == nil {
		return false, nil
	}
	c := out.PublicAccessBlockConfiguration
	allTrue := boolDeref(c.BlockPublicAcls) &&
		boolDeref(c.IgnorePublicAcls) &&
		boolDeref(c.BlockPublicPolicy) &&
		boolDeref(c.RestrictPublicBuckets)
	return allTrue, nil
}

// bucketVersioningEnabled returns true iff the bucket's versioning
// status is "Enabled" (not "Suspended" or unset). Optional field —
// absent versioning configuration is reported as false.
func (p *Plugin) bucketVersioningEnabled(ctx context.Context, name string) (bool, error) {
	out, err := p.api.GetBucketVersioning(ctx, &awss3.GetBucketVersioningInput{Bucket: &name})
	if err != nil {
		return false, err
	}
	if out == nil {
		return false, nil
	}
	return string(out.Status) == "Enabled", nil
}

// isAPIErrorCode returns true when err wraps a smithy.APIError with the
// supplied code. Used in lieu of typed-error matching since the v2 SDK
// exposes these as generic API errors.
func isAPIErrorCode(err error, code string) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == code
	}
	return false
}

func boolDeref(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
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
