// Package cloudtrail implements the aws.cloudtrail source plugin: lists
// CloudTrail trails in one AWS account along with each trail's logging
// status, and emits cloudtrail_trail evidence records suitable for SOC 2
// audit-logging policies (multi-region coverage, logging enablement,
// log file validation).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the concrete *cloudtrail.Client satisfies
// it, and unit tests inject an in-memory fake. The real SDK adapter has
// no integration tests at this milestone (deferred).
package cloudtrail

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today.
const EvidenceTypeID = "cloudtrail_trail"

// SourceID is the registered ID for the aws.cloudtrail plugin instance.
const SourceID = "aws.cloudtrail"

// API is the subset of the CloudTrail client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// AWS; the concrete *cloudtrail.Client satisfies it.
type API interface {
	DescribeTrails(ctx context.Context, params *awsct.DescribeTrailsInput, optFns ...func(*awsct.Options)) (*awsct.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, params *awsct.GetTrailStatusInput, optFns ...func(*awsct.Options)) (*awsct.GetTrailStatusOutput, error)
}

// Plugin is the in-process aws.cloudtrail source.
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
// default credential chain.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.cloudtrail: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsct.NewFromConfig(cfg),
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

// trailPayload is the shape of the JSON payload inside each
// cloudtrail_trail record. The fields are chosen to support common
// SOC 2 audit-logging policies (multi-region, logging, validation).
type trailPayload struct {
	Name                       string `json:"name"`
	ARN                        string `json:"arn"`
	HomeRegion                 string `json:"home_region"`
	IsMultiRegionTrail         bool   `json:"is_multi_region_trail"`
	IsOrganizationTrail        bool   `json:"is_organization_trail"`
	IncludeGlobalServiceEvents bool   `json:"include_global_service_events"`
	LogFileValidationEnabled   bool   `json:"log_file_validation_enabled"`
	IsLogging                  bool   `json:"is_logging"`
	S3BucketName               string `json:"s3_bucket_name,omitempty"`
	KMSKeyID                   string `json:"kms_key_id,omitempty"`
}

// Collect lists CloudTrail trails in the configured account and returns
// one cloudtrail_trail per trail. Records are sorted by ID before
// return so envelope bytes are stable across runs against stable
// account state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.cloudtrail: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	out, err := p.api.DescribeTrails(ctx, &awsct.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.cloudtrail: describe trails: %w", err)
	}
	records := make([]core.EvidenceRecord, 0, len(out.TrailList))
	now := p.now()
	for i := range out.TrailList {
		t := &out.TrailList[i]
		name := safeTrailName(t)
		arn := safeTrailARN(t)
		id := arn
		if id == "" {
			id = name
		}
		isLogging, err := p.trailIsLogging(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("aws.cloudtrail: status for trail %s: %w", name, err)
		}
		payload := trailPayload{
			Name:                       name,
			ARN:                        arn,
			HomeRegion:                 safeStr(t.HomeRegion),
			IsMultiRegionTrail:         safeBool(t.IsMultiRegionTrail),
			IsOrganizationTrail:        safeBool(t.IsOrganizationTrail),
			IncludeGlobalServiceEvents: safeBool(t.IncludeGlobalServiceEvents),
			LogFileValidationEnabled:   safeBool(t.LogFileValidationEnabled),
			IsLogging:                  isLogging,
			S3BucketName:               safeStr(t.S3BucketName),
			KMSKeyID:                   safeStr(t.KmsKeyId),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.cloudtrail: marshal trail payload: %w", err)
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

func (p *Plugin) trailIsLogging(ctx context.Context, t *cttypes.Trail) (bool, error) {
	// Prefer ARN — required for shadow trails to be addressable across regions.
	ref := safeTrailARN(t)
	if ref == "" {
		ref = safeTrailName(t)
	}
	if ref == "" {
		return false, nil
	}
	out, err := p.api.GetTrailStatus(ctx, &awsct.GetTrailStatusInput{Name: &ref})
	if err != nil {
		return false, err
	}
	if out.IsLogging == nil {
		return false, nil
	}
	return *out.IsLogging, nil
}

func safeTrailName(t *cttypes.Trail) string {
	if t == nil || t.Name == nil {
		return ""
	}
	return *t.Name
}

func safeTrailARN(t *cttypes.Trail) string {
	if t == nil || t.TrailARN == nil {
		return ""
	}
	return *t.TrailARN
}

func safeStr(s *string) string {
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
