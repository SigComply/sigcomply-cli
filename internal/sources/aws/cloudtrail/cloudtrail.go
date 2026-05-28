// Package cloudtrail implements the aws.cloudtrail source plugin: lists
// CloudTrail trails and emits audit_log_trail evidence records with
// cross-vendor logging-coverage and integrity attributes.
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

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "audit_log_trail"

// SourceID is the registered ID for the aws.cloudtrail plugin instance.
const SourceID = "aws.cloudtrail"

// API is the subset of the CloudTrail client this plugin uses.
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

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// trailPayload is the cross-vendor audit_log_trail shape.
type trailPayload struct {
	ID                         string `json:"id"`
	Name                       string `json:"name"`
	Provider                   string `json:"provider"`
	IsEnabled                  bool   `json:"is_enabled"`
	IsMultiRegion              bool   `json:"is_multi_region"`
	LogFileValidationEnabled   bool   `json:"log_file_validation_enabled"`
	KMSEncrypted               bool   `json:"kms_encrypted"`
	HomeRegion                 string `json:"home_region,omitempty"`
	IsOrganizationTrail        bool   `json:"is_organization_trail"`
	IncludeGlobalServiceEvents bool   `json:"include_global_service_events"`
	S3BucketName               string `json:"s3_bucket_name,omitempty"`
}

// Collect lists CloudTrail trails and returns one audit_log_trail record per trail.
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
			ID:                         id,
			Name:                       name,
			Provider:                   "aws",
			IsEnabled:                  isLogging,
			IsMultiRegion:              safeBool(t.IsMultiRegionTrail),
			LogFileValidationEnabled:   safeBool(t.LogFileValidationEnabled),
			KMSEncrypted:               safeStr(t.KmsKeyId) != "",
			HomeRegion:                 safeStr(t.HomeRegion),
			IsOrganizationTrail:        safeBool(t.IsOrganizationTrail),
			IncludeGlobalServiceEvents: safeBool(t.IncludeGlobalServiceEvents),
			S3BucketName:               safeStr(t.S3BucketName),
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
