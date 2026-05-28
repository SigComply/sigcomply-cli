// Package cloudwatch implements the aws.cloudwatch source plugin: lists
// CloudWatch Logs log groups and emits log_group evidence records with
// cross-vendor retention and encryption attributes.
package cloudwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today.
const EvidenceTypeID = "log_group"

// SourceID is the registered ID for the aws.cloudwatch plugin instance.
const SourceID = "aws.cloudwatch"

// API is the subset of the CloudWatch Logs client this plugin uses.
type API interface {
	DescribeLogGroups(ctx context.Context, params *cwl.DescribeLogGroupsInput, optFns ...func(*cwl.Options)) (*cwl.DescribeLogGroupsOutput, error)
}

// Plugin is the in-process aws.cloudwatch source.
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
		return nil, fmt.Errorf("aws.cloudwatch: load AWS config: %w", err)
	}
	return New(Options{
		API:    cwl.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// logGroupPayload is the cross-vendor log_group shape.
type logGroupPayload struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	RetentionSet  bool   `json:"retention_set"`
	RetentionDays int    `json:"retention_days"`
	KMSEncrypted  bool   `json:"kms_encrypted"`
	// AWS-specific extras
	ARN         string `json:"arn,omitempty"`
	StoredBytes int64  `json:"stored_bytes,omitempty"`
	KMSKeyID    string `json:"kms_key_id,omitempty"`
}

// Collect lists CloudWatch log groups and returns one log_group record per group.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.cloudwatch: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	groups, err := p.listAllGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.cloudwatch: describe log groups: %w", err)
	}
	records := make([]core.EvidenceRecord, 0, len(groups))
	now := p.now()
	for i := range groups {
		g := &groups[i]
		name := safeStr(g.LogGroupName)
		arn := safeStr(g.Arn)
		id := arn
		if id == "" {
			id = name
		}
		retDays := retentionDays(g.RetentionInDays)
		kmsKeyID := safeStr(g.KmsKeyId)
		payload := logGroupPayload{
			ID:            id,
			Name:          name,
			Provider:      "aws",
			RetentionSet:  g.RetentionInDays != nil,
			RetentionDays: retDays,
			KMSEncrypted:  kmsKeyID != "",
			ARN:           arn,
			StoredBytes:   safeInt64(g.StoredBytes),
			KMSKeyID:      kmsKeyID,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.cloudwatch: marshal log group payload: %w", err)
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

func (p *Plugin) listAllGroups(ctx context.Context) ([]cwltypes.LogGroup, error) {
	var (
		out   []cwltypes.LogGroup
		token *string
	)
	for {
		page, err := p.api.DescribeLogGroups(ctx, &cwl.DescribeLogGroupsInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, page.LogGroups...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func retentionDays(p *int32) int {
	if p == nil {
		return 0
	}
	return int(*p)
}

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

var _ core.SourcePlugin = (*Plugin)(nil)
