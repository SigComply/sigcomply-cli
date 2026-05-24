// Package cloudwatch implements the aws.cloudwatch source plugin: lists
// CloudWatch Logs log groups in one AWS account and emits
// cloudwatch_log_group evidence records suitable for SOC 2
// audit-logging policies (retention configured, encryption at rest).
//
// Today the plugin only emits cloudwatch_log_group records using the
// CloudWatch Logs SDK. CloudWatch alarms (cloudwatch_alarm) are a
// future addition under the same plugin ID.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the concrete *cloudwatchlogs.Client
// satisfies it, and unit tests inject an in-memory fake.
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
// cloudwatch_alarm will be added later under the same plugin.
const EvidenceTypeID = "cloudwatch_log_group"

// SourceID is the registered ID for the aws.cloudwatch plugin instance.
const SourceID = "aws.cloudwatch"

// API is the subset of the CloudWatch Logs client this plugin uses.
// Defining it as an interface lets tests inject a fake; the concrete
// *cloudwatchlogs.Client satisfies it.
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

// Init accepts plugin config (currently just region) but the
// constructor already has it; this is a no-op preserved for symmetry.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// logGroupPayload is the shape of the JSON payload inside each
// cloudwatch_log_group record.
type logGroupPayload struct {
	Name             string `json:"name"`
	ARN              string `json:"arn"`
	RetentionInDays  int    `json:"retention_in_days"`
	RetentionSet     bool   `json:"retention_set"`
	KMSKeyID         string `json:"kms_key_id,omitempty"`
	StoredBytes      int64  `json:"stored_bytes"`
	MetricFilterUsed int    `json:"metric_filter_count,omitempty"`
}

// Collect lists all CloudWatch log groups in the configured region and
// returns one cloudwatch_log_group record per group. Records are sorted
// by ID before return so envelope bytes are stable across runs against
// stable account state.
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
		payload := logGroupPayload{
			Name:             name,
			ARN:              arn,
			RetentionInDays:  retentionDays(g.RetentionInDays),
			RetentionSet:     g.RetentionInDays != nil,
			KMSKeyID:         safeStr(g.KmsKeyId),
			StoredBytes:      safeInt64(g.StoredBytes),
			MetricFilterUsed: int(safeInt32(g.MetricFilterCount)),
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

func safeInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

var _ core.SourcePlugin = (*Plugin)(nil)
