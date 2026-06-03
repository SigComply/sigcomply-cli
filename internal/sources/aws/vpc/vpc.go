// Package vpc implements the aws.vpc source plugin: lists VPCs in one AWS
// account and emits network evidence records carrying the cross-vendor
// flow-logging / default-network attributes policies check.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
package vpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "network"

// SourceID is the registered ID for the aws.vpc plugin instance.
const SourceID = "aws.vpc"

// flowLogStatusActive is the FlowLogStatus value AWS reports for a flow log
// that is actively delivering records.
const flowLogStatusActive = "ACTIVE"

// API is the subset of the EC2 client this plugin uses.
type API interface {
	DescribeVpcs(ctx context.Context, params *awsec2.DescribeVpcsInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeVpcsOutput, error)
	DescribeFlowLogs(ctx context.Context, params *awsec2.DescribeFlowLogsInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeFlowLogsOutput, error)
}

// Plugin is the in-process aws.vpc source.
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
		return nil, fmt.Errorf("aws.vpc: load AWS config: %w", err)
	}
	return New(Options{
		API:    awsec2.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// networkPayload is the cross-vendor network shape (see
// internal/evidence_types/schemas/network.v1.json). The four required
// fields (id, name, flow_logs_enabled, is_default) are always emitted —
// the evaluator errors on any referenced-but-absent field.
type networkPayload struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	Region          string `json:"region,omitempty"`
	FlowLogsEnabled bool   `json:"flow_logs_enabled"`
	IsDefault       bool   `json:"is_default"`
	CIDRBlock       string `json:"cidr_block,omitempty"`
}

// Collect lists VPCs and returns one network record per VPC.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.vpc: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	activeFlowLogs, err := p.activeFlowLogVPCs(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.vpc: describe flow logs: %w", err)
	}
	vpcs, err := p.listAllVPCs(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.vpc: describe vpcs: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(vpcs))
	for i := range vpcs {
		v := &vpcs[i]
		id := safeString(v.VpcId)
		if id == "" {
			continue
		}
		payload := networkPayload{
			ID:              id,
			Name:            vpcName(v),
			Provider:        "aws",
			Region:          p.region,
			FlowLogsEnabled: activeFlowLogs[id],
			IsDefault:       aws.ToBool(v.IsDefault),
			CIDRBlock:       safeString(v.CidrBlock),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.vpc: marshal payload: %w", err)
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

// activeFlowLogVPCs returns the set of VPC IDs that have at least one ACTIVE
// flow log targeting them (FlowLog.ResourceId == vpc-id).
func (p *Plugin) activeFlowLogVPCs(ctx context.Context) (map[string]bool, error) {
	active := make(map[string]bool)
	var nextToken *string
	for {
		page, err := p.api.DescribeFlowLogs(ctx, &awsec2.DescribeFlowLogsInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		for i := range page.FlowLogs {
			fl := &page.FlowLogs[i]
			if safeString(fl.FlowLogStatus) != flowLogStatusActive {
				continue
			}
			if rid := safeString(fl.ResourceId); rid != "" {
				active[rid] = true
			}
		}
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return active, nil
	}
}

func (p *Plugin) listAllVPCs(ctx context.Context) ([]ec2types.Vpc, error) {
	var (
		out       []ec2types.Vpc
		nextToken *string
	)
	for {
		page, err := p.api.DescribeVpcs(ctx, &awsec2.DescribeVpcsInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Vpcs...)
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return out, nil
	}
}

func vpcName(v *ec2types.Vpc) string {
	if v == nil {
		return ""
	}
	for _, tag := range v.Tags {
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil && *tag.Value != "" {
			return *tag.Value
		}
	}
	return safeString(v.VpcId)
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
