// Package ec2 implements the aws.ec2 source plugin: lists EC2 instances
// in one AWS account and emits ec2_instance evidence records carrying
// the network-exposure attributes that SOC 2 CC6.6 policies consume.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by the
// aws.iam plugin — the concrete *ec2.Client satisfies it, and unit tests
// inject an in-memory fake.
package ec2

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "ec2_instance"

// SourceID is the registered ID for the aws.ec2 plugin instance.
const SourceID = "aws.ec2"

// API is the subset of the EC2 client this plugin uses.
type API interface {
	DescribeInstances(ctx context.Context, params *awsec2.DescribeInstancesInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error)
}

// Plugin is the in-process aws.ec2 source.
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
		return nil, fmt.Errorf("aws.ec2: load AWS config: %w", err)
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

// instancePayload is the shape of the JSON payload inside each
// ec2_instance record.
type instancePayload struct {
	InstanceID       string `json:"instance_id"`
	State            string `json:"state,omitempty"`
	InstanceType     string `json:"instance_type,omitempty"`
	PublicIPAddress  string `json:"public_ip_address,omitempty"`
	PrivateIPAddress string `json:"private_ip_address,omitempty"`
	VPCID            string `json:"vpc_id,omitempty"`
	HasPublicIP      bool   `json:"has_public_ip"`
}

// Collect lists EC2 instances across all reservations in the configured
// region and returns one ec2_instance record per instance.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.ec2: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	instances, err := p.listAllInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.ec2: describe instances: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(instances))
	for i := range instances {
		inst := &instances[i]
		id := safeInstanceID(inst)
		if id == "" {
			continue
		}
		public := safeString(inst.PublicIpAddress)
		payload := instancePayload{
			InstanceID:       id,
			State:            safeState(inst.State),
			InstanceType:     string(inst.InstanceType),
			PublicIPAddress:  public,
			PrivateIPAddress: safeString(inst.PrivateIpAddress),
			VPCID:            safeString(inst.VpcId),
			HasPublicIP:      public != "",
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.ec2: marshal payload: %w", err)
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

func (p *Plugin) listAllInstances(ctx context.Context) ([]ec2types.Instance, error) {
	var (
		out       []ec2types.Instance
		nextToken *string
	)
	for {
		page, err := p.api.DescribeInstances(ctx, &awsec2.DescribeInstancesInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		for i := range page.Reservations {
			out = append(out, page.Reservations[i].Instances...)
		}
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return out, nil
	}
}

func safeInstanceID(inst *ec2types.Instance) string {
	if inst == nil || inst.InstanceId == nil {
		return ""
	}
	return *inst.InstanceId
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeState(s *ec2types.InstanceState) string {
	if s == nil {
		return ""
	}
	return string(s.Name)
}

var _ core.SourcePlugin = (*Plugin)(nil)
