// Package ec2 implements the aws.ec2 source plugin: lists EC2 instances
// in one AWS account and emits compute_instance evidence records carrying
// cross-vendor network-exposure, encryption, and monitoring attributes.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract) the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
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
const EvidenceTypeID = "compute_instance"

// SourceID is the registered ID for the aws.ec2 plugin instance.
const SourceID = "aws.ec2"

// API is the subset of the EC2 client this plugin uses.
type API interface {
	DescribeInstances(ctx context.Context, params *awsec2.DescribeInstancesInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error)
	DescribeVolumes(ctx context.Context, params *awsec2.DescribeVolumesInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeVolumesOutput, error)
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

// instancePayload is the cross-vendor compute_instance shape.
type instancePayload struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Provider            string `json:"provider"`
	Region              string `json:"region,omitempty"`
	IsRunning           bool   `json:"is_running"`
	HasPublicIP         bool   `json:"has_public_ip"`
	RootVolumeEncrypted bool   `json:"root_volume_encrypted"`
	MonitoringEnabled   bool   `json:"monitoring_enabled"`
	// AWS-specific extras (additionalProperties)
	InstanceType string `json:"instance_type,omitempty"`
	VPCID        string `json:"vpc_id,omitempty"`
}

// Collect lists EC2 instances and returns one compute_instance record per instance.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.ec2: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	instances, err := p.listAllInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.ec2: describe instances: %w", err)
	}
	// Best-effort root-volume encryption lookup; a DescribeVolumes
	// failure leaves the flag false rather than aborting collection.
	volumeEncrypted := p.rootVolumeEncryptionMap(ctx, instances)
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
			ID:                  id,
			Name:                instanceName(inst),
			Provider:            "aws",
			Region:              p.region,
			IsRunning:           safeState(inst.State) == "running",
			HasPublicIP:         public != "",
			RootVolumeEncrypted: volumeEncrypted[id],
			MonitoringEnabled:   safeMonitoring(inst.Monitoring),
			InstanceType:        string(inst.InstanceType),
			VPCID:               safeString(inst.VpcId),
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

// rootVolumeEncryptionMap returns a map of instanceID → encrypted for each
// instance's root EBS volume. Best-effort: unknown or on API error →
// absent (treated as false by the caller).
func (p *Plugin) rootVolumeEncryptionMap(ctx context.Context, instances []ec2types.Instance) map[string]bool {
	result := make(map[string]bool, len(instances))
	// Build map of volumeID → instanceID for root volumes.
	volToInstance := make(map[string]string)
	for i := range instances {
		inst := &instances[i]
		id := safeInstanceID(inst)
		if id == "" {
			continue
		}
		rootDevice := safeString(inst.RootDeviceName)
		for j := range inst.BlockDeviceMappings {
			m := &inst.BlockDeviceMappings[j]
			if safeString(m.DeviceName) == rootDevice && m.Ebs != nil && m.Ebs.VolumeId != nil {
				volToInstance[*m.Ebs.VolumeId] = id
			}
		}
	}
	if len(volToInstance) == 0 {
		return result
	}
	volIDs := make([]string, 0, len(volToInstance))
	for vid := range volToInstance {
		volIDs = append(volIDs, vid)
	}
	out, err := p.api.DescribeVolumes(ctx, &awsec2.DescribeVolumesInput{VolumeIds: volIDs})
	if err != nil {
		return result // best-effort: leave flags false on error
	}
	for i := range out.Volumes {
		v := &out.Volumes[i]
		if v.VolumeId == nil {
			continue
		}
		instID, ok := volToInstance[*v.VolumeId]
		if !ok {
			continue
		}
		result[instID] = v.Encrypted != nil && *v.Encrypted
	}
	return result
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

func instanceName(inst *ec2types.Instance) string {
	if inst == nil {
		return ""
	}
	for _, tag := range inst.Tags {
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
			return *tag.Value
		}
	}
	return safeInstanceID(inst)
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

func safeMonitoring(m *ec2types.Monitoring) bool {
	if m == nil {
		return false
	}
	return m.State == ec2types.MonitoringStateEnabled
}

var _ core.SourcePlugin = (*Plugin)(nil)
