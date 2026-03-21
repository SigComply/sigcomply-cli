package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// EC2Client defines the interface for EC2 operations.
//
//nolint:dupl // interface mirrors MockEC2Client in ec2_test.go by design
type EC2Client interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeFlowLogs(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error)
	GetEbsDefaultKmsKeyId(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error)
	GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeNetworkAcls(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeLaunchTemplateVersions(ctx context.Context, params *ec2.DescribeLaunchTemplateVersionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
	DescribeLaunchTemplates(ctx context.Context, params *ec2.DescribeLaunchTemplatesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error)
	DescribeVpcEndpoints(ctx context.Context, params *ec2.DescribeVpcEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	DescribeClientVpnEndpoints(ctx context.Context, params *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error)
	DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeTransitGateways(ctx context.Context, params *ec2.DescribeTransitGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error)
	GetSnapshotBlockPublicAccessState(ctx context.Context, params *ec2.GetSnapshotBlockPublicAccessStateInput, optFns ...func(*ec2.Options)) (*ec2.GetSnapshotBlockPublicAccessStateOutput, error)
}

// SecurityGroup represents an EC2 security group.
type SecurityGroup struct {
	GroupID      string           `json:"group_id"`
	GroupName    string           `json:"group_name"`
	Description  string           `json:"description"`
	VPCID       string           `json:"vpc_id"`
	IngressRules []SGRule         `json:"ingress_rules,omitempty"`
	OpenSSH      bool             `json:"open_ssh"`
	OpenRDP      bool             `json:"open_rdp"`
	OpenToAll    bool             `json:"open_to_all"`
}

// SGRule represents a security group ingress rule.
type SGRule struct {
	Protocol string `json:"protocol"`
	FromPort int32  `json:"from_port"`
	ToPort   int32  `json:"to_port"`
	CIDR     string `json:"cidr,omitempty"`
}

// VPCInfo represents a VPC with flow log status.
type VPCInfo struct {
	VPCID          string `json:"vpc_id"`
	IsDefault      bool   `json:"is_default"`
	CIDRBlock      string `json:"cidr_block"`
	FlowLogsEnabled bool  `json:"flow_logs_enabled"`
}

// EBSEncryptionConfig represents the EBS default encryption configuration.
type EBSEncryptionConfig struct {
	EncryptionByDefault bool   `json:"encryption_by_default"`
	DefaultKMSKeyID     string `json:"default_kms_key_id,omitempty"`
	Region              string `json:"region"`
}

// ToEvidence converts a SecurityGroup to Evidence.
func (sg *SecurityGroup) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(sg) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:security-group/%s", accountID, sg.GroupID)
	ev := evidence.New("aws", "aws:ec2:security-group", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ToEvidence converts a VPCInfo to Evidence.
func (v *VPCInfo) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(v) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:vpc/%s", accountID, v.VPCID)
	ev := evidence.New("aws", "aws:ec2:vpc", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ToEvidence converts an EBSEncryptionConfig to Evidence.
func (e *EBSEncryptionConfig) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(e) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("arn:aws:ec2:%s:%s:ebs-encryption-by-default", e.Region, accountID)
	ev := evidence.New("aws", "aws:ec2:ebs-encryption", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EC2Instance represents an EC2 instance with metadata service configuration.
type EC2Instance struct {
	InstanceID                string `json:"instance_id"`
	Name                      string `json:"name,omitempty"`
	HTTPTokens                string `json:"http_tokens"`
	HTTPEndpoint              string `json:"http_endpoint"`
	PublicIP                  string `json:"public_ip,omitempty"`
	DetailedMonitoringEnabled bool   `json:"detailed_monitoring_enabled"`
}

// EBSSnapshot represents an EBS snapshot with sharing status.
type EBSSnapshot struct {
	SnapshotID string `json:"snapshot_id"`
	VolumeID   string `json:"volume_id,omitempty"`
	Encrypted  bool   `json:"encrypted"`
	Public     bool   `json:"public"`
}

// ToEvidence converts an EBSSnapshot to Evidence.
func (s *EBSSnapshot) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:snapshot/%s", accountID, s.SnapshotID)
	ev := evidence.New("aws", "aws:ec2:ebs_snapshot", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// Subnet represents an EC2 subnet.
type Subnet struct {
	SubnetID            string `json:"subnet_id"`
	VPCID               string `json:"vpc_id"`
	AvailabilityZone    string `json:"availability_zone"`
	CIDRBlock           string `json:"cidr_block"`
	MapPublicIPOnLaunch bool   `json:"map_public_ip_on_launch"`
}

// ToEvidence converts a Subnet to Evidence.
func (s *Subnet) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:subnet/%s", accountID, s.SubnetID)
	ev := evidence.New("aws", "aws:ec2:subnet", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// NetworkACL represents an EC2 network ACL.
type NetworkACL struct {
	NetworkACLID           string `json:"network_acl_id"`
	VPCID                  string `json:"vpc_id"`
	IsDefault              bool   `json:"is_default"`
	UnrestrictedSSHIngress bool   `json:"unrestricted_ssh_ingress"`
	UnrestrictedRDPIngress bool   `json:"unrestricted_rdp_ingress"`
}

// ToEvidence converts a NetworkACL to Evidence.
func (n *NetworkACL) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(n) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:network-acl/%s", accountID, n.NetworkACLID)
	ev := evidence.New("aws", "aws:ec2:network-acl", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// LaunchTemplate represents an EC2 launch template with metadata options.
type LaunchTemplate struct {
	LaunchTemplateID   string `json:"launch_template_id"`
	LaunchTemplateName string `json:"launch_template_name"`
	HTTPTokens         string `json:"http_tokens"`
	HTTPEndpoint       string `json:"http_endpoint"`
}

// ToEvidence converts a LaunchTemplate to Evidence.
func (l *LaunchTemplate) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(l) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:launch-template/%s", accountID, l.LaunchTemplateID)
	ev := evidence.New("aws", "aws:ec2:launch-template", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ToEvidence converts an EC2Instance to Evidence.
func (i *EC2Instance) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(i) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:instance/%s", accountID, i.InstanceID)
	ev := evidence.New("aws", "aws:ec2:instance", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// VPCEndpointStatus represents VPC endpoint status for S3.
type VPCEndpointStatus struct {
	HasS3Endpoint bool   `json:"has_s3_endpoint"`
	Region        string `json:"region"`
}

// ToEvidence converts a VPCEndpointStatus to Evidence.
func (v *VPCEndpointStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(v) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc-endpoint-status", v.Region, accountID)
	ev := evidence.New("aws", "aws:ec2:vpc-endpoint-status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ClientVPNEndpoint represents an EC2 Client VPN endpoint.
type ClientVPNEndpoint struct {
	ClientVpnEndpointID      string `json:"client_vpn_endpoint_id"`
	ConnectionLoggingEnabled bool   `json:"connection_logging_enabled"`
	SplitTunnel              bool   `json:"split_tunnel"`
}

// ToEvidence converts a ClientVPNEndpoint to Evidence.
func (e *ClientVPNEndpoint) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(e) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:client-vpn-endpoint/%s", accountID, e.ClientVpnEndpointID)
	ev := evidence.New("aws", "aws:ec2:client-vpn-endpoint", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EBSVolume represents an EBS volume.
type EBSVolume struct {
	VolumeID     string `json:"volume_id"`
	Encrypted    bool   `json:"encrypted"`
	HasSnapshots bool   `json:"has_snapshots"`
}

// ToEvidence converts an EBSVolume to Evidence.
func (v *EBSVolume) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(v) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:volume/%s", accountID, v.VolumeID)
	ev := evidence.New("aws", "aws:ec2:volume", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EC2AMI represents an EC2 AMI.
type EC2AMI struct {
	ImageID string `json:"image_id"`
	Public  bool   `json:"public"`
}

// ToEvidence converts an EC2AMI to Evidence.
func (a *EC2AMI) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(a) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:image/%s", accountID, a.ImageID)
	ev := evidence.New("aws", "aws:ec2:ami", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// TransitGateway represents an EC2 transit gateway.
type TransitGateway struct {
	TransitGatewayID            string `json:"transit_gateway_id"`
	AutoAcceptSharedAttachments bool   `json:"auto_accept_shared_attachments"`
}

// ToEvidence converts a TransitGateway to Evidence.
func (tg *TransitGateway) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(tg) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:transit-gateway/%s", accountID, tg.TransitGatewayID)
	ev := evidence.New("aws", "aws:ec2:transit-gateway", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EC2AccountSetting represents EC2 account-level settings.
type EC2AccountSetting struct {
	EBSBlockPublicAccess bool   `json:"ebs_block_public_access"`
	Region               string `json:"region"`
}

// ToEvidence converts an EC2AccountSetting to Evidence.
func (s *EC2AccountSetting) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:ec2:%s:%s:account-setting", s.Region, accountID)
	ev := evidence.New("aws", "aws:ec2:account-setting", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EC2Collector collects EC2 data.
type EC2Collector struct {
	client EC2Client
	region string
}

// NewEC2Collector creates a new EC2 collector.
func NewEC2Collector(client EC2Client, region string) *EC2Collector {
	return &EC2Collector{client: client, region: region}
}

// CollectSecurityGroups retrieves all security groups.
func (c *EC2Collector) CollectSecurityGroups(ctx context.Context) ([]SecurityGroup, error) {
	output, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	var groups []SecurityGroup
	for i := range output.SecurityGroups {
		sg := &output.SecurityGroups[i]
		group := SecurityGroup{
			GroupID:     awssdk.ToString(sg.GroupId),
			GroupName:   awssdk.ToString(sg.GroupName),
			Description: awssdk.ToString(sg.Description),
			VPCID:      awssdk.ToString(sg.VpcId),
		}

		for j := range sg.IpPermissions {
			perm := &sg.IpPermissions[j]
			protocol := awssdk.ToString(perm.IpProtocol)
			fromPort := awssdk.ToInt32(perm.FromPort)
			toPort := awssdk.ToInt32(perm.ToPort)

			for _, ipRange := range perm.IpRanges {
				cidr := awssdk.ToString(ipRange.CidrIp)
				group.IngressRules = append(group.IngressRules, SGRule{
					Protocol: protocol,
					FromPort: fromPort,
					ToPort:   toPort,
					CIDR:     cidr,
				})

				if cidr == "0.0.0.0/0" {
					group.OpenToAll = true
					if protocol == "-1" || protocol == "tcp" {
						if protocol == "-1" || (fromPort <= 22 && toPort >= 22) {
							group.OpenSSH = true
						}
						if protocol == "-1" || (fromPort <= 3389 && toPort >= 3389) {
							group.OpenRDP = true
						}
					}
				}
			}
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// CollectVPCs retrieves all VPCs with flow log status.
func (c *EC2Collector) CollectVPCs(ctx context.Context) ([]VPCInfo, error) {
	vpcsOutput, err := c.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	// Build list of VPC IDs to filter flow logs by resource-id
	vpcIDs := make([]string, 0, len(vpcsOutput.Vpcs))
	for i := range vpcsOutput.Vpcs {
		vpcIDs = append(vpcIDs, awssdk.ToString(vpcsOutput.Vpcs[i].VpcId))
	}

	// Get flow logs for these VPCs (resource-type filter doesn't exist, use resource-id)
	flowLogVPCs := make(map[string]bool)
	if len(vpcIDs) > 0 {
		flowLogsOutput, err := c.client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
			Filter: []ec2types.Filter{
				{
					Name:   awssdk.String("resource-id"),
					Values: vpcIDs,
				},
			},
		})
		if err == nil {
			for i := range flowLogsOutput.FlowLogs {
				flowLogVPCs[awssdk.ToString(flowLogsOutput.FlowLogs[i].ResourceId)] = true
			}
		}
	}

	var vpcs []VPCInfo
	for i := range vpcsOutput.Vpcs {
		vpc := &vpcsOutput.Vpcs[i]
		vpcID := awssdk.ToString(vpc.VpcId)
		v := VPCInfo{
			VPCID:          vpcID,
			IsDefault:      awssdk.ToBool(vpc.IsDefault),
			CIDRBlock:      awssdk.ToString(vpc.CidrBlock),
			FlowLogsEnabled: flowLogVPCs[vpcID],
		}
		vpcs = append(vpcs, v)
	}

	return vpcs, nil
}

// CollectEBSEncryption retrieves the EBS default encryption configuration.
func (c *EC2Collector) CollectEBSEncryption(ctx context.Context) (*EBSEncryptionConfig, error) {
	config := &EBSEncryptionConfig{Region: c.region}

	output, err := c.client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		config.EncryptionByDefault = false
		return config, nil //nolint:nilerr // fail-safe: default to encryption disabled on error
	}

	config.EncryptionByDefault = awssdk.ToBool(output.EbsEncryptionByDefault)

	// Get default KMS key
	keyOutput, err := c.client.GetEbsDefaultKmsKeyId(ctx, &ec2.GetEbsDefaultKmsKeyIdInput{})
	if err == nil {
		config.DefaultKMSKeyID = awssdk.ToString(keyOutput.KmsKeyId)
	}

	return config, nil
}

// CollectInstances retrieves all EC2 instances with their IMDS configuration.
func (c *EC2Collector) CollectInstances(ctx context.Context) ([]EC2Instance, error) {
	var instances []EC2Instance
	var nextToken *string

	for {
		output, err := c.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe EC2 instances: %w", err)
		}

		for i := range output.Reservations {
			reservation := &output.Reservations[i]
			for j := range reservation.Instances {
				inst := &reservation.Instances[j]
				instance := EC2Instance{
					InstanceID: awssdk.ToString(inst.InstanceId),
				}

				// Get Name tag
				for _, tag := range inst.Tags {
					if awssdk.ToString(tag.Key) == "Name" {
						instance.Name = awssdk.ToString(tag.Value)
						break
					}
				}

				// Get public IP
				instance.PublicIP = awssdk.ToString(inst.PublicIpAddress)

				// Get IMDS configuration
				if inst.MetadataOptions != nil {
					instance.HTTPTokens = string(inst.MetadataOptions.HttpTokens)
					instance.HTTPEndpoint = string(inst.MetadataOptions.HttpEndpoint)
				}

				// Detailed monitoring
				if inst.Monitoring != nil {
					instance.DetailedMonitoringEnabled = string(inst.Monitoring.State) == statusEnabledLower
				}

				instances = append(instances, instance)
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return instances, nil
}

// CollectEBSSnapshots retrieves all EBS snapshots owned by the account.
func (c *EC2Collector) CollectEBSSnapshots(ctx context.Context, accountID string) ([]EBSSnapshot, error) {
	var snapshots []EBSSnapshot
	var nextToken *string

	for {
		output, err := c.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			OwnerIds:  []string{"self"},
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe EBS snapshots: %w", err)
		}

		for i := range output.Snapshots {
			snap := &output.Snapshots[i]
			snapshots = append(snapshots, EBSSnapshot{
				SnapshotID: awssdk.ToString(snap.SnapshotId),
				VolumeID:   awssdk.ToString(snap.VolumeId),
				Encrypted:  awssdk.ToBool(snap.Encrypted),
				Public:     false, // Requires DescribeSnapshotAttribute per snapshot
			})
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return snapshots, nil
}

// CollectSubnets retrieves all VPC subnets.
func (c *EC2Collector) CollectSubnets(ctx context.Context) ([]Subnet, error) {
	var subnets []Subnet
	var nextToken *string

	for {
		output, err := c.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe subnets: %w", err)
		}

		for i := range output.Subnets {
			subnet := &output.Subnets[i]
			subnets = append(subnets, Subnet{
				SubnetID:            awssdk.ToString(subnet.SubnetId),
				VPCID:               awssdk.ToString(subnet.VpcId),
				AvailabilityZone:    awssdk.ToString(subnet.AvailabilityZone),
				CIDRBlock:           awssdk.ToString(subnet.CidrBlock),
				MapPublicIPOnLaunch: awssdk.ToBool(subnet.MapPublicIpOnLaunch),
			})
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return subnets, nil
}

// CollectNetworkACLs retrieves all network ACLs with ingress analysis.
func (c *EC2Collector) CollectNetworkACLs(ctx context.Context) ([]NetworkACL, error) {
	var acls []NetworkACL
	var nextToken *string

	for {
		output, err := c.client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe network ACLs: %w", err)
		}

		for i := range output.NetworkAcls {
			acl := &output.NetworkAcls[i]
			nacl := NetworkACL{
				NetworkACLID: awssdk.ToString(acl.NetworkAclId),
				VPCID:        awssdk.ToString(acl.VpcId),
				IsDefault:    awssdk.ToBool(acl.IsDefault),
			}

			for _, entry := range acl.Entries {
				if entry.Egress != nil && *entry.Egress {
					continue
				}
				if entry.RuleAction != ec2types.RuleActionAllow {
					continue
				}
				if awssdk.ToString(entry.CidrBlock) != "0.0.0.0/0" {
					continue
				}
				if entry.PortRange != nil {
					fromPort := awssdk.ToInt32(entry.PortRange.From)
					toPort := awssdk.ToInt32(entry.PortRange.To)
					if fromPort <= 22 && toPort >= 22 {
						nacl.UnrestrictedSSHIngress = true
					}
					if fromPort <= 3389 && toPort >= 3389 {
						nacl.UnrestrictedRDPIngress = true
					}
				}
			}

			acls = append(acls, nacl)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return acls, nil
}

// CollectLaunchTemplates retrieves all launch templates with their default version metadata options.
func (c *EC2Collector) CollectLaunchTemplates(ctx context.Context) ([]LaunchTemplate, error) {
	var templates []LaunchTemplate
	var nextToken *string

	for {
		output, err := c.client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe launch templates: %w", err)
		}

		for i := range output.LaunchTemplates {
			lt := &output.LaunchTemplates[i]
			tmpl := LaunchTemplate{
				LaunchTemplateID:   awssdk.ToString(lt.LaunchTemplateId),
				LaunchTemplateName: awssdk.ToString(lt.LaunchTemplateName),
			}

			// Get default version to inspect metadata options
			versOutput, err := c.client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
				LaunchTemplateId: lt.LaunchTemplateId,
				Versions:         []string{"$Default"},
			})
			if err == nil && len(versOutput.LaunchTemplateVersions) > 0 {
				ltData := versOutput.LaunchTemplateVersions[0].LaunchTemplateData
				if ltData != nil && ltData.MetadataOptions != nil {
					tmpl.HTTPTokens = string(ltData.MetadataOptions.HttpTokens)
					tmpl.HTTPEndpoint = string(ltData.MetadataOptions.HttpEndpoint)
				}
			}

			templates = append(templates, tmpl)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return templates, nil
}

// CollectVPCEndpointStatus checks for VPC endpoints for S3.
func (c *EC2Collector) CollectVPCEndpointStatus(ctx context.Context) (*VPCEndpointStatus, error) {
	status := &VPCEndpointStatus{Region: c.region}

	output, err := c.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	for i := range output.VpcEndpoints {
		ep := &output.VpcEndpoints[i]
		serviceName := awssdk.ToString(ep.ServiceName)
		if strings.Contains(serviceName, "s3") {
			status.HasS3Endpoint = true
			break
		}
	}

	return status, nil
}

// CollectClientVPNEndpoints retrieves all Client VPN endpoints.
func (c *EC2Collector) CollectClientVPNEndpoints(ctx context.Context) ([]ClientVPNEndpoint, error) {
	var endpoints []ClientVPNEndpoint
	var nextToken *string

	for {
		output, err := c.client.DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe Client VPN endpoints: %w", err)
		}

		for i := range output.ClientVpnEndpoints {
			ep := &output.ClientVpnEndpoints[i]
			endpoint := ClientVPNEndpoint{
				ClientVpnEndpointID: awssdk.ToString(ep.ClientVpnEndpointId),
			}

			if ep.ConnectionLogOptions != nil {
				endpoint.ConnectionLoggingEnabled = awssdk.ToBool(ep.ConnectionLogOptions.Enabled)
			}

			endpoint.SplitTunnel = awssdk.ToBool(ep.SplitTunnel)

			endpoints = append(endpoints, endpoint)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return endpoints, nil
}

// CollectVolumes retrieves all EBS volumes with encryption and snapshot status.
func (c *EC2Collector) CollectVolumes(ctx context.Context, accountID string) ([]EBSVolume, error) {
	var volumes []EBSVolume
	var nextToken *string

	// First, collect all snapshot volume IDs to determine has_snapshots
	snapshotVolumeIDs := make(map[string]bool)
	var snapNextToken *string
	for {
		snapOutput, err := c.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			OwnerIds:  []string{"self"},
			NextToken: snapNextToken,
		})
		if err != nil {
			break // Fail-safe: if we can't get snapshots, volumes will have has_snapshots=false
		}
		for i := range snapOutput.Snapshots {
			snapshotVolumeIDs[awssdk.ToString(snapOutput.Snapshots[i].VolumeId)] = true
		}
		if snapOutput.NextToken == nil {
			break
		}
		snapNextToken = snapOutput.NextToken
	}

	for {
		output, err := c.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe EBS volumes: %w", err)
		}

		for i := range output.Volumes {
			vol := &output.Volumes[i]
			volID := awssdk.ToString(vol.VolumeId)
			volumes = append(volumes, EBSVolume{
				VolumeID:     volID,
				Encrypted:    awssdk.ToBool(vol.Encrypted),
				HasSnapshots: snapshotVolumeIDs[volID],
			})
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return volumes, nil
}

// CollectAMIs retrieves all self-owned AMIs.
func (c *EC2Collector) CollectAMIs(ctx context.Context) ([]EC2AMI, error) {
	output, err := c.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe AMIs: %w", err)
	}

	var amis []EC2AMI
	for i := range output.Images {
		img := &output.Images[i]
		amis = append(amis, EC2AMI{
			ImageID: awssdk.ToString(img.ImageId),
			Public:  awssdk.ToBool(img.Public),
		})
	}

	return amis, nil
}

// CollectTransitGateways retrieves all transit gateways.
func (c *EC2Collector) CollectTransitGateways(ctx context.Context) ([]TransitGateway, error) {
	var gateways []TransitGateway
	var nextToken *string

	for {
		output, err := c.client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe transit gateways: %w", err)
		}

		for i := range output.TransitGateways {
			tg := &output.TransitGateways[i]
			gateway := TransitGateway{
				TransitGatewayID: awssdk.ToString(tg.TransitGatewayId),
			}
			if tg.Options != nil {
				gateway.AutoAcceptSharedAttachments = tg.Options.AutoAcceptSharedAttachments == ec2types.AutoAcceptSharedAttachmentsValueEnable
			}
			gateways = append(gateways, gateway)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return gateways, nil
}

// CollectAccountSettings retrieves EC2 account-level settings.
func (c *EC2Collector) CollectAccountSettings(ctx context.Context) (*EC2AccountSetting, error) {
	setting := &EC2AccountSetting{Region: c.region}

	output, err := c.client.GetSnapshotBlockPublicAccessState(ctx, &ec2.GetSnapshotBlockPublicAccessStateInput{})
	if err != nil {
		return setting, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	setting.EBSBlockPublicAccess = output.State == ec2types.SnapshotBlockPublicAccessStateBlockAllSharing
	return setting, nil
}

// CollectEvidence collects all EC2 evidence.
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
func (c *EC2Collector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	// Security groups
	sgs, err := c.CollectSecurityGroups(ctx)
	if err != nil {
		return nil, err
	}
	for i := range sgs {
		evidenceList = append(evidenceList, sgs[i].ToEvidence(accountID))
	}

	// VPCs
	vpcs, err := c.CollectVPCs(ctx)
	if err != nil {
		// Fail-safe
		_ = err
	} else {
		for i := range vpcs {
			evidenceList = append(evidenceList, vpcs[i].ToEvidence(accountID))
		}
	}

	// EBS encryption
	ebsConfig, err := c.CollectEBSEncryption(ctx)
	if err != nil {
		_ = err
	} else {
		evidenceList = append(evidenceList, ebsConfig.ToEvidence(accountID))
	}

	// EC2 instances (for IMDSv2)
	instances, err := c.CollectInstances(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range instances {
			evidenceList = append(evidenceList, instances[i].ToEvidence(accountID))
		}
	}

	// EBS snapshots
	snapshots, err := c.CollectEBSSnapshots(ctx, accountID)
	if err != nil {
		_ = err
	} else {
		for i := range snapshots {
			evidenceList = append(evidenceList, snapshots[i].ToEvidence(accountID))
		}
	}

	// Subnets
	subnets, err := c.CollectSubnets(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range subnets {
			evidenceList = append(evidenceList, subnets[i].ToEvidence(accountID))
		}
	}

	// Network ACLs
	nacls, err := c.CollectNetworkACLs(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range nacls {
			evidenceList = append(evidenceList, nacls[i].ToEvidence(accountID))
		}
	}

	// Launch templates
	launchTemplates, err := c.CollectLaunchTemplates(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range launchTemplates {
			evidenceList = append(evidenceList, launchTemplates[i].ToEvidence(accountID))
		}
	}

	// VPC endpoint status
	vpcEndpointStatus, err := c.CollectVPCEndpointStatus(ctx)
	if err == nil {
		evidenceList = append(evidenceList, vpcEndpointStatus.ToEvidence(accountID))
	}

	// Client VPN endpoints
	clientVpnEndpoints, err := c.CollectClientVPNEndpoints(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range clientVpnEndpoints {
			evidenceList = append(evidenceList, clientVpnEndpoints[i].ToEvidence(accountID))
		}
	}

	// EBS volumes
	volumes, err := c.CollectVolumes(ctx, accountID)
	if err != nil {
		_ = err
	} else {
		for i := range volumes {
			evidenceList = append(evidenceList, volumes[i].ToEvidence(accountID))
		}
	}

	// AMIs
	amis, err := c.CollectAMIs(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range amis {
			evidenceList = append(evidenceList, amis[i].ToEvidence(accountID))
		}
	}

	// Transit gateways
	transitGateways, err := c.CollectTransitGateways(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range transitGateways {
			evidenceList = append(evidenceList, transitGateways[i].ToEvidence(accountID))
		}
	}

	// Account settings
	accountSettings, err := c.CollectAccountSettings(ctx)
	if err == nil {
		evidenceList = append(evidenceList, accountSettings.ToEvidence(accountID))
	}

	return evidenceList, nil
}

// portInRange checks if a port is within a given range string (e.g., "22-80").
func portInRange(portRange string, target int32) bool {
	// Simple port range parsing
	var start, end int64
	n, _ := fmt.Sscanf(portRange, "%d-%d", &start, &end) //nolint:errcheck // count n is the effective guard
	if n == 2 {
		return int64(target) >= start && int64(target) <= end
	}
	p, err := strconv.ParseInt(portRange, 10, 32)
	if err != nil {
		return false
	}
	return p == int64(target)
}
