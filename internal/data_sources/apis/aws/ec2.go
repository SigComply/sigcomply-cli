package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// EC2Client defines the interface for EC2 operations.
type EC2Client interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeFlowLogs(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error)
	GetEbsDefaultKmsKeyId(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error)
	GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
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
	InstanceID   string `json:"instance_id"`
	Name         string `json:"name,omitempty"`
	HttpTokens   string `json:"http_tokens"`
	HttpEndpoint string `json:"http_endpoint"`
}

// ToEvidence converts an EC2Instance to Evidence.
func (i *EC2Instance) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(i) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:ec2::%s:instance/%s", accountID, i.InstanceID)
	ev := evidence.New("aws", "aws:ec2:instance", resourceID, data)
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

	// Get all flow logs for VPCs
	flowLogsOutput, err := c.client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
		Filter: []ec2types.Filter{
			{
				Name:   awssdk.String("resource-type"),
				Values: []string{"VPC"},
			},
		},
	})

	flowLogVPCs := make(map[string]bool)
	if err == nil {
		for i := range flowLogsOutput.FlowLogs {
			flowLogVPCs[awssdk.ToString(flowLogsOutput.FlowLogs[i].ResourceId)] = true
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

		for _, reservation := range output.Reservations {
			for _, inst := range reservation.Instances {
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

				// Get IMDS configuration
				if inst.MetadataOptions != nil {
					instance.HttpTokens = string(inst.MetadataOptions.HttpTokens)
					instance.HttpEndpoint = string(inst.MetadataOptions.HttpEndpoint)
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

// CollectEvidence collects all EC2 evidence.
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
