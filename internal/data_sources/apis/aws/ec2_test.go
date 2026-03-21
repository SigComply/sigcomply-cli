package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockEC2Client implements EC2Client for testing.
type MockEC2Client struct {
	DescribeSecurityGroupsFunc    func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcsFunc              func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeFlowLogsFunc          func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error)
	GetEbsDefaultKmsKeyIDFunc     func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) //nolint:revive // matches AWS SDK naming
	GetEbsEncryptionByDefaultFunc func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
	DescribeInstancesFunc         func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSnapshotsFunc                func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeSubnetsFunc                  func(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeNetworkAclsFunc              func(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeLaunchTemplateVersionsFunc   func(ctx context.Context, params *ec2.DescribeLaunchTemplateVersionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
	DescribeLaunchTemplatesFunc          func(ctx context.Context, params *ec2.DescribeLaunchTemplatesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error)
	DescribeVpcEndpointsFunc             func(ctx context.Context, params *ec2.DescribeVpcEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	DescribeClientVpnEndpointsFunc           func(ctx context.Context, params *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error)
	DescribeVolumesFunc                      func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeImagesFunc                       func(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeTransitGatewaysFunc              func(ctx context.Context, params *ec2.DescribeTransitGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error)
	GetSnapshotBlockPublicAccessStateFunc    func(ctx context.Context, params *ec2.GetSnapshotBlockPublicAccessStateInput, optFns ...func(*ec2.Options)) (*ec2.GetSnapshotBlockPublicAccessStateOutput, error)
}

func (m *MockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return m.DescribeSecurityGroupsFunc(ctx, params, optFns...)
}

func (m *MockEC2Client) DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return m.DescribeVpcsFunc(ctx, params, optFns...)
}

func (m *MockEC2Client) DescribeFlowLogs(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
	return m.DescribeFlowLogsFunc(ctx, params, optFns...)
}

func (m *MockEC2Client) GetEbsDefaultKmsKeyId(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) { //nolint:revive // matches AWS SDK naming
	return m.GetEbsDefaultKmsKeyIDFunc(ctx, params, optFns...)
}

func (m *MockEC2Client) GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	return m.GetEbsEncryptionByDefaultFunc(ctx, params, optFns...)
}

func (m *MockEC2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.DescribeInstancesFunc != nil {
		return m.DescribeInstancesFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeInstancesOutput{}, nil
}

func (m *MockEC2Client) DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if m.DescribeSnapshotsFunc != nil {
		return m.DescribeSnapshotsFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeSnapshotsOutput{}, nil
}

func (m *MockEC2Client) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if m.DescribeSubnetsFunc != nil {
		return m.DescribeSubnetsFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeSubnetsOutput{}, nil
}

func (m *MockEC2Client) DescribeNetworkAcls(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	if m.DescribeNetworkAclsFunc != nil {
		return m.DescribeNetworkAclsFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeNetworkAclsOutput{}, nil
}

func (m *MockEC2Client) DescribeLaunchTemplateVersions(ctx context.Context, params *ec2.DescribeLaunchTemplateVersionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	if m.DescribeLaunchTemplateVersionsFunc != nil {
		return m.DescribeLaunchTemplateVersionsFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeLaunchTemplateVersionsOutput{}, nil
}

func (m *MockEC2Client) DescribeLaunchTemplates(ctx context.Context, params *ec2.DescribeLaunchTemplatesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error) {
	if m.DescribeLaunchTemplatesFunc != nil {
		return m.DescribeLaunchTemplatesFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeLaunchTemplatesOutput{}, nil
}

func (m *MockEC2Client) DescribeVpcEndpoints(ctx context.Context, params *ec2.DescribeVpcEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if m.DescribeVpcEndpointsFunc != nil {
		return m.DescribeVpcEndpointsFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeVpcEndpointsOutput{}, nil
}

func (m *MockEC2Client) DescribeClientVpnEndpoints(ctx context.Context, params *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error) {
	if m.DescribeClientVpnEndpointsFunc != nil {
		return m.DescribeClientVpnEndpointsFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeClientVpnEndpointsOutput{}, nil
}

func (m *MockEC2Client) DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if m.DescribeVolumesFunc != nil {
		return m.DescribeVolumesFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeVolumesOutput{}, nil
}

func (m *MockEC2Client) DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	if m.DescribeImagesFunc != nil {
		return m.DescribeImagesFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeImagesOutput{}, nil
}

func (m *MockEC2Client) DescribeTransitGateways(ctx context.Context, params *ec2.DescribeTransitGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error) {
	if m.DescribeTransitGatewaysFunc != nil {
		return m.DescribeTransitGatewaysFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeTransitGatewaysOutput{}, nil
}

func (m *MockEC2Client) GetSnapshotBlockPublicAccessState(ctx context.Context, params *ec2.GetSnapshotBlockPublicAccessStateInput, optFns ...func(*ec2.Options)) (*ec2.GetSnapshotBlockPublicAccessStateOutput, error) {
	if m.GetSnapshotBlockPublicAccessStateFunc != nil {
		return m.GetSnapshotBlockPublicAccessStateFunc(ctx, params, optFns...)
	}
	return &ec2.GetSnapshotBlockPublicAccessStateOutput{State: ec2types.SnapshotBlockPublicAccessStateUnblocked}, nil
}

func TestEC2Collector_CollectSecurityGroups(t *testing.T) {
	tests := []struct {
		name      string
		mockSGs   []ec2types.SecurityGroup
		mockErr   error
		wantCount int
		wantError bool
	}{
		{
			name: "SG open SSH to world",
			mockSGs: []ec2types.SecurityGroup{
				{
					GroupId:   awssdk.String("sg-123"),
					GroupName: awssdk.String("open-ssh"),
					VpcId:    awssdk.String("vpc-abc"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: awssdk.String("tcp"),
							FromPort:   awssdk.Int32(22),
							ToPort:     awssdk.Int32(22),
							IpRanges: []ec2types.IpRange{
								{CidrIp: awssdk.String("0.0.0.0/0")},
							},
						},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "SG with restricted access",
			mockSGs: []ec2types.SecurityGroup{
				{
					GroupId:   awssdk.String("sg-456"),
					GroupName: awssdk.String("restricted"),
					VpcId:    awssdk.String("vpc-abc"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: awssdk.String("tcp"),
							FromPort:   awssdk.Int32(443),
							ToPort:     awssdk.Int32(443),
							IpRanges: []ec2types.IpRange{
								{CidrIp: awssdk.String("10.0.0.0/8")},
							},
						},
					},
				},
			},
			wantCount: 1,
		},
		{
			name:      "no security groups",
			mockSGs:   []ec2types.SecurityGroup{},
			wantCount: 0,
		},
		{
			name:      "API error",
			mockErr:   errors.New("access denied"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockEC2Client{
				DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: tt.mockSGs}, nil
				},
			}

			collector := NewEC2Collector(mock, "us-east-1")
			sgs, err := collector.CollectSecurityGroups(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, sgs, tt.wantCount)

			if tt.name == "SG open SSH to world" {
				assert.True(t, sgs[0].OpenSSH, "should detect open SSH")
				assert.True(t, sgs[0].OpenToAll, "should detect open to all")
				assert.False(t, sgs[0].OpenRDP, "should not flag RDP")
			}
			if tt.name == "SG with restricted access" {
				assert.False(t, sgs[0].OpenSSH)
				assert.False(t, sgs[0].OpenToAll)
			}
		})
	}
}

func TestEC2Collector_CollectSecurityGroups_OpenRDP(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId:   awssdk.String("sg-rdp"),
						GroupName: awssdk.String("open-rdp"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: awssdk.String("tcp"),
								FromPort:   awssdk.Int32(3389),
								ToPort:     awssdk.Int32(3389),
								IpRanges: []ec2types.IpRange{
									{CidrIp: awssdk.String("0.0.0.0/0")},
								},
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	sgs, err := collector.CollectSecurityGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, sgs, 1)
	assert.True(t, sgs[0].OpenRDP)
	assert.False(t, sgs[0].OpenSSH)
}

func TestEC2Collector_CollectSecurityGroups_AllProtocol(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId:   awssdk.String("sg-all"),
						GroupName: awssdk.String("all-traffic"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: awssdk.String("-1"),
								IpRanges: []ec2types.IpRange{
									{CidrIp: awssdk.String("0.0.0.0/0")},
								},
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	sgs, err := collector.CollectSecurityGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, sgs, 1)
	assert.True(t, sgs[0].OpenSSH, "all protocol should flag SSH")
	assert.True(t, sgs[0].OpenRDP, "all protocol should flag RDP")
	assert.True(t, sgs[0].OpenToAll)
}

func TestEC2Collector_CollectVPCs(t *testing.T) {
	mock := &MockEC2Client{
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []ec2types.Vpc{
					{VpcId: awssdk.String("vpc-1"), IsDefault: awssdk.Bool(true), CidrBlock: awssdk.String("172.31.0.0/16")},
					{VpcId: awssdk.String("vpc-2"), IsDefault: awssdk.Bool(false), CidrBlock: awssdk.String("10.0.0.0/16")},
				},
			}, nil
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			// Verify the filter uses resource-id (not the invalid resource-type)
			require.Len(t, params.Filter, 1)
			assert.Equal(t, "resource-id", awssdk.ToString(params.Filter[0].Name))
			assert.ElementsMatch(t, []string{"vpc-1", "vpc-2"}, params.Filter[0].Values)
			return &ec2.DescribeFlowLogsOutput{
				FlowLogs: []ec2types.FlowLog{
					{ResourceId: awssdk.String("vpc-2")},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	vpcs, err := collector.CollectVPCs(context.Background())

	require.NoError(t, err)
	require.Len(t, vpcs, 2)

	assert.True(t, vpcs[0].IsDefault)
	assert.False(t, vpcs[0].FlowLogsEnabled, "vpc-1 should not have flow logs")

	assert.False(t, vpcs[1].IsDefault)
	assert.True(t, vpcs[1].FlowLogsEnabled, "vpc-2 should have flow logs")
}

func TestEC2Collector_CollectVPCs_FlowLogsError(t *testing.T) {
	mock := &MockEC2Client{
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []ec2types.Vpc{
					{VpcId: awssdk.String("vpc-1"), IsDefault: awssdk.Bool(false), CidrBlock: awssdk.String("10.0.0.0/16")},
				},
			}, nil
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			return nil, errors.New("flow logs access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	vpcs, err := collector.CollectVPCs(context.Background())

	require.NoError(t, err, "should handle flow logs error gracefully")
	require.Len(t, vpcs, 1)
	assert.False(t, vpcs[0].FlowLogsEnabled)
}

func TestEC2Collector_CollectEBSEncryption(t *testing.T) {
	tests := []struct {
		name           string
		encEnabled     *bool
		kmsKey         string
		encErr         error
		kmsErr         error
		wantEncryption bool
		wantKMSKey     string
	}{
		{
			name:           "encryption enabled with custom KMS key",
			encEnabled:     awssdk.Bool(true),
			kmsKey:         "arn:aws:kms:us-east-1:123:key/abc",
			wantEncryption: true,
			wantKMSKey:     "arn:aws:kms:us-east-1:123:key/abc",
		},
		{
			name:           "encryption disabled",
			encEnabled:     awssdk.Bool(false),
			wantEncryption: false,
		},
		{
			name:           "API error returns false",
			encErr:         errors.New("access denied"),
			wantEncryption: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockEC2Client{
				GetEbsEncryptionByDefaultFunc: func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
					if tt.encErr != nil {
						return nil, tt.encErr
					}
					return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: tt.encEnabled}, nil
				},
				GetEbsDefaultKmsKeyIDFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
					if tt.kmsErr != nil {
						return nil, tt.kmsErr
					}
					return &ec2.GetEbsDefaultKmsKeyIdOutput{KmsKeyId: awssdk.String(tt.kmsKey)}, nil
				},
			}

			collector := NewEC2Collector(mock, "us-east-1")
			config, err := collector.CollectEBSEncryption(context.Background())

			require.NoError(t, err, "CollectEBSEncryption should never error")
			assert.Equal(t, tt.wantEncryption, config.EncryptionByDefault)
			assert.Equal(t, "us-east-1", config.Region)
			if tt.wantKMSKey != "" {
				assert.Equal(t, tt.wantKMSKey, config.DefaultKMSKeyID)
			}
		})
	}
}

func TestEC2Collector_CollectEvidence(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("test")},
				},
			}, nil
		},
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []ec2types.Vpc{
					{VpcId: awssdk.String("vpc-1"), CidrBlock: awssdk.String("10.0.0.0/16")},
				},
			}, nil
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			return &ec2.DescribeFlowLogsOutput{}, nil
		},
		GetEbsEncryptionByDefaultFunc: func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
			return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: awssdk.Bool(true)}, nil
		},
		GetEbsDefaultKmsKeyIDFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return &ec2.GetEbsDefaultKmsKeyIdOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(ev), 3, "should have at least SG + VPC + EBS evidence")
}

func TestEC2Collector_CollectEBSSnapshots(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSnapshotsFunc: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{
				Snapshots: []ec2types.Snapshot{
					{
						SnapshotId: awssdk.String("snap-123"),
						VolumeId:   awssdk.String("vol-abc"),
						Encrypted:  awssdk.Bool(true),
					},
					{
						SnapshotId: awssdk.String("snap-456"),
						VolumeId:   awssdk.String("vol-def"),
						Encrypted:  awssdk.Bool(false),
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	snapshots, err := collector.CollectEBSSnapshots(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, snapshots, 2)
	assert.Equal(t, "snap-123", snapshots[0].SnapshotID)
	assert.True(t, snapshots[0].Encrypted)
	assert.False(t, snapshots[0].Public)
	assert.Equal(t, "snap-456", snapshots[1].SnapshotID)
	assert.False(t, snapshots[1].Encrypted)
}

func TestEC2Collector_CollectEBSSnapshots_Error(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSnapshotsFunc: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectEBSSnapshots(context.Background(), "123456789012")
	assert.Error(t, err)
}

func TestEBSSnapshot_ToEvidence(t *testing.T) {
	snap := &EBSSnapshot{SnapshotID: "snap-123", Encrypted: true}
	ev := snap.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ec2:ebs_snapshot", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "snap-123")
}

func TestSecurityGroup_ToEvidence(t *testing.T) {
	sg := &SecurityGroup{
		GroupID:   "sg-123",
		GroupName: "test-sg",
		OpenSSH:   true,
	}

	ev := sg.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ec2:security-group", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "sg-123")
	assert.NotEmpty(t, ev.Hash)
}

func TestPortInRange(t *testing.T) {
	assert.True(t, portInRange("22", 22))
	assert.True(t, portInRange("20-25", 22))
	assert.False(t, portInRange("80-443", 22))
	assert.False(t, portInRange("invalid", 22))
	assert.True(t, portInRange("3389", 3389))
}

// --- Negative Tests ---

func TestEC2Collector_CollectEvidence_SGFailsVPCAndEBSSucceed(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return nil, errors.New("security groups access denied")
		},
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []ec2types.Vpc{{VpcId: awssdk.String("vpc-1"), CidrBlock: awssdk.String("10.0.0.0/16")}},
			}, nil
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			return &ec2.DescribeFlowLogsOutput{}, nil
		},
		GetEbsEncryptionByDefaultFunc: func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
			return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: awssdk.Bool(true)}, nil
		},
		GetEbsDefaultKmsKeyIDFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return &ec2.GetEbsDefaultKmsKeyIdOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectEvidence(context.Background(), "123456789012")

	// SG failure is NOT fail-safe — it returns error and stops
	assert.Error(t, err, "SG collection is critical, should propagate error")
}

func TestEC2Collector_CollectEvidence_VPCFailsOthersSucceed(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("test")},
				},
			}, nil
		},
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return nil, errors.New("VPC access denied")
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			return &ec2.DescribeFlowLogsOutput{}, nil
		},
		GetEbsEncryptionByDefaultFunc: func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
			return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: awssdk.Bool(true)}, nil
		},
		GetEbsDefaultKmsKeyIDFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return &ec2.GetEbsDefaultKmsKeyIdOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err, "VPC failure is fail-safe, should not error")
	// SG(1) + EBS(1) + VPCEndpointStatus(1) = 3
	assert.GreaterOrEqual(t, len(ev), 2, "should have at least SG + EBS evidence (VPC skipped)")
}

func TestEC2Collector_CollectEvidence_EBSFailsOthersSucceed(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("test")},
				},
			}, nil
		},
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return &ec2.DescribeVpcsOutput{
				Vpcs: []ec2types.Vpc{{VpcId: awssdk.String("vpc-1"), CidrBlock: awssdk.String("10.0.0.0/16")}},
			}, nil
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			return &ec2.DescribeFlowLogsOutput{}, nil
		},
		GetEbsEncryptionByDefaultFunc: func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
			// EBS encryption check returns false on error (never errors)
			return nil, errors.New("access denied")
		},
		GetEbsDefaultKmsKeyIDFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err, "EBS failure is fail-safe")
	// SG(1) + VPC(1) + EBS(1) + VPCEndpointStatus(1) = 4
	assert.GreaterOrEqual(t, len(ev), 3, "should have SG + VPC + EBS evidence (EBS defaults to false)")
}

func TestEC2Collector_CollectEvidence_AllFail(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return nil, errors.New("SG error")
		},
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return nil, errors.New("VPC error")
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			return nil, errors.New("flow logs error")
		},
		GetEbsEncryptionByDefaultFunc: func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
			return nil, errors.New("EBS error")
		},
		GetEbsDefaultKmsKeyIDFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return nil, errors.New("KMS key error")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectEvidence(context.Background(), "123456789012")

	// SG is critical, so this errors
	assert.Error(t, err, "should fail because SG collection is critical")
}

func TestEC2Collector_CollectSecurityGroups_NilFields(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						// All pointer fields nil
						GroupId:   nil,
						GroupName: nil,
						VpcId:    nil,
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: nil,
								FromPort:   nil,
								ToPort:     nil,
								IpRanges:   nil,
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	sgs, err := collector.CollectSecurityGroups(context.Background())

	require.NoError(t, err, "should handle nil fields gracefully")
	require.Len(t, sgs, 1)
	assert.Equal(t, "", sgs[0].GroupID)
	assert.Equal(t, "", sgs[0].GroupName)
	assert.False(t, sgs[0].OpenSSH)
	assert.False(t, sgs[0].OpenRDP)
}

func TestEC2Collector_CollectSecurityGroups_PortRange(t *testing.T) {
	// SG with a wide port range that includes both SSH and RDP
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId:   awssdk.String("sg-wide"),
						GroupName: awssdk.String("wide-range"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: awssdk.String("tcp"),
								FromPort:   awssdk.Int32(1),
								ToPort:     awssdk.Int32(65535),
								IpRanges: []ec2types.IpRange{
									{CidrIp: awssdk.String("0.0.0.0/0")},
								},
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	sgs, err := collector.CollectSecurityGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, sgs, 1)
	assert.True(t, sgs[0].OpenSSH, "wide range should include SSH")
	assert.True(t, sgs[0].OpenRDP, "wide range should include RDP")
	assert.True(t, sgs[0].OpenToAll)
}

func TestEC2Collector_CollectEBSEncryption_KMSKeyError(t *testing.T) {
	// EBS encryption is enabled, but KMS key query fails
	mock := &MockEC2Client{
		GetEbsEncryptionByDefaultFunc: func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
			return &ec2.GetEbsEncryptionByDefaultOutput{EbsEncryptionByDefault: awssdk.Bool(true)}, nil
		},
		GetEbsDefaultKmsKeyIDFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return nil, errors.New("access denied to KMS")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	config, err := collector.CollectEBSEncryption(context.Background())

	require.NoError(t, err, "KMS key error is fail-safe")
	assert.True(t, config.EncryptionByDefault, "encryption status should still be reported")
	assert.Empty(t, config.DefaultKMSKeyID, "KMS key should be empty on error")
}

func TestEC2Collector_CollectVPCs_DescribeVPCsError(t *testing.T) {
	mock := &MockEC2Client{
		DescribeVpcsFunc: func(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
			return nil, errors.New("VPC service unavailable")
		},
		DescribeFlowLogsFunc: func(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
			return &ec2.DescribeFlowLogsOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectVPCs(context.Background())

	assert.Error(t, err, "DescribeVpcs error should propagate")
	assert.Contains(t, err.Error(), "failed to describe VPCs")
}

func TestEC2Collector_CollectSecurityGroups_UDPProtocol(t *testing.T) {
	// UDP port 22 open to world should NOT flag OpenSSH (SSH is TCP only)
	mock := &MockEC2Client{
		DescribeSecurityGroupsFunc: func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
			return &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId:   awssdk.String("sg-udp"),
						GroupName: awssdk.String("udp-22"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: awssdk.String("udp"),
								FromPort:   awssdk.Int32(22),
								ToPort:     awssdk.Int32(22),
								IpRanges: []ec2types.IpRange{
									{CidrIp: awssdk.String("0.0.0.0/0")},
								},
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	sgs, err := collector.CollectSecurityGroups(context.Background())

	require.NoError(t, err)
	require.Len(t, sgs, 1)
	assert.True(t, sgs[0].OpenToAll, "should still be open to all")
	assert.False(t, sgs[0].OpenSSH, "UDP port 22 should not flag SSH")
	assert.False(t, sgs[0].OpenRDP, "UDP should not flag RDP")
}

func TestPortInRange_EdgeCases(t *testing.T) {
	assert.True(t, portInRange("0-65535", 0))
	assert.True(t, portInRange("0-65535", 65535))
	assert.True(t, portInRange("0", 0))
	assert.False(t, portInRange("", 22))
	assert.False(t, portInRange("-1", 22))
}

// --- EC2 Instance / IMDSv2 tests ---

func TestEC2Collector_CollectInstances(t *testing.T) {
	mock := &MockEC2Client{
		DescribeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId: awssdk.String("i-123"),
								Tags: []ec2types.Tag{
									{Key: awssdk.String("Name"), Value: awssdk.String("web-server")},
								},
								MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
									HttpTokens:   ec2types.HttpTokensStateRequired,
									HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
								},
							},
							{
								InstanceId: awssdk.String("i-456"),
								MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
									HttpTokens:   ec2types.HttpTokensStateOptional,
									HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
								},
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	instances, err := collector.CollectInstances(context.Background())

	require.NoError(t, err)
	require.Len(t, instances, 2)

	assert.Equal(t, "i-123", instances[0].InstanceID)
	assert.Equal(t, "web-server", instances[0].Name)
	assert.Equal(t, "required", instances[0].HTTPTokens)

	assert.Equal(t, "i-456", instances[1].InstanceID)
	assert.Equal(t, "", instances[1].Name)
	assert.Equal(t, "optional", instances[1].HTTPTokens)
}

func TestEC2Collector_CollectInstances_PublicIP(t *testing.T) {
	mock := &MockEC2Client{
		DescribeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      awssdk.String("i-public"),
								PublicIpAddress: awssdk.String("54.123.45.67"),
								MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
									HttpTokens:   ec2types.HttpTokensStateRequired,
									HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
								},
							},
							{
								InstanceId: awssdk.String("i-private"),
								MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
									HttpTokens:   ec2types.HttpTokensStateRequired,
									HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
								},
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	instances, err := collector.CollectInstances(context.Background())

	require.NoError(t, err)
	require.Len(t, instances, 2)

	assert.Equal(t, "54.123.45.67", instances[0].PublicIP, "instance with public IP should capture it")
	assert.Empty(t, instances[1].PublicIP, "instance without public IP should have empty string")
}

func TestEC2Collector_CollectEBSSnapshots_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockEC2Client{
		DescribeSnapshotsFunc: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			callCount++
			if callCount == 1 {
				return &ec2.DescribeSnapshotsOutput{
					Snapshots: []ec2types.Snapshot{
						{SnapshotId: awssdk.String("snap-1"), VolumeId: awssdk.String("vol-1"), Encrypted: awssdk.Bool(true)},
					},
					NextToken: awssdk.String("token1"),
				}, nil
			}
			return &ec2.DescribeSnapshotsOutput{
				Snapshots: []ec2types.Snapshot{
					{SnapshotId: awssdk.String("snap-2"), VolumeId: awssdk.String("vol-2"), Encrypted: awssdk.Bool(false)},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	snapshots, err := collector.CollectEBSSnapshots(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, snapshots, 2)
	assert.Equal(t, "snap-1", snapshots[0].SnapshotID)
	assert.Equal(t, "snap-2", snapshots[1].SnapshotID)
	assert.Equal(t, 2, callCount, "should have paginated with 2 API calls")
}

func TestEC2Collector_CollectInstances_Error(t *testing.T) {
	mock := &MockEC2Client{
		DescribeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectInstances(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to describe EC2 instances")
}

func TestEC2Collector_CollectInstances_NoInstances(t *testing.T) {
	mock := &MockEC2Client{
		DescribeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
			return &ec2.DescribeInstancesOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	instances, err := collector.CollectInstances(context.Background())

	require.NoError(t, err)
	assert.Empty(t, instances)
}

func TestEC2Instance_ToEvidence(t *testing.T) {
	instance := &EC2Instance{
		InstanceID: "i-123",
		Name:       "web-server",
		HTTPTokens: "required",
	}

	ev := instance.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ec2:instance", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "i-123")
	assert.NotEmpty(t, ev.Hash)
}

func TestEC2Collector_CollectClientVPNEndpoints(t *testing.T) {
	mock := &MockEC2Client{
		DescribeClientVpnEndpointsFunc: func(ctx context.Context, params *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error) {
			return &ec2.DescribeClientVpnEndpointsOutput{
				ClientVpnEndpoints: []ec2types.ClientVpnEndpoint{
					{
						ClientVpnEndpointId: awssdk.String("cvpn-endpoint-123"),
						ConnectionLogOptions: &ec2types.ConnectionLogResponseOptions{
							Enabled: awssdk.Bool(true),
						},
					},
					{
						ClientVpnEndpointId: awssdk.String("cvpn-endpoint-456"),
						ConnectionLogOptions: &ec2types.ConnectionLogResponseOptions{
							Enabled: awssdk.Bool(false),
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	endpoints, err := collector.CollectClientVPNEndpoints(context.Background())

	require.NoError(t, err)
	require.Len(t, endpoints, 2)

	assert.Equal(t, "cvpn-endpoint-123", endpoints[0].ClientVpnEndpointID)
	assert.True(t, endpoints[0].ConnectionLoggingEnabled)

	assert.Equal(t, "cvpn-endpoint-456", endpoints[1].ClientVpnEndpointID)
	assert.False(t, endpoints[1].ConnectionLoggingEnabled)
}

func TestEC2Collector_CollectClientVPNEndpoints_NoLogOptions(t *testing.T) {
	mock := &MockEC2Client{
		DescribeClientVpnEndpointsFunc: func(ctx context.Context, params *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error) {
			return &ec2.DescribeClientVpnEndpointsOutput{
				ClientVpnEndpoints: []ec2types.ClientVpnEndpoint{
					{
						ClientVpnEndpointId:  awssdk.String("cvpn-endpoint-789"),
						ConnectionLogOptions: nil,
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	endpoints, err := collector.CollectClientVPNEndpoints(context.Background())

	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	assert.Equal(t, "cvpn-endpoint-789", endpoints[0].ClientVpnEndpointID)
	assert.False(t, endpoints[0].ConnectionLoggingEnabled, "nil ConnectionLogOptions should default to false")
}

func TestEC2Collector_CollectClientVPNEndpoints_Error(t *testing.T) {
	mock := &MockEC2Client{
		DescribeClientVpnEndpointsFunc: func(ctx context.Context, params *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectClientVPNEndpoints(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to describe Client VPN endpoints")
}

func TestClientVPNEndpoint_ToEvidence(t *testing.T) {
	ep := &ClientVPNEndpoint{
		ClientVpnEndpointID:      "cvpn-endpoint-123",
		ConnectionLoggingEnabled: true,
	}

	ev := ep.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ec2:client-vpn-endpoint", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "cvpn-endpoint-123")
	assert.Equal(t, "123456789012", ev.Metadata.AccountID)
	assert.NotEmpty(t, ev.Hash)
}

// --- EBS Volume Tests ---

func TestEC2Collector_CollectVolumes(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSnapshotsFunc: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{
				Snapshots: []ec2types.Snapshot{
					{SnapshotId: awssdk.String("snap-1"), VolumeId: awssdk.String("vol-1")},
				},
			}, nil
		},
		DescribeVolumesFunc: func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
			return &ec2.DescribeVolumesOutput{
				Volumes: []ec2types.Volume{
					{VolumeId: awssdk.String("vol-1"), Encrypted: awssdk.Bool(true)},
					{VolumeId: awssdk.String("vol-2"), Encrypted: awssdk.Bool(false)},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	volumes, err := collector.CollectVolumes(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, volumes, 2)
	assert.Equal(t, "vol-1", volumes[0].VolumeID)
	assert.True(t, volumes[0].Encrypted)
	assert.True(t, volumes[0].HasSnapshots, "vol-1 should have snapshots")
	assert.Equal(t, "vol-2", volumes[1].VolumeID)
	assert.False(t, volumes[1].Encrypted)
	assert.False(t, volumes[1].HasSnapshots, "vol-2 should not have snapshots")
}

func TestEC2Collector_CollectVolumes_Error(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSnapshotsFunc: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{}, nil
		},
		DescribeVolumesFunc: func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectVolumes(context.Background(), "123456789012")
	assert.Error(t, err)
}

func TestEC2Collector_CollectVolumes_Empty(t *testing.T) {
	mock := &MockEC2Client{
		DescribeSnapshotsFunc: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{}, nil
		},
		DescribeVolumesFunc: func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
			return &ec2.DescribeVolumesOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	volumes, err := collector.CollectVolumes(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Empty(t, volumes)
}

func TestEBSVolume_ToEvidence(t *testing.T) {
	vol := &EBSVolume{VolumeID: "vol-123", Encrypted: true, HasSnapshots: true}
	ev := vol.ToEvidence("123456789012")
	assert.Equal(t, "aws:ec2:volume", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "vol-123")
}

// --- AMI Tests ---

func TestEC2Collector_CollectAMIs(t *testing.T) {
	mock := &MockEC2Client{
		DescribeImagesFunc: func(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
			assert.Contains(t, params.Owners, "self")
			return &ec2.DescribeImagesOutput{
				Images: []ec2types.Image{
					{ImageId: awssdk.String("ami-123"), Public: awssdk.Bool(false)},
					{ImageId: awssdk.String("ami-456"), Public: awssdk.Bool(true)},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	amis, err := collector.CollectAMIs(context.Background())

	require.NoError(t, err)
	require.Len(t, amis, 2)
	assert.Equal(t, "ami-123", amis[0].ImageID)
	assert.False(t, amis[0].Public)
	assert.Equal(t, "ami-456", amis[1].ImageID)
	assert.True(t, amis[1].Public)
}

func TestEC2Collector_CollectAMIs_Error(t *testing.T) {
	mock := &MockEC2Client{
		DescribeImagesFunc: func(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectAMIs(context.Background())
	assert.Error(t, err)
}

func TestEC2AMI_ToEvidence(t *testing.T) {
	ami := &EC2AMI{ImageID: "ami-123", Public: true}
	ev := ami.ToEvidence("123456789012")
	assert.Equal(t, "aws:ec2:ami", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "ami-123")
}

// --- Transit Gateway Tests ---

func TestEC2Collector_CollectTransitGateways(t *testing.T) {
	mock := &MockEC2Client{
		DescribeTransitGatewaysFunc: func(ctx context.Context, params *ec2.DescribeTransitGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error) {
			return &ec2.DescribeTransitGatewaysOutput{
				TransitGateways: []ec2types.TransitGateway{
					{
						TransitGatewayId: awssdk.String("tgw-1"),
						Options: &ec2types.TransitGatewayOptions{
							AutoAcceptSharedAttachments: ec2types.AutoAcceptSharedAttachmentsValueEnable,
						},
					},
					{
						TransitGatewayId: awssdk.String("tgw-2"),
						Options: &ec2types.TransitGatewayOptions{
							AutoAcceptSharedAttachments: ec2types.AutoAcceptSharedAttachmentsValueDisable,
						},
					},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	gateways, err := collector.CollectTransitGateways(context.Background())

	require.NoError(t, err)
	require.Len(t, gateways, 2)
	assert.Equal(t, "tgw-1", gateways[0].TransitGatewayID)
	assert.True(t, gateways[0].AutoAcceptSharedAttachments)
	assert.Equal(t, "tgw-2", gateways[1].TransitGatewayID)
	assert.False(t, gateways[1].AutoAcceptSharedAttachments)
}

func TestEC2Collector_CollectTransitGateways_NilOptions(t *testing.T) {
	mock := &MockEC2Client{
		DescribeTransitGatewaysFunc: func(ctx context.Context, params *ec2.DescribeTransitGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error) {
			return &ec2.DescribeTransitGatewaysOutput{
				TransitGateways: []ec2types.TransitGateway{
					{TransitGatewayId: awssdk.String("tgw-nil"), Options: nil},
				},
			}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	gateways, err := collector.CollectTransitGateways(context.Background())

	require.NoError(t, err)
	require.Len(t, gateways, 1)
	assert.False(t, gateways[0].AutoAcceptSharedAttachments, "nil options should default to false")
}

func TestEC2Collector_CollectTransitGateways_Error(t *testing.T) {
	mock := &MockEC2Client{
		DescribeTransitGatewaysFunc: func(ctx context.Context, params *ec2.DescribeTransitGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	_, err := collector.CollectTransitGateways(context.Background())
	assert.Error(t, err)
}

func TestTransitGateway_ToEvidence(t *testing.T) {
	tg := &TransitGateway{TransitGatewayID: "tgw-123", AutoAcceptSharedAttachments: true}
	ev := tg.ToEvidence("123456789012")
	assert.Equal(t, "aws:ec2:transit-gateway", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "tgw-123")
}

// --- Account Settings Tests ---

func TestEC2Collector_CollectAccountSettings(t *testing.T) {
	tests := []struct {
		name             string
		state            ec2types.SnapshotBlockPublicAccessState
		apiErr           error
		wantBlockPublic  bool
	}{
		{
			name:            "block all sharing",
			state:           ec2types.SnapshotBlockPublicAccessStateBlockAllSharing,
			wantBlockPublic: true,
		},
		{
			name:            "block new sharing only",
			state:           ec2types.SnapshotBlockPublicAccessStateBlockNewSharing,
			wantBlockPublic: false,
		},
		{
			name:            "unblocked",
			state:           ec2types.SnapshotBlockPublicAccessStateUnblocked,
			wantBlockPublic: false,
		},
		{
			name:            "API error (fail-safe)",
			apiErr:          errors.New("access denied"),
			wantBlockPublic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockEC2Client{
				GetSnapshotBlockPublicAccessStateFunc: func(ctx context.Context, params *ec2.GetSnapshotBlockPublicAccessStateInput, optFns ...func(*ec2.Options)) (*ec2.GetSnapshotBlockPublicAccessStateOutput, error) {
					if tt.apiErr != nil {
						return nil, tt.apiErr
					}
					return &ec2.GetSnapshotBlockPublicAccessStateOutput{State: tt.state}, nil
				},
			}

			collector := NewEC2Collector(mock, "us-east-1")
			setting, err := collector.CollectAccountSettings(context.Background())

			require.NoError(t, err, "CollectAccountSettings should never error")
			assert.Equal(t, tt.wantBlockPublic, setting.EBSBlockPublicAccess)
			assert.Equal(t, "us-east-1", setting.Region)
		})
	}
}

func TestEC2AccountSetting_ToEvidence(t *testing.T) {
	setting := &EC2AccountSetting{EBSBlockPublicAccess: true, Region: "us-east-1"}
	ev := setting.ToEvidence("123456789012")
	assert.Equal(t, "aws:ec2:account-setting", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "account-setting")
}
