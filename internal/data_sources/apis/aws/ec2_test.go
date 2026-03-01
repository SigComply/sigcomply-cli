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
	GetEbsDefaultKmsKeyIdFunc     func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error)
	GetEbsEncryptionByDefaultFunc func(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
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

func (m *MockEC2Client) GetEbsDefaultKmsKeyId(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
	return m.GetEbsDefaultKmsKeyIdFunc(ctx, params, optFns...)
}

func (m *MockEC2Client) GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	return m.GetEbsEncryptionByDefaultFunc(ctx, params, optFns...)
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
				GetEbsDefaultKmsKeyIdFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
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
		GetEbsDefaultKmsKeyIdFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return &ec2.GetEbsDefaultKmsKeyIdOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 3, "should have SG + VPC + EBS evidence")
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
		GetEbsDefaultKmsKeyIdFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
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
		GetEbsDefaultKmsKeyIdFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return &ec2.GetEbsDefaultKmsKeyIdOutput{}, nil
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err, "VPC failure is fail-safe, should not error")
	assert.Len(t, ev, 2, "should have SG + EBS evidence (VPC skipped)")
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
		GetEbsDefaultKmsKeyIdFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEC2Collector(mock, "us-east-1")
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err, "EBS failure is fail-safe")
	assert.Len(t, ev, 3, "should have SG + VPC + EBS evidence (EBS defaults to false)")
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
		GetEbsDefaultKmsKeyIdFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
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
		GetEbsDefaultKmsKeyIdFunc: func(ctx context.Context, params *ec2.GetEbsDefaultKmsKeyIdInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsDefaultKmsKeyIdOutput, error) {
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
