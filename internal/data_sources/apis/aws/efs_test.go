package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockEFSClient struct {
	DescribeFileSystemsFunc  func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
	DescribeBackupPolicyFunc func(ctx context.Context, params *efs.DescribeBackupPolicyInput, optFns ...func(*efs.Options)) (*efs.DescribeBackupPolicyOutput, error)
}

func (m *MockEFSClient) DescribeFileSystems(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	return m.DescribeFileSystemsFunc(ctx, params, optFns...)
}

func (m *MockEFSClient) DescribeBackupPolicy(ctx context.Context, params *efs.DescribeBackupPolicyInput, optFns ...func(*efs.Options)) (*efs.DescribeBackupPolicyOutput, error) {
	if m.DescribeBackupPolicyFunc != nil {
		return m.DescribeBackupPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

func TestEFSCollector_CollectFileSystems(t *testing.T) {
	mock := &MockEFSClient{
		DescribeFileSystemsFunc: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{
						FileSystemId:  awssdk.String("fs-123"),
						FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-123"),
						Name:          awssdk.String("prod-efs"),
						Encrypted:     awssdk.Bool(true),
						KmsKeyId:      awssdk.String("arn:aws:kms:us-east-1:123:key/abc"),
					},
					{
						FileSystemId:  awssdk.String("fs-456"),
						FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-456"),
						Encrypted:     awssdk.Bool(false),
					},
				},
			}, nil
		},
	}

	collector := NewEFSCollector(mock)
	fss, err := collector.CollectFileSystems(context.Background())

	require.NoError(t, err)
	require.Len(t, fss, 2)

	assert.Equal(t, "fs-123", fss[0].FileSystemID)
	assert.True(t, fss[0].Encrypted)
	assert.Equal(t, "prod-efs", fss[0].Name)
	assert.Equal(t, "fs-456", fss[1].FileSystemID)
	assert.False(t, fss[1].Encrypted)
}

func TestEFSCollector_CollectFileSystems_Empty(t *testing.T) {
	mock := &MockEFSClient{
		DescribeFileSystemsFunc: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{FileSystems: []efstypes.FileSystemDescription{}}, nil
		},
	}

	collector := NewEFSCollector(mock)
	fss, err := collector.CollectFileSystems(context.Background())

	require.NoError(t, err)
	assert.Empty(t, fss)
}

func TestEFSCollector_CollectFileSystems_Error(t *testing.T) {
	mock := &MockEFSClient{
		DescribeFileSystemsFunc: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewEFSCollector(mock)
	_, err := collector.CollectFileSystems(context.Background())
	assert.Error(t, err)
}

func TestEFSCollector_CollectFileSystems_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockEFSClient{
		DescribeFileSystemsFunc: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			callCount++
			if callCount == 1 {
				return &efs.DescribeFileSystemsOutput{
					FileSystems: []efstypes.FileSystemDescription{
						{
							FileSystemId:  awssdk.String("fs-111"),
							FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-111"),
							Encrypted:     awssdk.Bool(true),
						},
					},
					NextMarker: awssdk.String("marker1"),
				}, nil
			}
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{
						FileSystemId:  awssdk.String("fs-222"),
						FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-222"),
						Encrypted:     awssdk.Bool(false),
					},
				},
			}, nil
		},
	}

	collector := NewEFSCollector(mock)
	fss, err := collector.CollectFileSystems(context.Background())

	require.NoError(t, err)
	require.Len(t, fss, 2)
	assert.Equal(t, "fs-111", fss[0].FileSystemID)
	assert.Equal(t, "fs-222", fss[1].FileSystemID)
	assert.Equal(t, 2, callCount, "should have paginated with 2 API calls")
}

func TestEFSCollector_CollectFileSystems_NilOptionalFields(t *testing.T) {
	mock := &MockEFSClient{
		DescribeFileSystemsFunc: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{
						FileSystemId:  awssdk.String("fs-nil"),
						FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-nil"),
						Encrypted:     awssdk.Bool(false),
						// Name and KmsKeyId intentionally nil
					},
				},
			}, nil
		},
	}

	collector := NewEFSCollector(mock)
	fss, err := collector.CollectFileSystems(context.Background())

	require.NoError(t, err)
	require.Len(t, fss, 1)
	assert.Equal(t, "", fss[0].Name, "nil Name should result in empty string")
	assert.Equal(t, "", fss[0].KMSKeyID, "nil KmsKeyId should result in empty string")
}

func TestEFSCollector_CollectEvidence(t *testing.T) {
	mock := &MockEFSClient{
		DescribeFileSystemsFunc: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{
						FileSystemId:  awssdk.String("fs-ev1"),
						FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-ev1"),
						Encrypted:     awssdk.Bool(true),
						Name:          awssdk.String("prod-efs"),
					},
					{
						FileSystemId:  awssdk.String("fs-ev2"),
						FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-ev2"),
						Encrypted:     awssdk.Bool(false),
					},
				},
			}, nil
		},
	}

	collector := NewEFSCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 2)
	assert.Equal(t, "aws:efs:file_system", ev[0].ResourceType)
	assert.Equal(t, "aws:efs:file_system", ev[1].ResourceType)
	assert.Equal(t, "123456789012", ev[0].Metadata.AccountID)
}

func TestEFSCollector_CollectEvidence_Error(t *testing.T) {
	mock := &MockEFSClient{
		DescribeFileSystemsFunc: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return nil, errors.New("service unavailable")
		},
	}

	collector := NewEFSCollector(mock)
	_, err := collector.CollectEvidence(context.Background(), "123456789012")
	assert.Error(t, err)
}

func TestEFSFileSystem_ToEvidence(t *testing.T) {
	fs := &EFSFileSystem{
		FileSystemID: "fs-123",
		ARN:          "arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-123",
		Encrypted:    true,
	}
	ev := fs.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:efs:file_system", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
