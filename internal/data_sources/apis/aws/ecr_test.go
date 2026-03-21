package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockECRClient implements ECRClient for testing.
type MockECRClient struct {
	DescribeRepositoriesFunc func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	GetLifecyclePolicyFunc   func(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
}

func (m *MockECRClient) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return m.DescribeRepositoriesFunc(ctx, params, optFns...)
}

func (m *MockECRClient) GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	if m.GetLifecyclePolicyFunc != nil {
		return m.GetLifecyclePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("LifecyclePolicyNotFoundException: no lifecycle policy")
}

func TestECRCollector_CollectRepositories(t *testing.T) {
	tests := []struct {
		name      string
		mockRepos []ecrtypes.Repository
		mockErr   error
		wantCount int
		wantError bool
	}{
		{
			name: "repo with scan-on-push enabled",
			mockRepos: []ecrtypes.Repository{
				{
					RepositoryName: awssdk.String("my-app"),
					RepositoryArn:  awssdk.String("arn:aws:ecr:us-east-1:123:repository/my-app"),
					RegistryId:     awssdk.String("123456789012"),
					ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{
						ScanOnPush: true,
					},
					EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
						EncryptionType: ecrtypes.EncryptionTypeAes256,
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "repo without scan-on-push",
			mockRepos: []ecrtypes.Repository{
				{
					RepositoryName: awssdk.String("legacy-app"),
					RepositoryArn:  awssdk.String("arn:aws:ecr:us-east-1:123:repository/legacy-app"),
					RegistryId:     awssdk.String("123456789012"),
					ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{
						ScanOnPush: false,
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "repo with KMS encryption",
			mockRepos: []ecrtypes.Repository{
				{
					RepositoryName: awssdk.String("secure-app"),
					RepositoryArn:  awssdk.String("arn:aws:ecr:us-east-1:123:repository/secure-app"),
					RegistryId:     awssdk.String("123456789012"),
					EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
						EncryptionType: ecrtypes.EncryptionTypeKms,
						KmsKey:         awssdk.String("arn:aws:kms:us-east-1:123:key/abc"),
					},
				},
			},
			wantCount: 1,
		},
		{
			name:      "no repositories",
			mockRepos: []ecrtypes.Repository{},
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
			mock := &MockECRClient{
				DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return &ecr.DescribeRepositoriesOutput{Repositories: tt.mockRepos}, nil
				},
			}

			collector := NewECRCollector(mock)
			repos, err := collector.CollectRepositories(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, repos, tt.wantCount)

			if tt.name == "repo with scan-on-push enabled" {
				assert.True(t, repos[0].ScanOnPush)
				assert.Equal(t, "AES256", repos[0].EncryptionType)
			}

			if tt.name == "repo without scan-on-push" {
				assert.False(t, repos[0].ScanOnPush)
			}

			if tt.name == "repo with KMS encryption" {
				assert.Equal(t, "KMS", repos[0].EncryptionType)
				assert.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", repos[0].EncryptionKeyID)
			}
		})
	}
}

func TestECRCollector_CollectRepositories_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockECRClient{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			callCount++
			if callCount == 1 {
				return &ecr.DescribeRepositoriesOutput{
					Repositories: []ecrtypes.Repository{
						{RepositoryName: awssdk.String("repo-1"), RepositoryArn: awssdk.String("arn:1"), RegistryId: awssdk.String("123")},
					},
					NextToken: awssdk.String("token1"),
				}, nil
			}
			return &ecr.DescribeRepositoriesOutput{
				Repositories: []ecrtypes.Repository{
					{RepositoryName: awssdk.String("repo-2"), RepositoryArn: awssdk.String("arn:2"), RegistryId: awssdk.String("123")},
				},
			}, nil
		},
	}

	collector := NewECRCollector(mock)
	repos, err := collector.CollectRepositories(context.Background())

	require.NoError(t, err)
	assert.Len(t, repos, 2)
	assert.Equal(t, 2, callCount)
}

func TestECRRepository_ToEvidence(t *testing.T) {
	repo := &ECRRepository{
		Name:       "my-app",
		ARN:        "arn:aws:ecr:us-east-1:123:repository/my-app",
		ScanOnPush: true,
	}

	ev := repo.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ecr:repository", ev.ResourceType)
	assert.Equal(t, "arn:aws:ecr:us-east-1:123:repository/my-app", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}

// --- Negative Tests ---

func TestECRCollector_CollectRepositories_PaginationErrorMidStream(t *testing.T) {
	callCount := 0
	mock := &MockECRClient{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			callCount++
			if callCount == 1 {
				return &ecr.DescribeRepositoriesOutput{
					Repositories: []ecrtypes.Repository{
						{RepositoryName: awssdk.String("repo-1"), RepositoryArn: awssdk.String("arn:1"), RegistryId: awssdk.String("123")},
					},
					NextToken: awssdk.String("token1"),
				}, nil
			}
			return nil, errors.New("throttling on page 2")
		},
	}

	collector := NewECRCollector(mock)
	_, err := collector.CollectRepositories(context.Background())

	assert.Error(t, err, "pagination error should propagate")
	assert.Contains(t, err.Error(), "failed to describe ECR repositories")
}

func TestECRCollector_CollectRepositories_NilScanningAndEncryption(t *testing.T) {
	mock := &MockECRClient{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			return &ecr.DescribeRepositoriesOutput{
				Repositories: []ecrtypes.Repository{
					{
						RepositoryName:             awssdk.String("bare-repo"),
						RepositoryArn:              awssdk.String("arn:bare"),
						RegistryId:                 awssdk.String("123"),
						ImageScanningConfiguration: nil,
						EncryptionConfiguration:    nil,
					},
				},
			}, nil
		},
	}

	collector := NewECRCollector(mock)
	repos, err := collector.CollectRepositories(context.Background())

	require.NoError(t, err, "nil scanning/encryption configs should be handled")
	require.Len(t, repos, 1)
	assert.False(t, repos[0].ScanOnPush, "nil scanning config should default to false")
	assert.Empty(t, repos[0].EncryptionType, "nil encryption config should be empty")
	assert.Empty(t, repos[0].EncryptionKeyID, "nil encryption config should have no key")
}

func TestECRCollector_CollectRepositories_EncryptionWithNilKmsKey(t *testing.T) {
	mock := &MockECRClient{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			return &ecr.DescribeRepositoriesOutput{
				Repositories: []ecrtypes.Repository{
					{
						RepositoryName: awssdk.String("aes-repo"),
						RepositoryArn:  awssdk.String("arn:aes"),
						RegistryId:     awssdk.String("123"),
						EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
							EncryptionType: ecrtypes.EncryptionTypeAes256,
							KmsKey:         nil,
						},
					},
				},
			}, nil
		},
	}

	collector := NewECRCollector(mock)
	repos, err := collector.CollectRepositories(context.Background())

	require.NoError(t, err)
	require.Len(t, repos, 1)
	assert.Equal(t, "AES256", repos[0].EncryptionType)
	assert.Empty(t, repos[0].EncryptionKeyID, "nil KMS key should be empty")
}

func TestECRCollector_CollectEvidence_Error(t *testing.T) {
	mock := &MockECRClient{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewECRCollector(mock)
	_, err := collector.CollectEvidence(context.Background(), "123456789012")

	assert.Error(t, err, "CollectEvidence should propagate error")
}
