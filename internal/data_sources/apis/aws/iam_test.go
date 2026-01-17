package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockIAMClient is a mock implementation of IAMClient for testing.
type MockIAMClient struct {
	ListUsersFunc      func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListMFADevicesFunc func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
}

func (m *MockIAMClient) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return m.ListUsersFunc(ctx, params, optFns...)
}

func (m *MockIAMClient) ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	return m.ListMFADevicesFunc(ctx, params, optFns...)
}

func TestIAMCollector_CollectUsers(t *testing.T) {
	tests := []struct {
		name           string
		mockUsers      []types.User
		mockMFADevices map[string][]types.MFADevice // username -> devices
		wantCount      int
		wantError      bool
	}{
		{
			name: "users with and without MFA",
			mockUsers: []types.User{
				{UserName: aws.String("alice"), Arn: aws.String("arn:aws:iam::123456789012:user/alice")},
				{UserName: aws.String("bob"), Arn: aws.String("arn:aws:iam::123456789012:user/bob")},
			},
			mockMFADevices: map[string][]types.MFADevice{
				"alice": {{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/alice")}},
				"bob":   {}, // No MFA
			},
			wantCount: 2,
			wantError: false,
		},
		{
			name:      "no users",
			mockUsers: []types.User{},
			wantCount: 0,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockIAM := &MockIAMClient{
				ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
					return &iam.ListUsersOutput{
						Users:       tt.mockUsers,
						IsTruncated: false,
					}, nil
				},
				ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
					devices := tt.mockMFADevices[*params.UserName]
					return &iam.ListMFADevicesOutput{
						MFADevices: devices,
					}, nil
				},
			}

			collector := &IAMCollector{client: mockIAM}
			users, err := collector.CollectUsers(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, users, tt.wantCount)

			if tt.wantCount > 0 {
				// Check alice has MFA enabled
				for _, u := range users {
					if u.UserName == "alice" {
						assert.True(t, u.MFAEnabled, "alice should have MFA enabled")
					}
					if u.UserName == "bob" {
						assert.False(t, u.MFAEnabled, "bob should not have MFA enabled")
					}
				}
			}
		})
	}
}

func TestIAMCollector_CollectUsers_Pagination(t *testing.T) {
	callCount := 0
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			callCount++
			if callCount == 1 {
				return &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("user1"), Arn: aws.String("arn:aws:iam::123456789012:user/user1")},
					},
					IsTruncated: true,
					Marker:      aws.String("marker1"),
				}, nil
			}
			return &iam.ListUsersOutput{
				Users: []types.User{
					{UserName: aws.String("user2"), Arn: aws.String("arn:aws:iam::123456789012:user/user2")},
				},
				IsTruncated: false,
			}, nil
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{}}, nil
		},
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, 2, callCount, "should have made 2 API calls for pagination")
}

func TestIAMCollector_CollectUsers_APIError(t *testing.T) {
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := &IAMCollector{client: mockIAM}
	_, err := collector.CollectUsers(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestIAMCollector_ToEvidence(t *testing.T) {
	user := IAMUser{
		UserName:   "alice",
		ARN:        "arn:aws:iam::123456789012:user/alice",
		UserID:     "AIDAEXAMPLE",
		MFAEnabled: true,
		MFADevices: []string{"arn:aws:iam::123456789012:mfa/alice"},
	}

	evidence := user.ToEvidence("123456789012")

	assert.Equal(t, "aws", evidence.Collector)
	assert.Equal(t, "aws:iam:user", evidence.ResourceType)
	assert.Equal(t, "arn:aws:iam::123456789012:user/alice", evidence.ResourceID)
	assert.Equal(t, "123456789012", evidence.Metadata.AccountID)
	assert.NotEmpty(t, evidence.Hash)
	assert.NotEmpty(t, evidence.Data)
}
