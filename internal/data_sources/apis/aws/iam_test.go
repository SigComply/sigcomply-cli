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
	ListUsersFunc       func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListMFADevicesFunc  func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	GetLoginProfileFunc func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
}

func (m *MockIAMClient) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return m.ListUsersFunc(ctx, params, optFns...)
}

func (m *MockIAMClient) ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	return m.ListMFADevicesFunc(ctx, params, optFns...)
}

func (m *MockIAMClient) GetLoginProfile(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	return m.GetLoginProfileFunc(ctx, params, optFns...)
}

func TestIAMCollector_CollectUsers(t *testing.T) {
	tests := []struct {
		name              string
		mockUsers         []types.User
		mockMFADevices    map[string][]types.MFADevice // username -> devices
		mockLoginProfiles map[string]bool              // username -> has login profile
		wantCount         int
		wantError         bool
	}{
		{
			name: "console users with and without MFA",
			mockUsers: []types.User{
				{UserName: aws.String("alice"), Arn: aws.String("arn:aws:iam::123456789012:user/alice")},
				{UserName: aws.String("bob"), Arn: aws.String("arn:aws:iam::123456789012:user/bob")},
			},
			mockMFADevices: map[string][]types.MFADevice{
				"alice": {{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/alice")}},
				"bob":   {}, // No MFA
			},
			mockLoginProfiles: map[string]bool{
				"alice": true, // Console user with MFA
				"bob":   true, // Console user without MFA
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
		{
			name: "programmatic-only user without MFA",
			mockUsers: []types.User{
				{UserName: aws.String("ci-bot"), Arn: aws.String("arn:aws:iam::123456789012:user/ci-bot")},
			},
			mockMFADevices: map[string][]types.MFADevice{
				"ci-bot": {}, // No MFA
			},
			mockLoginProfiles: map[string]bool{
				"ci-bot": false, // No console access
			},
			wantCount: 1,
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
				GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
					hasProfile := tt.mockLoginProfiles[*params.UserName]
					if !hasProfile {
						return nil, &types.NoSuchEntityException{Message: aws.String("Login Profile for User " + *params.UserName + " cannot be found.")}
					}
					return &iam.GetLoginProfileOutput{}, nil
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

			for _, u := range users {
				switch u.UserName {
				case "alice":
					assert.True(t, u.MFAEnabled, "alice should have MFA enabled")
					assert.True(t, u.HasLoginProfile, "alice should have console access")
				case "bob":
					assert.False(t, u.MFAEnabled, "bob should not have MFA enabled")
					assert.True(t, u.HasLoginProfile, "bob should have console access")
				case "ci-bot":
					assert.False(t, u.MFAEnabled, "ci-bot should not have MFA enabled")
					assert.False(t, u.HasLoginProfile, "ci-bot should not have console access")
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
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			return &iam.GetLoginProfileOutput{}, nil
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

func TestIAMCollector_HasLoginProfile_FailSafe(t *testing.T) {
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return &iam.ListUsersOutput{
				Users: []types.User{
					{UserName: aws.String("unknown-user"), Arn: aws.String("arn:aws:iam::123456789012:user/unknown-user")},
				},
				IsTruncated: false,
			}, nil
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{}}, nil
		},
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.True(t, users[0].HasLoginProfile, "should default to true on non-NoSuchEntity errors (fail-safe)")
}

// --- Negative tests ---

func TestIAMCollector_CollectUsers_MFADevicesError(t *testing.T) {
	// ListMFADevices fails for one user but collection should continue
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return &iam.ListUsersOutput{
				Users: []types.User{
					{UserName: aws.String("alice"), Arn: aws.String("arn:aws:iam::123456789012:user/alice")},
					{UserName: aws.String("bob"), Arn: aws.String("arn:aws:iam::123456789012:user/bob")},
				},
				IsTruncated: false,
			}, nil
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			if *params.UserName == "alice" {
				return nil, errors.New("access denied for alice MFA")
			}
			return &iam.ListMFADevicesOutput{
				MFADevices: []types.MFADevice{
					{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/bob")},
				},
			}, nil
		},
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			return &iam.GetLoginProfileOutput{}, nil
		},
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err, "should not fail even when MFA query fails for one user")
	require.Len(t, users, 2)

	// alice: MFA query failed → MFAEnabled defaults to false (fail-safe)
	assert.False(t, users[0].MFAEnabled, "alice should default to MFA disabled when query fails")
	assert.Empty(t, users[0].MFADevices)

	// bob: MFA query succeeded
	assert.True(t, users[1].MFAEnabled, "bob should have MFA enabled")
	assert.Len(t, users[1].MFADevices, 1)
}

func TestIAMCollector_CollectUsers_PaginationError(t *testing.T) {
	// First page succeeds, second page fails
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
			return nil, errors.New("pagination failed")
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{}}, nil
		},
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			return &iam.GetLoginProfileOutput{}, nil
		},
	}

	collector := &IAMCollector{client: mockIAM}
	_, err := collector.CollectUsers(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pagination failed")
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
