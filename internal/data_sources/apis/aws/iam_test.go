package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockIAMClient is a mock implementation of IAMClient for testing.
type MockIAMClient struct {
	ListUsersFunc                func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListMFADevicesFunc           func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	GetLoginProfileFunc          func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
	ListAccessKeysFunc           func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsedFunc     func(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	ListAttachedUserPoliciesFunc func(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
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

func (m *MockIAMClient) ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if m.ListAccessKeysFunc != nil {
		return m.ListAccessKeysFunc(ctx, params, optFns...)
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: []types.AccessKeyMetadata{}}, nil
}

func (m *MockIAMClient) GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if m.GetAccessKeyLastUsedFunc != nil {
		return m.GetAccessKeyLastUsedFunc(ctx, params, optFns...)
	}
	return &iam.GetAccessKeyLastUsedOutput{}, nil
}

func (m *MockIAMClient) ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	if m.ListAttachedUserPoliciesFunc != nil {
		return m.ListAttachedUserPoliciesFunc(ctx, params, optFns...)
	}
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: []types.AttachedPolicy{}}, nil
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

// --- Access key tests ---

func TestIAMCollector_AccessKeys(t *testing.T) {
	now := time.Now().UTC()
	keyCreated := now.Add(-100 * 24 * time.Hour) // 100 days ago
	keyLastUsed := now.Add(-10 * 24 * time.Hour) // 10 days ago

	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return &iam.ListUsersOutput{
				Users: []types.User{
					{UserName: aws.String("alice"), Arn: aws.String("arn:aws:iam::123456789012:user/alice")},
				},
				IsTruncated: false,
			}, nil
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{}}, nil
		},
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			return nil, &types.NoSuchEntityException{Message: aws.String("not found")}
		},
		ListAccessKeysFunc: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []types.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIA111111"),
						Status:      types.StatusTypeActive,
						CreateDate:  &keyCreated,
					},
					{
						AccessKeyId: aws.String("AKIA222222"),
						Status:      types.StatusTypeInactive,
						CreateDate:  &keyCreated,
					},
				},
			}, nil
		},
		GetAccessKeyLastUsedFunc: func(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
			if *params.AccessKeyId == "AKIA111111" {
				return &iam.GetAccessKeyLastUsedOutput{
					AccessKeyLastUsed: &types.AccessKeyLastUsed{
						LastUsedDate: &keyLastUsed,
						ServiceName:  aws.String("s3"),
					},
				}, nil
			}
			// AKIA222222: never used
			return &iam.GetAccessKeyLastUsedOutput{
				AccessKeyLastUsed: &types.AccessKeyLastUsed{},
			}, nil
		},
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err)
	require.Len(t, users, 1)

	u := users[0]
	assert.Len(t, u.AccessKeys, 2)
	assert.Equal(t, 1, u.ActiveKeyCount, "only one active key")
	assert.InDelta(t, 100, u.OldestKeyAgeDays, 1, "oldest active key is ~100 days old")

	// Active key with last used
	assert.Equal(t, "AKIA111111", u.AccessKeys[0].AccessKeyID)
	assert.Equal(t, "Active", u.AccessKeys[0].Status)
	assert.InDelta(t, 10, u.AccessKeys[0].LastUsedDays, 1)
	assert.Equal(t, "s3", u.AccessKeys[0].LastUsedService)

	// Inactive key, never used
	assert.Equal(t, "AKIA222222", u.AccessKeys[1].AccessKeyID)
	assert.Equal(t, "Inactive", u.AccessKeys[1].Status)
	assert.Equal(t, -1, u.AccessKeys[1].LastUsedDays)
}

// newSingleUserMock creates a MockIAMClient with a single user "alice" and default no-op stubs
// for MFA, login profile, access keys, and attached policies. Override specific funcs as needed.
func newSingleUserMock() *MockIAMClient {
	return &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return &iam.ListUsersOutput{
				Users: []types.User{
					{UserName: aws.String("alice"), Arn: aws.String("arn:aws:iam::123456789012:user/alice")},
				},
				IsTruncated: false,
			}, nil
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{}}, nil
		},
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			return nil, &types.NoSuchEntityException{Message: aws.String("not found")}
		},
	}
}

func TestIAMCollector_AccessKeys_Error_FailSafe(t *testing.T) {
	mockIAM := newSingleUserMock()
	mockIAM.ListAccessKeysFunc = func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
		return nil, errors.New("access denied")
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err, "should not fail when access key query fails")
	require.Len(t, users, 1)
	assert.Empty(t, users[0].AccessKeys)
	assert.Equal(t, 0, users[0].ActiveKeyCount)
	assert.Equal(t, 0, users[0].OldestKeyAgeDays)
}

// --- Attached policy tests ---

func TestIAMCollector_AttachedPolicies(t *testing.T) {
	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return &iam.ListUsersOutput{
				Users: []types.User{
					{UserName: aws.String("admin"), Arn: aws.String("arn:aws:iam::123456789012:user/admin")},
					{UserName: aws.String("reader"), Arn: aws.String("arn:aws:iam::123456789012:user/reader")},
				},
				IsTruncated: false,
			}, nil
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{}}, nil
		},
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			return nil, &types.NoSuchEntityException{Message: aws.String("not found")}
		},
		ListAttachedUserPoliciesFunc: func(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
			if *params.UserName == "admin" {
				return &iam.ListAttachedUserPoliciesOutput{
					AttachedPolicies: []types.AttachedPolicy{
						{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
					},
				}, nil
			}
			return &iam.ListAttachedUserPoliciesOutput{
				AttachedPolicies: []types.AttachedPolicy{
					{PolicyName: aws.String("ReadOnlyAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")},
				},
			}, nil
		},
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err)
	require.Len(t, users, 2)

	// admin user
	assert.True(t, users[0].HasAdminPolicy, "admin should have admin policy")
	assert.Len(t, users[0].AttachedPolicies, 1)
	assert.Equal(t, "AdministratorAccess", users[0].AttachedPolicies[0].PolicyName)

	// reader user
	assert.False(t, users[1].HasAdminPolicy, "reader should not have admin policy")
	assert.Len(t, users[1].AttachedPolicies, 1)
	assert.Equal(t, "ReadOnlyAccess", users[1].AttachedPolicies[0].PolicyName)
}

func TestIAMCollector_AttachedPolicies_Error_FailSafe(t *testing.T) {
	mockIAM := newSingleUserMock()
	mockIAM.ListAttachedUserPoliciesFunc = func(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
		return nil, errors.New("access denied")
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err, "should not fail when policy query fails")
	require.Len(t, users, 1)
	assert.Empty(t, users[0].AttachedPolicies)
	assert.False(t, users[0].HasAdminPolicy)
}

// --- Password inactive days tests ---

func TestIAMCollector_PasswordInactiveDays(t *testing.T) {
	now := time.Now().UTC()
	pwdLastUsed := now.Add(-45 * 24 * time.Hour) // 45 days ago

	mockIAM := &MockIAMClient{
		ListUsersFunc: func(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
			return &iam.ListUsersOutput{
				Users: []types.User{
					{
						UserName:         aws.String("console-user"),
						Arn:              aws.String("arn:aws:iam::123456789012:user/console-user"),
						PasswordLastUsed: &pwdLastUsed,
					},
					{
						UserName: aws.String("programmatic-user"),
						Arn:      aws.String("arn:aws:iam::123456789012:user/programmatic-user"),
					},
				},
				IsTruncated: false,
			}, nil
		},
		ListMFADevicesFunc: func(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
			return &iam.ListMFADevicesOutput{MFADevices: []types.MFADevice{}}, nil
		},
		GetLoginProfileFunc: func(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
			if *params.UserName == "console-user" {
				return &iam.GetLoginProfileOutput{}, nil
			}
			return nil, &types.NoSuchEntityException{Message: aws.String("not found")}
		},
	}

	collector := &IAMCollector{client: mockIAM}
	users, err := collector.CollectUsers(context.Background())

	require.NoError(t, err)
	require.Len(t, users, 2)

	// Console user with password last used 45 days ago
	assert.InDelta(t, 45, users[0].PasswordInactiveDays, 1)

	// Programmatic user (no login profile)
	assert.Equal(t, -1, users[1].PasswordInactiveDays)
}

func TestDaysBetween(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		from time.Time
		want int
	}{
		{"same day", now, 0},
		{"one day ago", now.Add(-24 * time.Hour), 1},
		{"90 days ago", now.Add(-90 * 24 * time.Hour), 90},
		{"partial day", now.Add(-36 * time.Hour), 1}, // 1.5 days = floor(1.5) = 1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, daysBetween(tt.from, now))
		})
	}
}
