package github

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	gh "github.com/google/go-github/v57/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMember_ToEvidence(t *testing.T) {
	member := &Member{
		Login:        "testuser",
		ID:           123,
		Type:         "User",
		Organization: "testorg",
	}

	ev := member.ToEvidence()

	assert.Equal(t, "github", ev.Collector)
	assert.Equal(t, "github:member", ev.ResourceType)
	assert.Equal(t, "testorg/members/testuser", ev.ResourceID)
	assert.Equal(t, "testorg", ev.Metadata.Organization)

	// Verify data is valid JSON
	var parsed Member
	err := json.Unmarshal(ev.Data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "testuser", parsed.Login)
	assert.Equal(t, int64(123), parsed.ID)
}

func TestMemberCollector_CollectMembers(t *testing.T) {
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			return []*gh.User{
				{
					Login:     strPtr("member1"),
					ID:        int64Ptr(1),
					Type:      strPtr("User"),
					SiteAdmin: gh.Bool(false),
				},
				{
					Login:     strPtr("member2"),
					ID:        int64Ptr(2),
					Type:      strPtr("User"),
					SiteAdmin: gh.Bool(false),
				},
			}, &gh.Response{}, nil
		},
	}

	collector := NewMemberCollector(mockClient)
	evidence, err := collector.CollectMembers(context.Background(), "testorg")

	require.NoError(t, err)
	assert.Len(t, evidence, 2)
}

func TestMemberCollector_CollectMembers_WithPagination(t *testing.T) {
	page := 0
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			page++
			if page == 1 {
				return []*gh.User{
					{Login: strPtr("member1"), ID: int64Ptr(1)},
				}, &gh.Response{NextPage: 2}, nil
			}
			return []*gh.User{
				{Login: strPtr("member2"), ID: int64Ptr(2)},
			}, &gh.Response{NextPage: 0}, nil
		},
	}

	collector := NewMemberCollector(mockClient)
	evidence, err := collector.CollectMembers(context.Background(), "testorg")

	require.NoError(t, err)
	assert.Len(t, evidence, 2)
}

func TestMemberCollector_CollectMembersWithFilter(t *testing.T) {
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			// Only return members matching the filter
			if opts.Filter == filter2FADisabled {
				return []*gh.User{
					{Login: strPtr("no2fa-user"), ID: int64Ptr(1)},
				}, &gh.Response{}, nil
			}
			return []*gh.User{
				{Login: strPtr("user1"), ID: int64Ptr(1)},
				{Login: strPtr("user2"), ID: int64Ptr(2)},
			}, &gh.Response{}, nil
		},
	}

	collector := NewMemberCollector(mockClient)

	// Test with 2fa_disabled filter
	evidence, err := collector.CollectMembersWithFilter(context.Background(), "testorg", filter2FADisabled)
	require.NoError(t, err)
	assert.Len(t, evidence, 1)

	var member Member
	err = json.Unmarshal(evidence[0].Data, &member)
	require.NoError(t, err)
	assert.NotNil(t, member.TwoFactorEnabled)
	assert.False(t, *member.TwoFactorEnabled)
}

// --- Negative tests ---

func TestMemberCollector_CollectMembers_APIError(t *testing.T) {
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			return nil, nil, errors.New("API rate limit exceeded")
		},
	}

	collector := NewMemberCollector(mockClient)
	_, err := collector.CollectMembers(context.Background(), "testorg")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit")
}

func TestMemberCollector_CollectMembersWithFilter_APIError(t *testing.T) {
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			return nil, nil, errors.New("forbidden")
		},
	}

	collector := NewMemberCollector(mockClient)
	_, err := collector.CollectMembersWithFilter(context.Background(), "testorg", filter2FADisabled)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestMemberCollector_CollectMembersWithTwoFactorStatus_AllMembersError(t *testing.T) {
	// 2fa_disabled query succeeds but the main ListMembers call fails
	callCount := 0
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			callCount++
			if opts.Filter == filter2FADisabled {
				// Admin access works for 2FA filter
				return []*gh.User{}, &gh.Response{}, nil
			}
			// Main member list fails
			return nil, nil, errors.New("server error")
		},
	}

	collector := NewMemberCollector(mockClient)
	_, _, err := collector.CollectMembersWithTwoFactorStatus(context.Background(), "testorg")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "server error")
}

func TestMemberCollector_CollectMembersWithTwoFactorStatus_No2FAAccess(t *testing.T) {
	// 2fa_disabled query fails (no admin), but main listing works
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			if opts.Filter == filter2FADisabled {
				return nil, nil, errors.New("403 Forbidden")
			}
			return []*gh.User{
				{Login: strPtr("member1"), ID: int64Ptr(1)},
			}, &gh.Response{}, nil
		},
	}

	collector := NewMemberCollector(mockClient)
	ev, has2FA, err := collector.CollectMembersWithTwoFactorStatus(context.Background(), "testorg")

	require.NoError(t, err)
	assert.False(t, has2FA, "should not have 2FA visibility when admin access denied")
	assert.Len(t, ev, 1)
}

func TestMemberCollector_CollectMembers_Empty(t *testing.T) {
	mockClient := &MockClient{
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			return []*gh.User{}, &gh.Response{}, nil
		},
	}

	collector := NewMemberCollector(mockClient)
	evidence, err := collector.CollectMembers(context.Background(), "testorg")

	require.NoError(t, err)
	assert.Len(t, evidence, 0)
}
