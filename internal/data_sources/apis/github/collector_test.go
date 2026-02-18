package github

import (
	"context"
	"errors"
	"os"
	"testing"

	gh "github.com/google/go-github/v57/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockClient is a mock implementation of the GitHub client interface.
//
//nolint:dupl // Mock intentionally mirrors Client interface
type MockClient struct {
	GetAuthenticatedUserFunc  func(ctx context.Context) (*gh.User, *gh.Response, error)
	ListOrganizationsFunc     func(ctx context.Context, user string, opts *gh.ListOptions) ([]*gh.Organization, *gh.Response, error)
	ListOrgReposFunc          func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error)
	ListUserReposFunc         func(ctx context.Context, user string, opts *gh.RepositoryListByUserOptions) ([]*gh.Repository, *gh.Response, error)
	GetBranchProtectionFunc   func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error)
	ListOrgMembersFunc        func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error)
	GetRepositoryFunc         func(ctx context.Context, owner, repo string) (*gh.Repository, *gh.Response, error)
}

func (m *MockClient) GetAuthenticatedUser(ctx context.Context) (*gh.User, *gh.Response, error) {
	if m.GetAuthenticatedUserFunc != nil {
		return m.GetAuthenticatedUserFunc(ctx)
	}
	return nil, nil, nil
}

func (m *MockClient) ListOrganizations(ctx context.Context, user string, opts *gh.ListOptions) ([]*gh.Organization, *gh.Response, error) {
	if m.ListOrganizationsFunc != nil {
		return m.ListOrganizationsFunc(ctx, user, opts)
	}
	return nil, nil, nil
}

func (m *MockClient) ListOrgRepos(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
	if m.ListOrgReposFunc != nil {
		return m.ListOrgReposFunc(ctx, org, opts)
	}
	return nil, nil, nil
}

func (m *MockClient) ListUserRepos(ctx context.Context, user string, opts *gh.RepositoryListByUserOptions) ([]*gh.Repository, *gh.Response, error) {
	if m.ListUserReposFunc != nil {
		return m.ListUserReposFunc(ctx, user, opts)
	}
	return nil, nil, nil
}

func (m *MockClient) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
	if m.GetBranchProtectionFunc != nil {
		return m.GetBranchProtectionFunc(ctx, owner, repo, branch)
	}
	return nil, nil, nil
}

func (m *MockClient) ListOrgMembers(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
	if m.ListOrgMembersFunc != nil {
		return m.ListOrgMembersFunc(ctx, org, opts)
	}
	return nil, nil, nil
}

func (m *MockClient) GetRepository(ctx context.Context, owner, repo string) (*gh.Repository, *gh.Response, error) {
	if m.GetRepositoryFunc != nil {
		return m.GetRepositoryFunc(ctx, owner, repo)
	}
	return nil, nil, nil
}

func strPtr(s string) *string {
	return &s
}

func int64Ptr(i int64) *int64 {
	return &i
}

func TestNew(t *testing.T) {
	c := New()
	require.NotNil(t, c)
}

func TestCollector_WithToken(t *testing.T) {
	c := New().WithToken("test-token")
	assert.Equal(t, "test-token", c.token)
}

func TestCollector_WithOrganization(t *testing.T) {
	c := New().WithOrganization("test-org")
	assert.Equal(t, "test-org", c.organization)
}

func TestCollector_Init_NoToken(t *testing.T) {
	// Clear any existing token
	original := os.Getenv("GITHUB_TOKEN")
	t.Cleanup(func() {
		if original != "" {
			_ = os.Setenv("GITHUB_TOKEN", original) //nolint:errcheck // Test cleanup
		} else {
			_ = os.Unsetenv("GITHUB_TOKEN") //nolint:errcheck // Test cleanup
		}
	})
	_ = os.Unsetenv("GITHUB_TOKEN") //nolint:errcheck // Test setup

	c := New()
	err := c.Init(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub token not configured")
}

func TestCollector_Status_NotInitialized(t *testing.T) {
	c := New()
	status := c.Status(context.Background())
	assert.False(t, status.Connected)
	assert.Contains(t, status.Error, "not initialized")
}

func TestCollector_Status_Connected(t *testing.T) {
	mockClient := &MockClient{
		GetAuthenticatedUserFunc: func(ctx context.Context) (*gh.User, *gh.Response, error) {
			return &gh.User{
				Login: strPtr("testuser"),
			}, nil, nil
		},
	}

	c := New()
	c.InitWithClient(mockClient)

	status := c.Status(context.Background())
	assert.True(t, status.Connected)
	assert.Equal(t, "testuser", status.Username)
}

func TestCollector_Collect_NotInitialized(t *testing.T) {
	c := New()
	_, err := c.Collect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestCollector_Collect_UserRepos(t *testing.T) {
	mockClient := &MockClient{
		GetAuthenticatedUserFunc: func(ctx context.Context) (*gh.User, *gh.Response, error) {
			return &gh.User{
				Login: strPtr("testuser"),
			}, nil, nil
		},
		ListUserReposFunc: func(ctx context.Context, user string, opts *gh.RepositoryListByUserOptions) ([]*gh.Repository, *gh.Response, error) {
			return []*gh.Repository{
				{
					Name:          strPtr("repo1"),
					FullName:      strPtr("testuser/repo1"),
					Owner:         &gh.User{Login: strPtr("testuser")},
					Private:       gh.Bool(false),
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(false),
				},
			}, &gh.Response{}, nil
		},
		GetBranchProtectionFunc: func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
			return nil, nil, nil // No branch protection
		},
	}

	c := New()
	c.InitWithClient(mockClient)

	result, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Evidence, 1)
	assert.Equal(t, "github:repository", result.Evidence[0].ResourceType)
}

func TestCollector_Collect_OrgRepos(t *testing.T) {
	mockClient := &MockClient{
		GetAuthenticatedUserFunc: func(ctx context.Context) (*gh.User, *gh.Response, error) {
			return &gh.User{
				Login: strPtr("testuser"),
			}, nil, nil
		},
		ListOrgReposFunc: func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			return []*gh.Repository{
				{
					Name:          strPtr("org-repo1"),
					FullName:      strPtr("testorg/org-repo1"),
					Owner:         &gh.User{Login: strPtr("testorg")},
					Private:       gh.Bool(true),
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(false),
				},
			}, &gh.Response{}, nil
		},
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			return []*gh.User{
				{
					Login: strPtr("member1"),
					ID:    int64Ptr(1),
					Type:  strPtr("User"),
				},
			}, &gh.Response{}, nil
		},
		GetBranchProtectionFunc: func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
			return nil, nil, nil
		},
	}

	c := New().WithOrganization("testorg")
	c.InitWithClient(mockClient)

	result, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	// Should have 1 repo + 1 member
	assert.Len(t, result.Evidence, 2)
}

// --- Negative tests ---

func TestCollector_Status_APIError(t *testing.T) {
	mockClient := &MockClient{
		GetAuthenticatedUserFunc: func(ctx context.Context) (*gh.User, *gh.Response, error) {
			return nil, nil, errors.New("401 Unauthorized")
		},
	}

	c := New()
	c.InitWithClient(mockClient)

	status := c.Status(context.Background())
	assert.False(t, status.Connected)
	assert.Contains(t, status.Error, "Unauthorized")
}

func TestCollector_Collect_ReposAndMembersFail(t *testing.T) {
	// Both repos and members fail — fail-safe should return empty result with errors
	mockClient := &MockClient{
		GetAuthenticatedUserFunc: func(ctx context.Context) (*gh.User, *gh.Response, error) {
			return &gh.User{Login: strPtr("testuser")}, nil, nil
		},
		ListOrgReposFunc: func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			return nil, nil, errors.New("repos API error")
		},
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			return nil, nil, errors.New("members API error")
		},
	}

	c := New().WithOrganization("testorg")
	c.InitWithClient(mockClient)

	result, err := c.Collect(context.Background())
	require.NoError(t, err, "Collect should not error even when sub-collectors fail")
	assert.Empty(t, result.Evidence, "should have no evidence when both fail")
	assert.True(t, result.HasErrors())

	// Should have errors for both resources
	resourceErrors := make(map[string]bool)
	for _, e := range result.Errors {
		resourceErrors[e.Resource] = true
	}
	assert.True(t, resourceErrors["repositories"])
	assert.True(t, resourceErrors["members"])
}

func TestCollector_Collect_ReposFailMembersSucceed(t *testing.T) {
	// Repos fail but members succeed — partial result
	mockClient := &MockClient{
		GetAuthenticatedUserFunc: func(ctx context.Context) (*gh.User, *gh.Response, error) {
			return &gh.User{Login: strPtr("testuser")}, nil, nil
		},
		ListOrgReposFunc: func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			return nil, nil, errors.New("repos API error")
		},
		ListOrgMembersFunc: func(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
			return []*gh.User{
				{Login: strPtr("member1"), ID: int64Ptr(1)},
			}, &gh.Response{}, nil
		},
	}

	c := New().WithOrganization("testorg")
	c.InitWithClient(mockClient)

	result, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Len(t, result.Evidence, 1, "should have member evidence")
	assert.True(t, result.HasErrors(), "should have repos error")
}

func TestCollectionResult_HasErrors(t *testing.T) {
	tests := []struct {
		name     string
		result   CollectionResult
		expected bool
	}{
		{
			name:     "no errors",
			result:   CollectionResult{Errors: nil},
			expected: false,
		},
		{
			name:     "empty errors",
			result:   CollectionResult{Errors: []CollectionError{}},
			expected: false,
		},
		{
			name: "has errors",
			result: CollectionResult{
				Errors: []CollectionError{{Resource: "repos", Error: "failed"}},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.HasErrors())
		})
	}
}
