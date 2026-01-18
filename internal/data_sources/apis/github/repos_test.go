package github

import (
	"context"
	"encoding/json"
	"testing"

	gh "github.com/google/go-github/v57/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_ToEvidence(t *testing.T) {
	repo := &Repository{
		Name:          "test-repo",
		FullName:      "owner/test-repo",
		Owner:         "owner",
		Private:       true,
		DefaultBranch: "main",
	}

	ev := repo.ToEvidence()

	assert.Equal(t, "github", ev.Collector)
	assert.Equal(t, "github:repository", ev.ResourceType)
	assert.Equal(t, "owner/test-repo", ev.ResourceID)
	assert.Equal(t, "owner", ev.Metadata.Organization)

	// Verify data is valid JSON
	var parsed Repository
	err := json.Unmarshal(ev.Data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "test-repo", parsed.Name)
}

func TestRepoCollector_CollectOrgRepos(t *testing.T) {
	mockClient := &MockClient{
		ListOrgReposFunc: func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			return []*gh.Repository{
				{
					Name:          strPtr("repo1"),
					FullName:      strPtr("testorg/repo1"),
					Owner:         &gh.User{Login: strPtr("testorg")},
					Private:       gh.Bool(false),
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(false),
				},
				{
					Name:          strPtr("repo2"),
					FullName:      strPtr("testorg/repo2"),
					Owner:         &gh.User{Login: strPtr("testorg")},
					Private:       gh.Bool(true),
					DefaultBranch: strPtr("develop"),
					Archived:      gh.Bool(false),
				},
			}, &gh.Response{}, nil
		},
		GetBranchProtectionFunc: func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
			return nil, nil, nil
		},
	}

	collector := NewRepoCollector(mockClient)
	evidence, err := collector.CollectOrgRepos(context.Background(), "testorg")

	require.NoError(t, err)
	assert.Len(t, evidence, 2)
}

func TestRepoCollector_CollectOrgRepos_WithPagination(t *testing.T) {
	page := 0
	mockClient := &MockClient{
		ListOrgReposFunc: func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			page++
			if page == 1 {
				return []*gh.Repository{
					{
						Name:          strPtr("repo1"),
						FullName:      strPtr("testorg/repo1"),
						Owner:         &gh.User{Login: strPtr("testorg")},
						DefaultBranch: strPtr("main"),
						Archived:      gh.Bool(false),
					},
				}, &gh.Response{NextPage: 2}, nil
			}
			return []*gh.Repository{
				{
					Name:          strPtr("repo2"),
					FullName:      strPtr("testorg/repo2"),
					Owner:         &gh.User{Login: strPtr("testorg")},
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(false),
				},
			}, &gh.Response{NextPage: 0}, nil
		},
		GetBranchProtectionFunc: func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
			return nil, nil, nil
		},
	}

	collector := NewRepoCollector(mockClient)
	evidence, err := collector.CollectOrgRepos(context.Background(), "testorg")

	require.NoError(t, err)
	assert.Len(t, evidence, 2)
}

func TestRepoCollector_CollectOrgRepos_SkipsArchived(t *testing.T) {
	mockClient := &MockClient{
		ListOrgReposFunc: func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			return []*gh.Repository{
				{
					Name:          strPtr("active-repo"),
					FullName:      strPtr("testorg/active-repo"),
					Owner:         &gh.User{Login: strPtr("testorg")},
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(false),
				},
				{
					Name:          strPtr("archived-repo"),
					FullName:      strPtr("testorg/archived-repo"),
					Owner:         &gh.User{Login: strPtr("testorg")},
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(true),
				},
			}, &gh.Response{}, nil
		},
		GetBranchProtectionFunc: func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
			return nil, nil, nil
		},
	}

	collector := NewRepoCollector(mockClient)
	evidence, err := collector.CollectOrgRepos(context.Background(), "testorg")

	require.NoError(t, err)
	assert.Len(t, evidence, 1)

	var repo Repository
	err = json.Unmarshal(evidence[0].Data, &repo)
	require.NoError(t, err)
	assert.Equal(t, "active-repo", repo.Name)
}

func TestRepoCollector_CollectUserRepos(t *testing.T) {
	mockClient := &MockClient{
		ListUserReposFunc: func(ctx context.Context, user string, opts *gh.RepositoryListByUserOptions) ([]*gh.Repository, *gh.Response, error) {
			return []*gh.Repository{
				{
					Name:          strPtr("my-repo"),
					FullName:      strPtr("user/my-repo"),
					Owner:         &gh.User{Login: strPtr("user")},
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(false),
				},
			}, &gh.Response{}, nil
		},
		GetBranchProtectionFunc: func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
			return nil, nil, nil
		},
	}

	collector := NewRepoCollector(mockClient)
	evidence, err := collector.CollectUserRepos(context.Background(), "user")

	require.NoError(t, err)
	assert.Len(t, evidence, 1)
}

func TestRepoCollector_WithBranchProtection(t *testing.T) {
	mockClient := &MockClient{
		ListOrgReposFunc: func(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
			return []*gh.Repository{
				{
					Name:          strPtr("protected-repo"),
					FullName:      strPtr("testorg/protected-repo"),
					Owner:         &gh.User{Login: strPtr("testorg")},
					DefaultBranch: strPtr("main"),
					Archived:      gh.Bool(false),
				},
			}, &gh.Response{}, nil
		},
		GetBranchProtectionFunc: func(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
			return &gh.Protection{
				RequiredPullRequestReviews: &gh.PullRequestReviewsEnforcement{
					RequiredApprovingReviewCount: 2,
					DismissStaleReviews:          true,
					RequireCodeOwnerReviews:      true,
				},
				RequiredStatusChecks: &gh.RequiredStatusChecks{
					Strict: true,
				},
				EnforceAdmins: &gh.AdminEnforcement{
					Enabled: true,
				},
			}, nil, nil
		},
	}

	collector := NewRepoCollector(mockClient)
	evidence, err := collector.CollectOrgRepos(context.Background(), "testorg")

	require.NoError(t, err)
	require.Len(t, evidence, 1)

	var repo Repository
	err = json.Unmarshal(evidence[0].Data, &repo)
	require.NoError(t, err)

	require.NotNil(t, repo.BranchProtection)
	assert.True(t, repo.BranchProtection.Enabled)
	assert.True(t, repo.BranchProtection.RequirePullRequest)
	assert.Equal(t, 2, repo.BranchProtection.RequiredReviewers)
	assert.True(t, repo.BranchProtection.DismissStaleReviews)
	assert.True(t, repo.BranchProtection.RequireCodeOwnerReviews)
	assert.True(t, repo.BranchProtection.RequiredStatusChecks)
	assert.True(t, repo.BranchProtection.EnforceAdmins)
}

func TestConvertBranchProtection(t *testing.T) {
	tests := []struct {
		name     string
		input    *gh.Protection
		expected *BranchProtection
	}{
		{
			name: "minimal protection",
			input: &gh.Protection{
				EnforceAdmins: &gh.AdminEnforcement{
					Enabled: false,
				},
			},
			expected: &BranchProtection{
				Enabled:      true,
				EnforceAdmins: false,
			},
		},
		{
			name: "with PR reviews",
			input: &gh.Protection{
				RequiredPullRequestReviews: &gh.PullRequestReviewsEnforcement{
					RequiredApprovingReviewCount: 1,
				},
			},
			expected: &BranchProtection{
				Enabled:           true,
				RequirePullRequest: true,
				RequiredReviewers: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertBranchProtection(tt.input)
			assert.Equal(t, tt.expected.Enabled, result.Enabled)
			assert.Equal(t, tt.expected.RequirePullRequest, result.RequirePullRequest)
			assert.Equal(t, tt.expected.RequiredReviewers, result.RequiredReviewers)
		})
	}
}
