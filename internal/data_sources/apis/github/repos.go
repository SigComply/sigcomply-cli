package github

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	gh "github.com/google/go-github/v57/github"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// Repository represents a GitHub repository with its security settings.
type Repository struct {
	Name              string               `json:"name"`
	FullName          string               `json:"full_name"`
	Owner             string               `json:"owner"`
	Private           bool                 `json:"private"`
	DefaultBranch     string               `json:"default_branch"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
	BranchProtection  *BranchProtection    `json:"branch_protection,omitempty"`
	Archived          bool                 `json:"archived"`
	Visibility        string               `json:"visibility"`
}

// BranchProtection represents branch protection settings.
type BranchProtection struct {
	Enabled                     bool `json:"enabled"`
	RequirePullRequest          bool `json:"require_pull_request"`
	RequiredReviewers           int  `json:"required_reviewers"`
	DismissStaleReviews         bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews     bool `json:"require_code_owner_reviews"`
	RequiredStatusChecks        bool `json:"required_status_checks"`
	RequireLinearHistory        bool `json:"require_linear_history"`
	AllowForcePushes            bool `json:"allow_force_pushes"`
	AllowDeletions              bool `json:"allow_deletions"`
	EnforceAdmins               bool `json:"enforce_admins"`
	RequireSignedCommits        bool `json:"require_signed_commits"`
	RequireConversationResolution bool `json:"require_conversation_resolution"`
}

// ToEvidence converts a Repository to an Evidence struct.
func (r *Repository) ToEvidence() evidence.Evidence {
	data, _ := json.Marshal(r) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("github", "github:repository", r.FullName, data)
	ev.Metadata = evidence.Metadata{
		Organization: r.Owner,
	}
	return ev
}

// RepoCollector collects GitHub repository data.
type RepoCollector struct {
	client Client
}

// NewRepoCollector creates a new repository collector.
func NewRepoCollector(client Client) *RepoCollector {
	return &RepoCollector{client: client}
}

// CollectOrgRepos collects repositories from an organization.
func (c *RepoCollector) CollectOrgRepos(ctx context.Context, org string) ([]evidence.Evidence, error) {
	repos, err := c.listOrgRepos(ctx, org)
	if err != nil {
		return nil, err
	}

	return c.collectEvidence(ctx, repos)
}

// CollectUserRepos collects repositories for the authenticated user.
func (c *RepoCollector) CollectUserRepos(ctx context.Context, username string) ([]evidence.Evidence, error) {
	repos, err := c.listUserRepos(ctx, username)
	if err != nil {
		return nil, err
	}

	return c.collectEvidence(ctx, repos)
}

// listOrgRepos lists all repositories for an organization with pagination.
func (c *RepoCollector) listOrgRepos(ctx context.Context, org string) ([]*gh.Repository, error) {
	var allRepos []*gh.Repository
	opts := &gh.RepositoryListByOrgOptions{
		ListOptions: gh.ListOptions{PerPage: 100},
	}

	for {
		repos, resp, err := c.client.ListOrgRepos(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list organization repositories: %w", err)
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// listUserRepos lists all repositories for a user with pagination.
func (c *RepoCollector) listUserRepos(ctx context.Context, username string) ([]*gh.Repository, error) {
	var allRepos []*gh.Repository
	opts := &gh.RepositoryListByUserOptions{
		ListOptions: gh.ListOptions{PerPage: 100},
	}

	for {
		repos, resp, err := c.client.ListUserRepos(ctx, username, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list user repositories: %w", err)
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// collectEvidence converts GitHub repositories to evidence.
func (c *RepoCollector) collectEvidence(ctx context.Context, repos []*gh.Repository) ([]evidence.Evidence, error) {
	evidenceList := make([]evidence.Evidence, 0, len(repos))

	for _, repo := range repos {
		// Skip archived repositories
		if repo.GetArchived() {
			continue
		}

		r := &Repository{
			Name:          repo.GetName(),
			FullName:      repo.GetFullName(),
			Owner:         repo.GetOwner().GetLogin(),
			Private:       repo.GetPrivate(),
			DefaultBranch: repo.GetDefaultBranch(),
			Archived:      repo.GetArchived(),
			Visibility:    repo.GetVisibility(),
		}

		if repo.CreatedAt != nil {
			r.CreatedAt = repo.CreatedAt.Time
		}
		if repo.UpdatedAt != nil {
			r.UpdatedAt = repo.UpdatedAt.Time
		}

		// Get branch protection for the default branch
		if repo.GetDefaultBranch() != "" {
			protection, _, err := c.client.GetBranchProtection(ctx, r.Owner, r.Name, repo.GetDefaultBranch())
			if err == nil && protection != nil {
				r.BranchProtection = convertBranchProtection(protection)
			}
			// If branch protection is not configured, it will be nil
			// This is expected for repos without protection enabled
		}

		evidenceList = append(evidenceList, r.ToEvidence())
	}

	return evidenceList, nil
}

// convertBranchProtection converts GitHub API branch protection to our struct.
func convertBranchProtection(p *gh.Protection) *BranchProtection {
	bp := &BranchProtection{
		Enabled: true,
	}

	// Check force pushes setting
	if fp := p.GetAllowForcePushes(); fp != nil {
		bp.AllowForcePushes = fp.Enabled
	}

	// Check deletions setting
	if ad := p.GetAllowDeletions(); ad != nil {
		bp.AllowDeletions = ad.Enabled
	}

	// Check linear history
	if lh := p.GetRequireLinearHistory(); lh != nil {
		bp.RequireLinearHistory = lh.Enabled
	}

	// Check signed commits
	if rs := p.GetRequiredSignatures(); rs != nil {
		bp.RequireSignedCommits = rs.GetEnabled()
	}

	// Check pull request requirements
	if prReview := p.GetRequiredPullRequestReviews(); prReview != nil {
		bp.RequirePullRequest = true
		bp.RequiredReviewers = prReview.RequiredApprovingReviewCount
		bp.DismissStaleReviews = prReview.DismissStaleReviews
		bp.RequireCodeOwnerReviews = prReview.RequireCodeOwnerReviews
	}

	// Check status check requirements
	if statusChecks := p.GetRequiredStatusChecks(); statusChecks != nil {
		bp.RequiredStatusChecks = true
	}

	// Check if admins are enforced
	if ae := p.GetEnforceAdmins(); ae != nil {
		bp.EnforceAdmins = ae.Enabled
	}

	// Check conversation resolution (if available)
	if cr := p.GetRequiredConversationResolution(); cr != nil {
		bp.RequireConversationResolution = cr.Enabled
	}

	return bp
}
