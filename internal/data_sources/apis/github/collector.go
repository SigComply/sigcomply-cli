// Package github provides evidence collection from GitHub.
package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	gh "github.com/google/go-github/v57/github"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
	"golang.org/x/oauth2"
)

// Client defines the interface for GitHub API operations.
//
//nolint:dupl // Interface intentionally mirrors MockClient in tests
type Client interface {
	GetAuthenticatedUser(ctx context.Context) (*gh.User, *gh.Response, error)
	ListOrganizations(ctx context.Context, user string, opts *gh.ListOptions) ([]*gh.Organization, *gh.Response, error)
	ListOrgRepos(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error)
	ListUserRepos(ctx context.Context, user string, opts *gh.RepositoryListByUserOptions) ([]*gh.Repository, *gh.Response, error)
	GetBranchProtection(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error)
	ListOrgMembers(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error)
	GetRepository(ctx context.Context, owner, repo string) (*gh.Repository, *gh.Response, error)
}

// APIClient wraps the go-github client to implement the Client interface.
type APIClient struct {
	client *gh.Client
}

// NewAPIClient creates a new API client wrapper.
func NewAPIClient(client *gh.Client) *APIClient {
	return &APIClient{client: client}
}

// GetAuthenticatedUser returns the authenticated user.
func (c *APIClient) GetAuthenticatedUser(ctx context.Context) (*gh.User, *gh.Response, error) {
	return c.client.Users.Get(ctx, "")
}

// ListOrganizations lists organizations for a user.
func (c *APIClient) ListOrganizations(ctx context.Context, user string, opts *gh.ListOptions) ([]*gh.Organization, *gh.Response, error) {
	return c.client.Organizations.List(ctx, user, opts)
}

// ListOrgRepos lists repositories for an organization.
func (c *APIClient) ListOrgRepos(ctx context.Context, org string, opts *gh.RepositoryListByOrgOptions) ([]*gh.Repository, *gh.Response, error) {
	return c.client.Repositories.ListByOrg(ctx, org, opts)
}

// ListUserRepos lists repositories for a user.
func (c *APIClient) ListUserRepos(ctx context.Context, user string, opts *gh.RepositoryListByUserOptions) ([]*gh.Repository, *gh.Response, error) {
	return c.client.Repositories.ListByUser(ctx, user, opts)
}

// GetBranchProtection gets branch protection settings.
func (c *APIClient) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
	return c.client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
}

// ListOrgMembers lists members of an organization.
func (c *APIClient) ListOrgMembers(ctx context.Context, org string, opts *gh.ListMembersOptions) ([]*gh.User, *gh.Response, error) {
	return c.client.Organizations.ListMembers(ctx, org, opts)
}

// GetRepository gets a repository.
func (c *APIClient) GetRepository(ctx context.Context, owner, repo string) (*gh.Repository, *gh.Response, error) {
	return c.client.Repositories.Get(ctx, owner, repo)
}

// CollectorStatus represents the current state of the GitHub collector.
type CollectorStatus struct {
	Connected    bool     `json:"connected"`
	Username     string   `json:"username,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// CollectionResult represents the result of collecting evidence from GitHub.
type CollectionResult struct {
	Evidence []evidence.Evidence `json:"evidence"`
	Errors   []CollectionError   `json:"errors,omitempty"`
}

// CollectionError represents an error during collection.
type CollectionError struct {
	Resource string `json:"resource"`
	Error    string `json:"error"`
}

// HasErrors returns true if there were any collection errors.
func (r *CollectionResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Collector gathers evidence from GitHub.
type Collector struct {
	client       Client
	token        string
	organization string
	username     string
}

// New creates a new GitHub Collector.
func New() *Collector {
	return &Collector{}
}

// WithToken sets the GitHub token.
func (c *Collector) WithToken(token string) *Collector {
	c.token = token
	return c
}

// WithOrganization sets the organization to collect from.
func (c *Collector) WithOrganization(org string) *Collector {
	c.organization = org
	return c
}

// Init initializes the GitHub client.
func (c *Collector) Init(ctx context.Context) error {
	// Get token from config or environment
	token := c.token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	if token == "" {
		return errors.New("GitHub token not configured: set GITHUB_TOKEN environment variable")
	}

	// Create OAuth2 client
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	// Create GitHub client
	ghClient := gh.NewClient(tc)
	c.client = NewAPIClient(ghClient)

	return nil
}

// InitWithClient initializes the collector with a pre-configured client (for testing).
func (c *Collector) InitWithClient(client Client) {
	c.client = client
}

// InitWithHTTPClient initializes the collector with a custom HTTP client.
func (c *Collector) InitWithHTTPClient(httpClient *http.Client) {
	ghClient := gh.NewClient(httpClient)
	c.client = NewAPIClient(ghClient)
}

// Status returns the current connection status of the collector.
func (c *Collector) Status(ctx context.Context) CollectorStatus {
	status := CollectorStatus{
		Organization: c.organization,
	}

	if c.client == nil {
		status.Connected = false
		status.Error = "client not initialized"
		return status
	}

	user, _, err := c.client.GetAuthenticatedUser(ctx)
	if err != nil {
		status.Connected = false
		status.Error = err.Error()
		return status
	}

	status.Connected = true
	status.Username = user.GetLogin()
	c.username = user.GetLogin()

	return status
}

// Collect gathers evidence from GitHub using fail-safe pattern.
func (c *Collector) Collect(ctx context.Context) (*CollectionResult, error) {
	if c.client == nil {
		return nil, errors.New("client not initialized: call Init() first")
	}

	// Verify connectivity first
	status := c.Status(ctx)
	if !status.Connected {
		return nil, fmt.Errorf("GitHub connection failed: %s", status.Error)
	}

	result := &CollectionResult{
		Evidence: []evidence.Evidence{},
		Errors:   []CollectionError{},
	}

	// Collect repositories
	c.collectRepos(ctx, result)

	// Collect organization members if organization is specified
	if c.organization != "" {
		c.collectMembers(ctx, result)
	}

	return result, nil
}

// collectRepos collects repository evidence.
func (c *Collector) collectRepos(ctx context.Context, result *CollectionResult) {
	repoCollector := NewRepoCollector(c.client)

	var ev []evidence.Evidence
	var err error

	if c.organization != "" {
		ev, err = repoCollector.CollectOrgRepos(ctx, c.organization)
	} else {
		ev, err = repoCollector.CollectUserRepos(ctx, c.username)
	}

	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Resource: "repositories",
			Error:    err.Error(),
		})
		return
	}

	result.Evidence = append(result.Evidence, ev...)
}

// collectMembers collects organization member evidence with 2FA status.
func (c *Collector) collectMembers(ctx context.Context, result *CollectionResult) {
	memberCollector := NewMemberCollector(c.client)

	// Try to collect members with 2FA status (requires admin access for full visibility)
	ev, has2FAVisibility, err := memberCollector.CollectMembersWithTwoFactorStatus(ctx, c.organization)

	if err != nil {
		result.Errors = append(result.Errors, CollectionError{
			Resource: "members",
			Error:    err.Error(),
		})
		return
	}

	if !has2FAVisibility {
		// Add a warning that 2FA status couldn't be determined
		result.Errors = append(result.Errors, CollectionError{
			Resource: "members-2fa",
			Error:    "2FA status unknown - requires org admin access to verify member 2FA status",
		})
	}

	result.Evidence = append(result.Evidence, ev...)
}
