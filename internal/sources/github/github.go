// Package github implements the github source plugin: lists
// repositories and organization members from a single GitHub
// organization and emits two evidence types — github_repository and
// github_org_member — suitable for SOC 2 branch-protection and 2FA
// coverage policies.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the concrete *httpAPI satisfies it, and
// unit tests inject an in-memory fake. The real HTTP adapter has no
// integration tests today (deferred — live API integration tests are
// out of scope for this batch).
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// Evidence type IDs this plugin emits.
const (
	EvidenceTypeRepository = "github_repository"
	EvidenceTypeOrgMember  = "github_org_member"
)

// SourceID is the registered ID for the github plugin instance.
const SourceID = "github"

// Repo is the subset of fields the plugin extracts from a repository
// listing. The plugin returns one record per Repo, augmented with
// branch-protection state queried via a second call.
type Repo struct {
	Name            string
	DefaultBranch   string
	ProtectionOn    bool
	RequiredReviews int
}

// Member is the subset of fields the plugin extracts from an org
// member listing.
type Member struct {
	Login       string
	TwoFactorOn bool
	Role        string
}

// API is the subset of the GitHub REST API the plugin uses. Defining
// it as an interface lets tests inject a fake without making real
// network calls; the concrete *httpAPI satisfies it.
type API interface {
	// ListRepos returns all repos in the configured organization.
	// Implementations must page transparently — callers receive the
	// full list in one slice.
	ListRepos(ctx context.Context) ([]Repo, error)
	// ListOrgMembers returns all members of the configured org along
	// with their 2FA state and role. 2FA state requires admin scope.
	ListOrgMembers(ctx context.Context) ([]Member, error)
}

// Plugin is the in-process github source.
type Plugin struct {
	api API
	org string
	now func() time.Time
}

// Options is the constructor input.
type Options struct {
	API API
	Org string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
// Callers using the real GitHub REST API should use NewFromToken.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api: opts.API,
		org: opts.Org,
		now: now,
	}
}

// NewFromToken constructs a Plugin backed by the real GitHub REST API
// using the supplied personal-access or app token. The plugin issues
// requests against api.github.com. Live integration tests are deferred.
func NewFromToken(_ context.Context, org, token string) (*Plugin, error) {
	if org == "" {
		return nil, fmt.Errorf("github: org is required")
	}
	if token == "" {
		return nil, fmt.Errorf("github: token is required")
	}
	return New(Options{
		API: &httpAPI{
			org:    org,
			token:  token,
			base:   "https://api.github.com",
			client: &http.Client{Timeout: 30 * time.Second},
		},
		Org: org,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string {
	return []string{EvidenceTypeRepository, EvidenceTypeOrgMember}
}

// Init is a no-op; the constructor has already received configuration.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// repoPayload is the JSON payload shape inside each github_repository record.
type repoPayload struct {
	Name                    string `json:"name"`
	DefaultBranch           string `json:"default_branch"`
	BranchProtectionEnabled bool   `json:"branch_protection_enabled"`
	RequiredReviewersCount  int    `json:"required_reviewers_count"`
}

// memberPayload is the JSON payload shape inside each github_org_member record.
type memberPayload struct {
	Login        string `json:"login"`
	TwoFAEnabled bool   `json:"two_fa_enabled"`
	Role         string `json:"role"`
}

// Collect dispatches by req.EvidenceType — a plugin emits multiple
// evidence types and returns records of the type the SlotRequest asks
// for. Records are sorted by ID before return so envelope bytes are
// stable across runs against stable org state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	switch req.EvidenceType {
	case EvidenceTypeRepository:
		return p.collectRepos(ctx)
	case EvidenceTypeOrgMember:
		return p.collectMembers(ctx)
	default:
		return nil, fmt.Errorf("github: unsupported evidence type %q (only %q, %q)",
			req.EvidenceType, EvidenceTypeRepository, EvidenceTypeOrgMember)
	}
}

func (p *Plugin) collectRepos(ctx context.Context) ([]core.EvidenceRecord, error) {
	repos, err := p.api.ListRepos(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: list repos: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(repos))
	for i := range repos {
		r := repos[i]
		payload := repoPayload{
			Name:                    r.Name,
			DefaultBranch:           r.DefaultBranch,
			BranchProtectionEnabled: r.ProtectionOn,
			RequiredReviewersCount:  r.RequiredReviews,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("github: marshal repo payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeRepository,
			ID:          r.Name,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (p *Plugin) collectMembers(ctx context.Context) ([]core.EvidenceRecord, error) {
	members, err := p.api.ListOrgMembers(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: list org members: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(members))
	for i := range members {
		m := members[i]
		payload := memberPayload{
			Login:        m.Login,
			TwoFAEnabled: m.TwoFactorOn,
			Role:         m.Role,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("github: marshal member payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeOrgMember,
			ID:          m.Login,
			IdentityKey: m.Login,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// --- Real HTTP adapter -----------------------------------------------------

// httpAPI is the production implementation of API. It hits api.github.com
// directly via net/http to avoid pulling in github.com/google/go-github
// (which would add a sizable dependency tree). The endpoints used:
//
//	GET /orgs/{org}/repos                  — paged listing of repos
//	GET /repos/{org}/{repo}/branches/{br}/protection  — branch protection
//	GET /orgs/{org}/members?filter=2fa_disabled       — 2FA-off members
//	GET /orgs/{org}/members                — full member roster + role
//
// The adapter respects GitHub's `Link` header for pagination but is
// otherwise minimal; integration coverage is deferred.
type httpAPI struct {
	org    string
	token  string
	base   string
	client *http.Client
}

type ghRepo struct {
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
}

type ghProtection struct {
	RequiredPullRequestReviews struct {
		RequiredApprovingReviewCount int `json:"required_approving_review_count"`
	} `json:"required_pull_request_reviews"`
}

type ghMember struct {
	Login string `json:"login"`
}

type ghMembership struct {
	Role string `json:"role"`
}

func (h *httpAPI) ListRepos(ctx context.Context) ([]Repo, error) {
	var out []Repo
	page := 1
	for {
		path := fmt.Sprintf("/orgs/%s/repos?per_page=100&page=%d", url.PathEscape(h.org), page)
		var repos []ghRepo
		hasMore, err := h.getJSON(ctx, path, &repos)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			rp := Repo{Name: r.Name, DefaultBranch: r.DefaultBranch}
			if r.DefaultBranch != "" {
				on, reviews := h.fetchProtection(ctx, r.Name, r.DefaultBranch)
				rp.ProtectionOn = on
				rp.RequiredReviews = reviews
			}
			out = append(out, rp)
		}
		if !hasMore {
			return out, nil
		}
		page++
	}
}

func (h *httpAPI) fetchProtection(ctx context.Context, repo, branch string) (on bool, requiredReviews int) {
	path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection",
		url.PathEscape(h.org), url.PathEscape(repo), url.PathEscape(branch))
	var p ghProtection
	if _, err := h.getJSON(ctx, path, &p); err != nil {
		// 404 = no protection; any other error is surfaced as
		// protection-off + 0 reviewers. The aggregator decides.
		return false, 0
	}
	return true, p.RequiredPullRequestReviews.RequiredApprovingReviewCount
}

func (h *httpAPI) ListOrgMembers(ctx context.Context) ([]Member, error) {
	// 2FA-disabled members are reported by a filtered listing.
	disabled := map[string]bool{}
	if err := h.listOrgMemberLogins(ctx, "2fa_disabled", disabled); err != nil {
		return nil, err
	}
	// Full roster.
	all := map[string]bool{}
	if err := h.listOrgMemberLogins(ctx, "", all); err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(all))
	for login := range all {
		m := Member{Login: login, TwoFactorOn: !disabled[login]}
		// Role lookup per member; admin scope required.
		role, err := h.fetchMembershipRole(ctx, login)
		if err == nil {
			m.Role = role
		}
		out = append(out, m)
	}
	return out, nil
}

func (h *httpAPI) listOrgMemberLogins(ctx context.Context, filter string, into map[string]bool) error {
	page := 1
	for {
		q := url.Values{}
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		if filter != "" {
			q.Set("filter", filter)
		}
		path := fmt.Sprintf("/orgs/%s/members?%s", url.PathEscape(h.org), q.Encode())
		var members []ghMember
		hasMore, err := h.getJSON(ctx, path, &members)
		if err != nil {
			return err
		}
		for _, m := range members {
			into[m.Login] = true
		}
		if !hasMore {
			return nil
		}
		page++
	}
}

func (h *httpAPI) fetchMembershipRole(ctx context.Context, login string) (string, error) {
	path := fmt.Sprintf("/orgs/%s/memberships/%s", url.PathEscape(h.org), url.PathEscape(login))
	var m ghMembership
	if _, err := h.getJSON(ctx, path, &m); err != nil {
		return "", err
	}
	return m.Role, nil
}

// getJSON performs a single GET and decodes the JSON body into out.
// It returns hasMore=true when the response carries a `Link` header
// with a rel="next" entry.
func (h *httpAPI) getJSON(ctx context.Context, path string, out any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+path, http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode == http.StatusNotFound {
		return false, fmt.Errorf("github: %s: %s", path, resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return false, fmt.Errorf("github: %s: %s: %w", path, resp.Status, readErr)
		}
		return false, fmt.Errorf("github: %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return false, fmt.Errorf("github: decode %s: %w", path, err)
	}
	return hasNextLink(resp.Header.Get("Link")), nil
}

// hasNextLink reports whether a Link header advertises a rel="next" page.
// Format reference: https://docs.github.com/rest/guides/using-pagination-in-the-rest-api
func hasNextLink(link string) bool {
	if link == "" {
		return false
	}
	for _, part := range strings.Split(link, ",") {
		if strings.Contains(part, `rel="next"`) {
			return true
		}
	}
	return false
}

var _ core.SourcePlugin = (*Plugin)(nil)
