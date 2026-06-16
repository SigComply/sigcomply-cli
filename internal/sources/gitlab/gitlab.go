// Package gitlab implements the gitlab source plugin: lists projects
// ("repositories") and members under a single GitLab group and emits the
// cross-vendor git_repository and directory_user evidence types —
// suitable for SOC 2 / ISO 27001 branch-protection, code-review, and
// identity (MFA/admin/lifecycle) policies.
//
// GitLab is one of several substitutable source-code platforms (GitHub,
// Bitbucket, future Gitea/Azure DevOps); a policy accepts the
// git_repository evidence type, not a vendor, so this plugin is
// immediately usable by every policy that already consumes GitHub
// repositories (the substitutability principle —
// docs/architecture/04a-evidence-type-registry.md).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md §The
// plugin contract), the plugin caches nothing across Collect calls. N
// policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the github plugin — the
// concrete *sdkAPI (backed by gitlab.com/gitlab-org/api/client-go)
// satisfies it, and unit tests inject an in-memory fake. The real SDK
// adapter is exercised by an httptest-backed test; live integration
// tests against gitlab.com are deferred to the testing revamp.
//
// directory_user (WU-2.2): the plugin also lists the group's members and
// emits one directory_user per member, mapping AccessLevel ≥ Maintainer
// (or instance-admin) → is_admin, account state → is_active, and the
// user's two_factor_enabled → mfa_enabled. 2FA and instance-admin status
// are only readable with a group-owner / instance-admin token (via the
// Users API); without that privilege the sdkAPI degrades gracefully and
// mfa_enabled is best-effort false — documented in docs/configuration.md.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeRepository is the cross-vendor git_repository shape this
// plugin emits.
const EvidenceTypeRepository = "git_repository"

// EvidenceTypeDirectoryUser is the cross-vendor directory_user shape this
// plugin emits for the group's members — identical to the shape the
// github and okta plugins emit (the same identity evidence type).
const EvidenceTypeDirectoryUser = "directory_user"

// SourceID is the registered ID for the gitlab plugin instance.
const SourceID = "gitlab"

// defaultBaseURL is the gitlab.com REST endpoint; self-managed instances
// override it via the base_url config key.
const defaultBaseURL = "https://gitlab.com"

// Repo is the subset of fields the plugin extracts from a GitLab project,
// normalized into the git_repository contract. Every field maps to a
// property of the git_repository evidence type so policies never read an
// absent field.
//
// Fields without a read-only GitLab API analog are left at their zero
// value and documented at the mapping site (sdkAPI.ListRepos):
//   - SecretScanningEnabled / CodeScanningEnabled / DependabotAlertsEnabled
//     (GitLab pipeline SAST/Secret/Dependency scanning is configured in
//     .gitlab-ci.yml, not exposed as a project-settings boolean).
type Repo struct {
	Name            string
	DefaultBranch   string
	ProtectionOn    bool
	RequiredReviews int

	RequiresSignedCommits   bool
	RequiresLinearHistory   bool
	AllowsForcePush         bool
	DismissStaleReviews     bool
	RequireCodeOwnerReviews bool

	IsPrivate bool
	Archived  bool

	SecretScanningEnabled   bool
	PushProtectionEnabled   bool
	DependabotAlertsEnabled bool
	CodeScanningEnabled     bool
}

// Member is the subset of fields the plugin extracts from a GitLab group
// member, normalized into the directory_user contract. Every field maps
// to a property the consuming policies read so none reads an absent field.
//
// MFAEnabled and the instance-admin component of IsAdmin require a
// group-owner / instance-admin token (the Users API exposes
// two_factor_enabled / is_admin); the sdkAPI degrades gracefully when the
// token can't read them, leaving MFAEnabled best-effort false.
type Member struct {
	Username   string
	Name       string
	Email      string
	MFAEnabled bool
	IsAdmin    bool
	IsActive   bool
}

// API is the subset of the GitLab REST API the plugin uses. Defining it
// as an interface lets tests inject a fake without making real network
// calls; the concrete *sdkAPI satisfies it.
type API interface {
	// ListRepos returns all projects under the configured group,
	// normalized into the git_repository contract. Implementations must
	// page transparently — callers receive the full list in one slice.
	ListRepos(ctx context.Context) ([]Repo, error)
	// ListMembers returns all members of the configured group, normalized
	// into the directory_user contract. Implementations must page
	// transparently — callers receive the full list in one slice.
	ListMembers(ctx context.Context) ([]Member, error)
}

// Plugin is the in-process gitlab source.
type Plugin struct {
	api API
	now func() time.Time
}

// Options is the constructor input.
type Options struct {
	API API
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers
// using the real GitLab REST API should use NewFromToken.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{api: opts.API, now: now}
}

// NewFromToken constructs a Plugin backed by the real GitLab REST API for
// the given group, using the supplied personal-access/group token. A
// blank baseURL defaults to gitlab.com; self-managed instances pass their
// own URL. Live integration tests are deferred.
func NewFromToken(_ context.Context, group, token, baseURL string) (*Plugin, error) {
	if group == "" {
		return nil, fmt.Errorf("gitlab: group is required")
	}
	if token == "" {
		return nil, fmt.Errorf("gitlab: token is required")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	client, err := gitlab.NewClient(token, gitlab.WithBaseURL(baseURL))
	if err != nil {
		return nil, fmt.Errorf("gitlab: build client: %w", err)
	}
	return New(Options{API: &sdkAPI{client: client, group: group}}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce: project
// metadata as git_repository and group members as directory_user.
func (*Plugin) Emits() []string {
	return []string{EvidenceTypeRepository, EvidenceTypeDirectoryUser}
}

// Init is a no-op; the constructor has already received configuration.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// repoPayload is the git_repository shape this plugin emits — identical to
// the github plugin's (it is the same cross-vendor evidence type). Every
// boolean/integer property the schema declares is emitted (never omitempty
// on the policy-read fields): an absent field would error the consuming
// policy rather than being read as false, so the plugin owns the full
// cross-vendor contract.
type repoPayload struct {
	Name                   string `json:"name"`
	DefaultBranch          string `json:"default_branch"`
	DefaultBranchProtected bool   `json:"default_branch_protected"`
	RequiredReviewersCount int    `json:"required_reviewers_count"`

	RequiresSignedCommits   bool `json:"requires_signed_commits"`
	RequiresLinearHistory   bool `json:"requires_linear_history"`
	AllowsForcePush         bool `json:"allows_force_push"`
	DismissStaleReviews     bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews bool `json:"require_code_owner_reviews"`

	IsPrivate bool `json:"is_private"`
	Archived  bool `json:"archived"`

	SecretScanningEnabled   bool `json:"secret_scanning_enabled"`
	PushProtectionEnabled   bool `json:"push_protection_enabled"`
	DependabotAlertsEnabled bool `json:"dependabot_alerts_enabled"`
	CodeScanningEnabled     bool `json:"code_scanning_enabled"`
}

// memberPayload is the directory_user shape this plugin emits — identical
// to the github/okta plugins' (the same cross-vendor evidence type). The
// policy-read booleans are emitted unconditionally (an absent field errors
// the consuming policy rather than reading as false); email is optional in
// the schema and omitted when GitLab does not expose it.
type memberPayload struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
	MFAEnabled  bool   `json:"mfa_enabled"`
	IsAdmin     bool   `json:"is_admin"`
	IsActive    bool   `json:"is_active"`
}

// Collect dispatches to the per-type collectors for whichever emitted
// types the slot accepts, returning their records together. A slot that
// accepts neither emitted type is rejected.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantRepos := req.Accepts(EvidenceTypeRepository)
	wantMembers := req.Accepts(EvidenceTypeDirectoryUser)
	if !wantRepos && !wantMembers {
		return nil, fmt.Errorf("gitlab: AcceptedTypes %v does not include emitted types %q,%q",
			req.AcceptedTypes, EvidenceTypeRepository, EvidenceTypeDirectoryUser)
	}
	var out []core.EvidenceRecord
	if wantRepos {
		rs, err := p.collectRepos(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if wantMembers {
		rs, err := p.collectMembers(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

// collectRepos returns one git_repository record per project under the
// group, sorted by ID (the project path).
func (p *Plugin) collectRepos(ctx context.Context) ([]core.EvidenceRecord, error) {
	repos, err := p.api.ListRepos(ctx)
	if err != nil {
		return nil, fmt.Errorf("gitlab: list repos: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(repos))
	for i := range repos {
		r := repos[i]
		payload := repoPayload{
			Name:                    r.Name,
			DefaultBranch:           r.DefaultBranch,
			DefaultBranchProtected:  r.ProtectionOn,
			RequiredReviewersCount:  r.RequiredReviews,
			RequiresSignedCommits:   r.RequiresSignedCommits,
			RequiresLinearHistory:   r.RequiresLinearHistory,
			AllowsForcePush:         r.AllowsForcePush,
			DismissStaleReviews:     r.DismissStaleReviews,
			RequireCodeOwnerReviews: r.RequireCodeOwnerReviews,
			IsPrivate:               r.IsPrivate,
			Archived:                r.Archived,
			SecretScanningEnabled:   r.SecretScanningEnabled,
			PushProtectionEnabled:   r.PushProtectionEnabled,
			DependabotAlertsEnabled: r.DependabotAlertsEnabled,
			CodeScanningEnabled:     r.CodeScanningEnabled,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gitlab: marshal repo payload: %w", err)
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

// collectMembers returns one directory_user record per group member,
// sorted by ID (the member's username). IdentityKey is the username —
// the stable per-source identity (mirroring github; GitLab member email
// is not reliably exposed without an elevated token).
func (p *Plugin) collectMembers(ctx context.Context) ([]core.EvidenceRecord, error) {
	members, err := p.api.ListMembers(ctx)
	if err != nil {
		return nil, fmt.Errorf("gitlab: list members: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(members))
	for i := range members {
		m := members[i]
		payload := memberPayload{
			ID:          m.Username,
			DisplayName: m.Name,
			Email:       m.Email,
			MFAEnabled:  m.MFAEnabled,
			IsAdmin:     m.IsAdmin,
			IsActive:    m.IsActive,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gitlab: marshal member payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeDirectoryUser,
			ID:          m.Username,
			IdentityKey: m.Username,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// --- Real SDK adapter ------------------------------------------------------

// sdkAPI is the production implementation of API, backed by the official
// GitLab Go client. For each project under the group it issues follow-up
// calls to read branch-protection, approval-rule, and push-rule state,
// degrading gracefully when an endpoint is unavailable (404 on free tier
// or for an unprotected branch, 403 on insufficient privilege) rather
// than failing the whole listing.
type sdkAPI struct {
	client *gitlab.Client
	group  string
}

func (s *sdkAPI) ListRepos(ctx context.Context) ([]Repo, error) {
	opt := &gitlab.ListGroupProjectsOptions{
		ListOptions:      gitlab.ListOptions{PerPage: 100, Page: 1},
		IncludeSubGroups: gitlab.Ptr(true),
	}
	var out []Repo
	for {
		projects, resp, err := s.client.Groups.ListGroupProjects(s.group, opt, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("gitlab: list group projects: %w", err)
		}
		for _, proj := range projects {
			out = append(out, s.mapProject(ctx, proj))
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return out, nil
}

// mapProject normalizes one GitLab project into the git_repository
// contract, issuing the per-project follow-up reads.
func (s *sdkAPI) mapProject(ctx context.Context, proj *gitlab.Project) Repo {
	r := Repo{
		Name:          proj.PathWithNamespace,
		DefaultBranch: proj.DefaultBranch,
		// Visibility is private|internal|public; anything but public is
		// non-public for the is_private contract.
		IsPrivate: proj.Visibility != gitlab.PublicVisibility,
		Archived:  proj.Archived,
		// Fast-forward merge forbids merge commits → linear history.
		RequiresLinearHistory: proj.MergeMethod == gitlab.FastForwardMerge,
		// Pre-receive secret detection is GitLab's push-time secret
		// blocking — the closest analog to push_protection_enabled.
		PushProtectionEnabled: proj.PreReceiveSecretDetectionEnabled,
		// No read-only GitLab analog (pipeline scanning lives in
		// .gitlab-ci.yml, not a project-settings boolean): left false.
		SecretScanningEnabled:   false,
		CodeScanningEnabled:     false,
		DependabotAlertsEnabled: false,
	}

	// Branch protection on the default branch. A 404 means the default
	// branch carries no exact-name protection rule (treat as unprotected);
	// any other error also leaves the protection fields at false.
	if proj.DefaultBranch != "" {
		pb, resp, err := s.client.ProtectedBranches.GetProtectedBranch(
			proj.ID, proj.DefaultBranch, gitlab.WithContext(ctx))
		if err == nil && pb != nil {
			r.ProtectionOn = true
			r.AllowsForcePush = pb.AllowForcePush
			r.RequireCodeOwnerReviews = pb.CodeOwnerApprovalRequired
		} else if !isNotFound(resp) {
			// Non-404 (e.g. 403 insufficient privilege): leave unprotected
			// rather than failing the run; the gap surfaces via the policy.
			_ = err
		}
	}

	// Required reviewer count: the maximum approvals_required across the
	// project's approval rules (free tier exposes a single rule).
	if rules, _, err := s.client.Projects.GetProjectApprovalRules(
		proj.ID, &gitlab.GetProjectApprovalRulesListsOptions{}, gitlab.WithContext(ctx)); err == nil {
		for _, rule := range rules {
			if int(rule.ApprovalsRequired) > r.RequiredReviews {
				r.RequiredReviews = int(rule.ApprovalsRequired)
			}
		}
	}

	// Dismiss-stale-reviews ↔ reset approvals when new commits are pushed.
	if cfg, _, err := s.client.Projects.GetApprovalConfiguration(
		proj.ID, gitlab.WithContext(ctx)); err == nil && cfg != nil {
		r.DismissStaleReviews = cfg.ResetApprovalsOnPush
	}

	// Signed-commit enforcement via push rules (premium; 404 on free tier
	// or when no push rule is configured → false).
	if pr, _, err := s.client.Projects.GetProjectPushRules(
		proj.ID, gitlab.WithContext(ctx)); err == nil && pr != nil {
		r.RequiresSignedCommits = pr.RejectUnsignedCommits
	}

	return r
}

// ListMembers lists the configured group's members, normalizing each into
// the directory_user contract. AccessLevel and account state come straight
// from the members listing; two_factor_enabled and instance-admin status
// require a per-member Users-API read that only a privileged token can
// satisfy — that read degrades gracefully (best-effort) so an
// insufficiently-scoped token still yields a usable listing rather than a
// hard failure.
func (s *sdkAPI) ListMembers(ctx context.Context) ([]Member, error) {
	opt := &gitlab.ListGroupMembersOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
	}
	var out []Member
	for {
		members, resp, err := s.client.Groups.ListAllGroupMembers(s.group, opt, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("gitlab: list group members: %w", err)
		}
		for _, m := range members {
			out = append(out, s.mapMember(ctx, m))
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return out, nil
}

// mapMember normalizes one GitLab group member into the directory_user
// contract. is_admin is the group role (Maintainer/Owner) OR instance
// admin; mfa_enabled and instance-admin come from a per-member Users-API
// read that degrades gracefully when the token lacks the privilege.
func (s *sdkAPI) mapMember(ctx context.Context, m *gitlab.GroupMember) Member {
	mem := Member{
		Username: m.Username,
		Name:     m.Name,
		Email:    m.Email,
		// AccessLevel ≥ Maintainer (40) is the group-level elevated role;
		// instance admins are folded in below from the Users API.
		IsAdmin:  m.AccessLevel >= gitlab.MaintainerPermissions,
		IsActive: m.State == "active",
	}
	// two_factor_enabled and is_admin (instance) are only on the User
	// object, readable via the Users API with a group-owner / instance-admin
	// token. Any error (403 insufficient privilege, 404) leaves mfa_enabled
	// best-effort false rather than failing the listing — documented as a
	// known v1 visibility gap in docs/configuration.md.
	if u, _, err := s.client.Users.GetUser(m.ID, gitlab.GetUsersOptions{}, gitlab.WithContext(ctx)); err == nil && u != nil {
		mem.MFAEnabled = u.TwoFactorEnabled
		if u.IsAdmin {
			mem.IsAdmin = true
		}
	}
	return mem
}

// isNotFound reports whether a GitLab response carries a 404 status. The
// client returns a non-nil *Response even on HTTP error, so the status is
// readable alongside the error.
func isNotFound(resp *gitlab.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusNotFound
}

var _ core.SourcePlugin = (*Plugin)(nil)
