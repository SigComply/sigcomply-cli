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
// Period-scoped types: alongside the two configuration snapshots the
// plugin also emits pull_request (one record per merge request MERGED
// inside the audit window) and deployment (one record per release to a
// GitLab environment in the window, failed ones included). GitLab merge
// requests map onto the cross-vendor pull_request type deliberately —
// the type is vendor-neutral, so one CC8.1 / ISO A.8.32 change-review
// policy samples GitHub PRs and GitLab MRs through a single contract.
// The window arrives as period_start / period_end slot params; a caller
// that passes none (the conformance harness) gets a trailing one-year
// window ending at the injected clock, never time.Now().
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
	"strconv"
	"strings"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeRepository is the cross-vendor git_repository shape this
// plugin emits.
const EvidenceTypeRepository = "git_repository"

// EvidenceTypeDirectoryUser is the cross-vendor directory_user shape this
// plugin emits for the group's members — identical to the shape the
// github and okta plugins emit (the same identity evidence type).
const EvidenceTypeDirectoryUser = "directory_user"

// EvidenceTypePullRequest is the cross-vendor pull_request shape — one
// record per change MERGED during the audit period. A GitLab merge
// request IS that change; the evidence type is vendor-neutral, so the
// github and gitlab plugins are substitutable for a change-review
// policy. It answers "did this change actually get reviewed?", which
// the git_repository configuration snapshot structurally cannot.
const EvidenceTypePullRequest = "pull_request"

// EvidenceTypeDeployment is the cross-vendor deployment shape — one
// record per release to a running environment during the period,
// failed ones included.
const EvidenceTypeDeployment = "deployment"

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

// PullRequest is one merge request MERGED into a project under the
// group during the audit period. The adapter supplies the raw vendor
// facts — GitLab's flat approver list and the newest MR pipeline's
// outcome; the plugin derives approval_count /
// independent_approval_count / approved_before_merge from them, so the
// normalization is unit-testable without a network.
type PullRequest struct {
	// Repository is the project's full path ("group/project"), the same
	// form git_repository uses for name, so the two types join.
	Repository string
	// Number is the MR iid — the per-project number a customer quotes in
	// a waiver, not the instance-wide id.
	Number       int
	Author       string
	MergedBy     string
	TargetBranch string
	// MergeCommitSHA is the commit the MR produced on the target branch;
	// the adapter substitutes the squash commit when the project squashes
	// and GitLab therefore reports no merge commit.
	MergeCommitSHA string
	MergedAt       time.Time
	// Approvers carries the usernames GitLab reports in approved_by,
	// verbatim — the plugin de-duplicates and drops blanks. Empty when
	// the approvals endpoint could not be read (graceful degradation) or
	// when nobody approved.
	Approvers []string
	// ChecksPassed is true when the newest pipeline attached to the MR
	// succeeded. GitLab exposes no per-check aggregate comparable to
	// GitHub's check runs, so the head pipeline is the CI signal.
	ChecksPassed bool
}

// Deployment is one release of code to a GitLab environment during the
// audit period, including failed ones — a failed production deployment
// is still a change event an auditor may ask about.
type Deployment struct {
	Repository string
	// ID is the vendor-native deployment identifier as a string.
	ID  string
	SHA string
	// Environment is the environment name exactly as GitLab reports it.
	Environment string
	// EnvironmentTier is GitLab's environment tier ("production",
	// "staging", …). Empty when the project never set one, in which case
	// the plugin falls back to the environment name for is_production.
	EnvironmentTier string
	Creator         string
	CreatedAt       time.Time
	// Status is the raw GitLab deployment status (created / running /
	// success / failed / canceled / blocked), normalized by the plugin
	// into the deployment type's closed vocabulary.
	Status string
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
	// ListMergedPullRequests returns the group's merge requests merged
	// inside [start, end], normalized into the pull_request contract.
	// Implementations must page transparently and may over-return —
	// the plugin re-applies the window, so it owns the period semantics
	// regardless of which API implementation is wired in.
	ListMergedPullRequests(ctx context.Context, start, end time.Time) ([]PullRequest, error)
	// ListDeployments returns the group's deployments created inside
	// [start, end], failed ones included, normalized into the deployment
	// contract. Implementations must page transparently and may
	// over-return; the plugin re-applies the window.
	ListDeployments(ctx context.Context, start, end time.Time) ([]Deployment, error)
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
// metadata as git_repository, group members as directory_user, and the
// two period-scoped types — merged merge requests as pull_request and
// environment releases as deployment.
func (*Plugin) Emits() []string {
	return []string{
		EvidenceTypeRepository, EvidenceTypeDirectoryUser,
		EvidenceTypePullRequest, EvidenceTypeDeployment,
	}
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
// the schema and omitted when GitLab does not expose it. username carries
// the GitLab username (also the record id) for roster alias matching.
type memberPayload struct {
	ID          string `json:"id"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
	MFAEnabled  bool   `json:"mfa_enabled"`
	IsAdmin     bool   `json:"is_admin"`
	IsActive    bool   `json:"is_active"`
}

// pullRequestPayload is the pull_request shape this plugin emits — one
// record per merged merge request. Identical to the github plugin's (it
// is the same cross-vendor evidence type). Every property the schema
// declares is emitted unconditionally (no omitempty): the four derived
// fields are policy-read, and an absent field errors the consuming
// policy rather than reading as false/zero. merged_at is RFC3339 UTC.
type pullRequestPayload struct {
	Repository               string `json:"repository"`
	Number                   int    `json:"number"`
	Author                   string `json:"author"`
	MergedBy                 string `json:"merged_by"`
	TargetBranch             string `json:"target_branch"`
	MergeCommitSHA           string `json:"merge_commit_sha"`
	MergedAt                 string `json:"merged_at"`
	ApprovalCount            int    `json:"approval_count"`
	IndependentApprovalCount int    `json:"independent_approval_count"`
	ApprovedBeforeMerge      bool   `json:"approved_before_merge"`
	ChecksPassed             bool   `json:"checks_passed"`
}

// deploymentPayload is the deployment shape this plugin emits — one
// record per deployment created in the period. Every schema property is
// emitted unconditionally; environment is verbatim vendor text while
// is_production and status are normalized by the plugin.
type deploymentPayload struct {
	Repository   string `json:"repository"`
	DeploymentID string `json:"deployment_id"`
	Environment  string `json:"environment"`
	IsProduction bool   `json:"is_production"`
	DeployedBy   string `json:"deployed_by"`
	DeployedAt   string `json:"deployed_at"`
	CommitSHA    string `json:"commit_sha"`
	Status       string `json:"status"`
}

// Collect dispatches to the per-type collectors for whichever emitted
// types the slot accepts, returning their records together. A slot that
// accepts none of the emitted types is rejected. Records are sorted by
// ID within each type group; the collector splits them by Type for
// envelope writing.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	// The period window is resolved once so a slot accepting both
	// period-scoped types sees one identical [start, end].
	start, end := p.periodWindow(req)
	collectors := []struct {
		typeID  string
		collect func(context.Context) ([]core.EvidenceRecord, error)
	}{
		{EvidenceTypeRepository, p.collectRepos},
		{EvidenceTypeDirectoryUser, p.collectMembers},
		{EvidenceTypePullRequest, func(ctx context.Context) ([]core.EvidenceRecord, error) {
			return p.collectPullRequests(ctx, start, end)
		}},
		{EvidenceTypeDeployment, func(ctx context.Context) ([]core.EvidenceRecord, error) {
			return p.collectDeployments(ctx, start, end)
		}},
	}
	var out []core.EvidenceRecord
	matched := false
	for _, c := range collectors {
		if !req.Accepts(c.typeID) {
			continue
		}
		matched = true
		rs, err := c.collect(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if !matched {
		return nil, fmt.Errorf("gitlab: AcceptedTypes %v does not include emitted types %q,%q,%q,%q",
			req.AcceptedTypes, EvidenceTypeRepository, EvidenceTypeDirectoryUser,
			EvidenceTypePullRequest, EvidenceTypeDeployment)
	}
	return out, nil
}

// periodWindow resolves the audit window for the period-scoped evidence
// types. The orchestrator injects period_start/period_end as native
// time.Time slot params; callers that pass none (the conformance
// harness, an ad-hoc Collect) get a trailing one-year window ending at
// the injected clock, never time.Now() — two Collects must agree.
func (p *Plugin) periodWindow(req core.SlotRequest) (start, end time.Time) {
	start = timeParam(req.Params, "period_start")
	end = timeParam(req.Params, "period_end")
	if end.IsZero() {
		end = p.now()
	}
	if start.IsZero() {
		start = end.AddDate(-1, 0, 0)
	}
	return start, end
}

// timeParam reads a time.Time slot parameter, returning the zero value
// when missing or the wrong type. Slot params are map[string]any by
// design. (Duplicated from internal/sources/manual per the plugin
// KISS-no-DRY axiom — source plugins share no helper package.)
func timeParam(m map[string]any, key string) time.Time {
	if v, ok := m[key].(time.Time); ok {
		return v
	}
	return time.Time{}
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
			Username:    m.Username,
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

// collectPullRequests returns one pull_request record per merge request
// merged inside [start, end]. Record IDs are "{group}/{project}#{iid}" —
// the form a customer writes in a YAML waiver's resource_id, so it must
// stay stable and human-writable. The window is re-applied here (the
// adapter already filters) so the plugin owns the period semantics
// regardless of which API implementation is wired in.
func (p *Plugin) collectPullRequests(ctx context.Context, start, end time.Time) ([]core.EvidenceRecord, error) {
	prs, err := p.api.ListMergedPullRequests(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("gitlab: list merged merge requests: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(prs))
	for i := range prs {
		pr := prs[i]
		if pr.MergedAt.IsZero() || pr.MergedAt.Before(start) || pr.MergedAt.After(end) {
			continue
		}
		approvals, independent, beforeMerge := approvalState(&pr)
		payload := pullRequestPayload{
			Repository:               pr.Repository,
			Number:                   pr.Number,
			Author:                   pr.Author,
			MergedBy:                 pr.MergedBy,
			TargetBranch:             pr.TargetBranch,
			MergeCommitSHA:           pr.MergeCommitSHA,
			MergedAt:                 pr.MergedAt.UTC().Format(time.RFC3339),
			ApprovalCount:            approvals,
			IndependentApprovalCount: independent,
			ApprovedBeforeMerge:      beforeMerge,
			ChecksPassed:             pr.ChecksPassed,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gitlab: marshal merge request payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypePullRequest,
			ID:          fmt.Sprintf("%s#%d", pr.Repository, pr.Number),
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// approvalState reduces GitLab's flat approver list to the three
// approval fields the pull_request evidence type declares.
//
// Counting rule: one vote per distinct non-blank username — GitLab's
// approved_by is already the current approval set (a withdrawn approval
// leaves it), so there is no review state machine to collapse as there
// is on GitHub. approvalCount includes the author; independentCount
// excludes them, so a self-approved change reads as zero.
//
// approvedBeforeMerge is simply "an independent approval exists":
// GitLab exposes NO approval timestamp, and an approval cannot be
// recorded there after the merge (the MR is closed to approvals once
// merged), so an approval that exists is necessarily one that preceded
// the merge.
func approvalState(pr *PullRequest) (approvalCount, independentCount int, approvedBeforeMerge bool) {
	seen := make(map[string]bool, len(pr.Approvers))
	for _, raw := range pr.Approvers {
		user := strings.TrimSpace(raw)
		if user == "" || seen[user] {
			continue
		}
		seen[user] = true
		approvalCount++
		if user == pr.Author {
			continue
		}
		independentCount++
	}
	return approvalCount, independentCount, independentCount >= 1
}

// collectDeployments returns one deployment record per deployment
// created inside [start, end], failed ones included. Record IDs are
// "{group}/{project}/deployments/{id}" — waiver-writable, like the
// pull_request form.
func (p *Plugin) collectDeployments(ctx context.Context, start, end time.Time) ([]core.EvidenceRecord, error) {
	deployments, err := p.api.ListDeployments(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("gitlab: list deployments: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(deployments))
	for i := range deployments {
		d := deployments[i]
		if d.CreatedAt.IsZero() || d.CreatedAt.Before(start) || d.CreatedAt.After(end) {
			continue
		}
		payload := deploymentPayload{
			Repository:   d.Repository,
			DeploymentID: d.ID,
			Environment:  d.Environment,
			IsProduction: isProductionEnvironment(d.EnvironmentTier, d.Environment),
			DeployedBy:   d.Creator,
			DeployedAt:   d.CreatedAt.UTC().Format(time.RFC3339),
			CommitSHA:    d.SHA,
			Status:       normalizeDeploymentStatus(d.Status),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gitlab: marshal deployment payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeDeployment,
			ID:          fmt.Sprintf("%s/deployments/%s", d.Repository, d.ID),
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// environmentTierProduction is GitLab's declared production tier — the
// authoritative signal, since a project that sets tiers has told GitLab
// exactly which environment is production.
const environmentTierProduction = "production"

// isProductionEnvironment normalizes GitLab's two production signals.
// A non-empty tier is authoritative in BOTH directions: an environment
// explicitly tiered "staging" is not production even when it is named
// "prod-canary". Only when the project set no tier at all does the
// conventional environment name decide. Keeping the customer's local
// naming out of policies is the point of is_production.
func isProductionEnvironment(tier, environment string) bool {
	if t := strings.ToLower(strings.TrimSpace(tier)); t != "" {
		return t == environmentTierProduction
	}
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case environmentTierProduction, "prod", "live":
		return true
	default:
		return false
	}
}

// The deployment evidence type's closed status vocabulary. Named
// because the enum is the contract policies read, distinct from the raw
// GitLab statuses the switch below matches on.
const (
	deploymentStatusSuccess = "success"
	deploymentStatusFailure = "failure"
	deploymentStatusPending = "pending"
	deploymentStatusUnknown = "unknown"
)

// normalizeDeploymentStatus maps GitLab's deployment status to the
// deployment status enum. An empty or unrecognized status maps to
// "unknown" rather than guessing a terminal outcome — the schema is
// explicit that unknown must never be read as either success or
// failure, and it is distinct from pending.
func normalizeDeploymentStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case deploymentStatusSuccess:
		return deploymentStatusSuccess
	case "failed", "canceled":
		return deploymentStatusFailure
	case "created", "running", "blocked":
		return deploymentStatusPending
	default:
		return deploymentStatusUnknown
	}
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
		IncludeSubGroups: new(true),
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
	if u, _, err := s.client.Users.GetUser(m.ID, &gitlab.GetUserOptions{}, gitlab.WithContext(ctx)); err == nil && u != nil {
		mem.MFAEnabled = u.TwoFactorEnabled
		if u.IsAdmin {
			mem.IsAdmin = true
		}
	}
	return mem
}

// mergeRequestStateMerged is the only MR state the pull_request contract
// admits: the type is a population of CHANGES, and an open or
// closed-without-merge MR never became one.
const mergeRequestStateMerged = "merged"

// projectIndex lists the group's projects once and returns a
// projectID → full-path lookup plus those project IDs in ascending
// order. Both period-scoped collectors need it: the merge-request
// listing is group-wide but reports only a numeric project_id (the
// pull_request contract needs the path, so git_repository joins), and
// the deployments endpoint is per-project only — GitLab publishes no
// group-level deployments route. The ID slice is sorted because Go map
// iteration order is randomized and two Collect runs must agree.
func (s *sdkAPI) projectIndex(ctx context.Context) (paths map[int64]string, ids []int64, err error) {
	opt := &gitlab.ListGroupProjectsOptions{
		ListOptions:      gitlab.ListOptions{PerPage: 100, Page: 1},
		IncludeSubGroups: new(true),
	}
	paths = map[int64]string{}
	for {
		projects, resp, lerr := s.client.Groups.ListGroupProjects(s.group, opt, gitlab.WithContext(ctx))
		if lerr != nil {
			return nil, nil, fmt.Errorf("gitlab: list group projects: %w", lerr)
		}
		for _, proj := range projects {
			paths[proj.ID] = proj.PathWithNamespace
			ids = append(ids, proj.ID)
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return paths, ids, nil
}

// ListMergedPullRequests lists the group's merged merge requests via the
// group-wide endpoint (one listing for every project, rather than N
// per-project listings). GitLab offers no merged_after filter, so
// UpdatedAfter is the server-side pre-filter — a merged MR is never
// updated before it is merged — and the real [start, end] test is
// applied client-side against merged_at.
func (s *sdkAPI) ListMergedPullRequests(ctx context.Context, start, end time.Time) ([]PullRequest, error) {
	paths, _, err := s.projectIndex(ctx)
	if err != nil {
		return nil, err
	}
	opt := &gitlab.ListGroupMergeRequestsOptions{
		ListOptions:  gitlab.ListOptions{PerPage: 100, Page: 1},
		State:        new(mergeRequestStateMerged),
		UpdatedAfter: &start,
	}
	var out []PullRequest
	for {
		mrs, resp, lerr := s.client.MergeRequests.ListGroupMergeRequests(s.group, opt, gitlab.WithContext(ctx))
		if lerr != nil {
			return nil, fmt.Errorf("gitlab: list group merge requests: %w", lerr)
		}
		for _, mr := range mrs {
			if pr, ok := s.mapMergeRequest(ctx, mr, paths, start, end); ok {
				out = append(out, pr)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return out, nil
}

// mapMergeRequest normalizes one merge request into the pull_request
// contract, issuing the per-MR approvals and pipelines reads. It
// reports false for an MR that is outside the window, unmerged, or
// whose project is absent from the group listing (no path to report, so
// it cannot satisfy the repository contract).
func (s *sdkAPI) mapMergeRequest(ctx context.Context, mr *gitlab.BasicMergeRequest,
	paths map[int64]string, start, end time.Time) (PullRequest, bool) {
	if mr == nil || mr.MergedAt == nil {
		return PullRequest{}, false
	}
	path, ok := paths[mr.ProjectID]
	if !ok {
		return PullRequest{}, false
	}
	mergedAt := mr.MergedAt.UTC()
	if mergedAt.Before(start) || mergedAt.After(end) {
		return PullRequest{}, false
	}
	pr := PullRequest{
		Repository:     path,
		Number:         int(mr.IID),
		MergedBy:       mergeUsername(mr),
		TargetBranch:   mr.TargetBranch,
		MergeCommitSHA: mr.MergeCommitSHA,
		MergedAt:       mergedAt,
		Approvers:      s.mergeRequestApprovers(ctx, mr.ProjectID, mr.IID),
		ChecksPassed:   s.mergeRequestChecksPassed(ctx, mr.ProjectID, mr.IID),
	}
	if mr.Author != nil {
		pr.Author = mr.Author.Username
	}
	if pr.MergeCommitSHA == "" {
		// A squash-merged MR reports no merge_commit_sha; the squash
		// commit IS the commit it produced on the target branch, which is
		// what deployment.commit_sha joins against.
		pr.MergeCommitSHA = mr.SquashCommitSHA
	}
	return pr, true
}

// mergeUsername reports who performed the merge, empty when GitLab
// attributes it to no user.
func mergeUsername(mr *gitlab.BasicMergeRequest) string {
	if mr.MergeUser != nil {
		return mr.MergeUser.Username
	}
	// MergedBy is the pre-v5 predecessor of MergeUser and is the only
	// populated field on self-managed instances older than the release
	// that introduced MergeUser; dropping the fallback would silently
	// blank merged_by on those instances.
	if u := mr.MergedBy; u != nil { //nolint:staticcheck // SA1019: deliberate fallback for pre-MergeUser self-managed instances.
		return u.Username
	}
	return ""
}

// mergeRequestApprovers reads the MR's approver usernames. The
// single-MR approvals endpoint IS available on GitLab Free; approval
// RULES are Premium and 403/404 there, so any error degrades to "no
// approvers recorded" (counts 0, non-fatal) rather than failing the
// whole run — the same graceful-degradation idiom mapProject uses for
// push rules.
func (s *sdkAPI) mergeRequestApprovers(ctx context.Context, projectID, iid int64) []string {
	cfg, _, err := s.client.MergeRequestApprovals.GetConfiguration(projectID, iid, gitlab.WithContext(ctx))
	if err != nil || cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.ApprovedBy))
	for _, a := range cfg.ApprovedBy {
		if a == nil || a.User == nil {
			continue
		}
		out = append(out, a.User.Username)
	}
	return out
}

// pipelineStatusSuccess is the only GitLab pipeline status that counts
// as checks having passed.
const pipelineStatusSuccess = "success"

// mergeRequestChecksPassed reports whether the newest pipeline attached
// to the MR succeeded. GitLab returns MR pipelines newest-first, so the
// head of the list is the run that gated the merge. No pipelines at all
// — and an unreadable listing — deliberately report false: the schema
// states that a change merged with nothing verifying it is exactly the
// condition CC8.1 asks about, so "no CI configured" is not a pass.
func (s *sdkAPI) mergeRequestChecksPassed(ctx context.Context, projectID, iid int64) bool {
	pipelines, _, err := s.client.MergeRequests.ListMergeRequestPipelines(projectID, iid, gitlab.WithContext(ctx))
	if err != nil || len(pipelines) == 0 || pipelines[0] == nil {
		return false
	}
	return strings.EqualFold(pipelines[0].Status, pipelineStatusSuccess)
}

// ListDeployments lists every project's deployments in the window.
// GitLab publishes no group-level deployments route, so this iterates
// the group's projects in ascending-ID order (deterministically — Go map
// order is randomized).
func (s *sdkAPI) ListDeployments(ctx context.Context, start, end time.Time) ([]Deployment, error) {
	paths, ids, err := s.projectIndex(ctx)
	if err != nil {
		return nil, err
	}
	var out []Deployment
	for _, id := range ids {
		ds, derr := s.projectDeployments(ctx, id, paths[id], start, end)
		if derr != nil {
			return nil, derr
		}
		out = append(out, ds...)
	}
	return out, nil
}

// projectDeployments lists one project's deployments. Unlike the
// merge-request endpoint this one accepts a server-side updated window,
// which is applied as a pre-filter; the authoritative [start, end] test
// is still made client-side against created_at, the field the deployment
// contract records.
func (s *sdkAPI) projectDeployments(ctx context.Context, projectID int64, path string,
	start, end time.Time) ([]Deployment, error) {
	opt := &gitlab.ListProjectDeploymentsOptions{
		ListOptions:   gitlab.ListOptions{PerPage: 100, Page: 1},
		UpdatedAfter:  &start,
		UpdatedBefore: &end,
	}
	var out []Deployment
	for {
		deployments, resp, err := s.client.Deployments.ListProjectDeployments(
			projectID, opt, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("gitlab: list deployments for project %d: %w", projectID, err)
		}
		for _, d := range deployments {
			if dep, ok := mapDeployment(d, path, start, end); ok {
				out = append(out, dep)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return out, nil
}

// mapDeployment normalizes one GitLab deployment into the deployment
// contract, reporting false when it falls outside the window. The
// status is carried through raw — the plugin, not the adapter, owns the
// mapping into the evidence type's closed vocabulary.
func mapDeployment(d *gitlab.Deployment, path string, start, end time.Time) (Deployment, bool) {
	if d == nil || d.CreatedAt == nil {
		return Deployment{}, false
	}
	createdAt := d.CreatedAt.UTC()
	if createdAt.Before(start) || createdAt.After(end) {
		return Deployment{}, false
	}
	// The instance-wide id is what addresses the deployment in the API;
	// iid is the per-project fallback when a payload omits it.
	id := d.ID
	if id == 0 {
		id = d.IID
	}
	dep := Deployment{
		Repository: path,
		ID:         strconv.FormatInt(id, 10),
		SHA:        d.SHA,
		CreatedAt:  createdAt,
		Status:     d.Status,
	}
	if d.User != nil {
		dep.Creator = d.User.Username
	}
	if d.Environment != nil {
		dep.Environment = d.Environment.Name
		dep.EnvironmentTier = d.Environment.Tier
	}
	return dep, true
}

// isNotFound reports whether a GitLab response carries a 404 status. The
// client returns a non-nil *Response even on HTTP error, so the status is
// readable alongside the error.
func isNotFound(resp *gitlab.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusNotFound
}

var _ core.SourcePlugin = (*Plugin)(nil)
