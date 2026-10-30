// Package github implements the github source plugin: it reads a single
// GitHub organization and emits six cloud-neutral evidence types —
// git_repository, directory_user, source_control_org_policy,
// vulnerability_finding, pull_request and deployment — suitable for
// SOC 2 branch-protection, 2FA-coverage and change-management policies.
//
// The first four are point-in-time configuration snapshots. The last two
// are PERIOD-SCOPED: they report what happened between the audit
// window's period_start and period_end (injected as native time.Time
// slot params by the orchestrator), not what is configured now.
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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// Evidence type IDs this plugin emits.
//
// EvidenceTypeRepository is the cross-vendor git_repository shape;
// GitHub is one of several substitutable source-code platforms
// (GitLab, Bitbucket, future Gitea/Azure DevOps).
// EvidenceTypeDirectoryUser is the cross-vendor directory_user
// shape — GitHub org members are one of several substitutable
// directory sources (AWS IAM, Okta, future Azure AD/LDAP).
// EvidenceTypeOrgPolicy is the cross-vendor source_control_org_policy
// shape — a single org/group-level governance record (GitHub org,
// GitLab group, Bitbucket workspace).
// EvidenceTypeVulnerability is the cross-vendor vulnerability_finding
// shape — one record per open Dependabot alert; GitHub is one of
// several substitutable finding sources (AWS Inspector, GCP SCC).
// EvidenceTypePullRequest is the cross-vendor pull_request shape — one
// record per change MERGED during the audit period (GitHub PR, GitLab
// MR, Bitbucket PR). It answers "did this change actually get
// reviewed?", which the git_repository configuration snapshot cannot.
// EvidenceTypeDeployment is the cross-vendor deployment shape — one
// record per release to a running environment during the period.
const (
	EvidenceTypeRepository    = "git_repository"
	EvidenceTypeDirectoryUser = "directory_user"
	EvidenceTypeOrgPolicy     = "source_control_org_policy"
	EvidenceTypeVulnerability = "vulnerability_finding"
	EvidenceTypePullRequest   = "pull_request"
	EvidenceTypeDeployment    = "deployment"
)

// SourceID is the registered ID for the github plugin instance.
const SourceID = "github"

// Repo is the subset of fields the plugin extracts from a repository
// listing. The plugin returns one record per Repo, augmented with
// branch-protection state and code-security settings queried via
// follow-up calls. Every field maps to a property of the git_repository
// evidence type so policies never read an absent field.
type Repo struct {
	Name            string
	DefaultBranch   string
	ProtectionOn    bool
	RequiredReviews int

	// Branch-protection rule details (default branch).
	RequiresSignedCommits   bool
	RequiresLinearHistory   bool
	AllowsForcePush         bool
	DismissStaleReviews     bool
	RequireCodeOwnerReviews bool

	// Repository attributes.
	IsPrivate bool
	Archived  bool

	// Code-security and analysis features.
	SecretScanningEnabled   bool
	PushProtectionEnabled   bool
	DependabotAlertsEnabled bool
	CodeScanningEnabled     bool
}

// Member is the subset of fields the plugin extracts from an org
// member listing.
type Member struct {
	Login       string
	TwoFactorOn bool
	Role        string
}

// OrgPolicy is the org/group-level governance state the plugin extracts
// from a single organization. Exactly one OrgPolicy maps to one
// source_control_org_policy record. Every field maps to a property of
// that evidence type so policies never read an absent field.
type OrgPolicy struct {
	// TwoFactorRequired is the org-wide MFA enforcement flag. GitHub
	// reports this as a tri-state (true/false/null when the caller lacks
	// admin scope); the adapter normalizes null to false.
	TwoFactorRequired bool
	// DefaultRepoPermission is the baseline member permission: one of
	// none/read/write/admin (GitHub's default_repository_permission).
	DefaultRepoPermission string

	MembersCanCreatePublicRepos bool
	WebCommitSignoffRequired    bool
	AdvancedSecurityNewRepos    bool
	SecretScanningNewRepos      bool
	DependabotAlertsNewRepos    bool
}

// DependabotAlert is the subset of an org Dependabot alert the plugin
// maps to one vulnerability_finding record. Severity and State carry
// GitHub's raw vocabulary (low/medium/high/critical, open/dismissed/
// fixed); the plugin normalizes them to the evidence type's enums.
type DependabotAlert struct {
	Number       int
	RepoFullName string
	PackageName  string
	Summary      string
	Severity     string
	State        string
	CVEID        string
	CVSSScore    float64
	// PatchAvailable is true when GitHub reports a first patched version.
	PatchAvailable bool
}

// Review is one review a user submitted on a pull request. State carries
// GitHub's raw vocabulary (APPROVED / CHANGES_REQUESTED / COMMENTED /
// DISMISSED / PENDING); the plugin reduces the per-user review history to
// the approval counts the pull_request evidence type declares.
// SubmittedAt is the zero value when the vendor reports no timestamp.
type Review struct {
	User        string
	State       string
	SubmittedAt time.Time
}

// CheckRun is one automated check associated with a pull request's head
// commit. Status is GitHub's lifecycle state (queued / in_progress /
// completed) and Conclusion its outcome (success / failure / neutral /
// canceled / skipped / timed_out / action_required).
type CheckRun struct {
	Status     string
	Conclusion string
}

// PullRequest is one change MERGED into a repository during the audit
// period. The adapter supplies the raw vendor facts (including the full
// review history and the head commit's check runs); the plugin derives
// approval_count / independent_approval_count / approved_before_merge /
// checks_passed from them, so the normalization is unit-testable without
// a network.
type PullRequest struct {
	// Repository is the `org/repo` form, matching git_repository.name.
	Repository     string
	Number         int
	Author         string
	MergedBy       string
	TargetBranch   string
	MergeCommitSHA string
	MergedAt       time.Time
	Reviews        []Review
	CheckRuns      []CheckRun
	// CommitStatusState and CommitStatusCount are the head commit's
	// combined commit status (Status API, used by CI systems that do not
	// report check runs): GitHub's aggregate state (success / pending /
	// failure) and the number of statuses behind it. A count of 0 means
	// no CI reported through the Status API.
	CommitStatusState string
	CommitStatusCount int
}

// Deployment is one release of code to a running environment during the
// audit period, including failed ones. State carries the raw latest
// GitHub deployment-status state (success / error / failure / pending /
// queued / in_progress / inactive) and is empty when the deployment has
// no status entries at all; the plugin normalizes it to the evidence
// type's closed vocabulary.
type Deployment struct {
	Repository string
	// ID is the vendor-native deployment identifier as a string.
	ID          string
	SHA         string
	Environment string
	// ProductionEnvironment is GitHub's production_environment flag. The
	// field is frequently absent from the API response; the adapter
	// treats absent as false and the plugin falls back to the
	// environment name when deriving is_production.
	ProductionEnvironment bool
	Creator               string
	CreatedAt             time.Time
	State                 string
}

// API is the subset of the GitHub REST API the plugin uses. Defining
// it as an interface lets tests inject a fake without making real
// network calls; the concrete *httpAPI satisfies it.
type API interface {
	// ListRepos returns all repos in the configured organization.
	// Implementations must page transparently — callers receive the
	// full list in one slice. Archived repos are returned with only
	// their listing fields; the plugin drops them (see collectRepos).
	ListRepos(ctx context.Context) ([]Repo, error)
	// ListOrgMembers returns all members of the configured org along
	// with their 2FA state and role. 2FA state requires admin scope.
	ListOrgMembers(ctx context.Context) ([]Member, error)
	// ListOutsideCollaborators returns users with access to org repos
	// who are not org members (external identities). 2FA state requires
	// admin scope; these users carry no org role.
	ListOutsideCollaborators(ctx context.Context) ([]Member, error)
	// GetOrgPolicy returns the configured org's governance settings.
	// The org-settings fields (2FA requirement, default permission)
	// require an org-admin-scoped token.
	GetOrgPolicy(ctx context.Context) (OrgPolicy, error)
	// ListDependabotAlerts returns the org's open Dependabot alerts.
	// Requires a token with Dependabot alerts read access. When GitHub
	// answers that alerts are disabled the implementation returns an
	// empty slice, so the per-repo gap is reported by the
	// dependabot_alerts_enabled policy; any other error (a token without
	// access included) is returned.
	ListDependabotAlerts(ctx context.Context) ([]DependabotAlert, error)
	// ListMergedPullRequests returns the org's pull requests merged into
	// each repository's default branch with a merge timestamp inside
	// [start, end]. GitHub's pulls listing has no date filter, so
	// implementations paginate newest-updated-first and stop once a page
	// predates start. Any error reading a repository's pulls, reviews,
	// checks or statuses is returned: evidence silently missing for one
	// repo would let the change-management policies pass on the rest.
	ListMergedPullRequests(ctx context.Context, start, end time.Time) ([]PullRequest, error)
	// ListDeployments returns the org's deployments created inside
	// [start, end], including failed ones. Same pagination and error
	// handling as ListMergedPullRequests.
	ListDeployments(ctx context.Context, start, end time.Time) ([]Deployment, error)
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

// defaultBaseURL is the github.com REST endpoint; GitHub Enterprise
// Server instances pass their own (typically https://ghe.example.com/api/v3).
const defaultBaseURL = "https://api.github.com"

// NewFromToken constructs a Plugin backed by the real GitHub REST API
// using the supplied personal-access or app token. A blank baseURL
// defaults to github.com; GitHub Enterprise Server instances pass their
// own URL. Live integration tests are deferred.
func NewFromToken(_ context.Context, org, token, baseURL string) (*Plugin, error) {
	if org == "" {
		return nil, fmt.Errorf("github: org is required")
	}
	if token == "" {
		return nil, fmt.Errorf("github: token is required")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return New(Options{
		API: &httpAPI{
			org:    org,
			token:  token,
			base:   strings.TrimSuffix(baseURL, "/"),
			client: &http.Client{Timeout: 30 * time.Second},
		},
		Org: org,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string {
	return []string{
		EvidenceTypeRepository, EvidenceTypeDirectoryUser, EvidenceTypeOrgPolicy,
		EvidenceTypeVulnerability, EvidenceTypePullRequest, EvidenceTypeDeployment,
	}
}

// Caveats declares the one field this plugin can emit without observing it.
//
// Conditional, not absolute: GitHub really does publish the org-wide 2FA
// requirement, but GET /orgs/{org} returns two_factor_requirement_enabled as a
// tri-state — true, false, or null when the caller lacks the admin:org scope.
// GetOrgPolicy flattens null to false (the field is a bool on the wire type and
// a policy reading an absent field is an error, so some value must be chosen),
// and it does so silently: no error is returned and nothing is logged, because
// the rest of the org record is still perfectly usable. What that leaves is a
// false that an org-wide-MFA policy grades as a real "2FA is not enforced",
// with nothing in the run to distinguish it from "we were not allowed to look".
// The caveat is what says it.
//
// Declared unconditionally because token scope is not known at plan time: the
// org read happens during collection, long after the planner has to decide
// whether to warn. Over-warning a correctly-scoped token is the cheaper error.
//
// Deliberately NOT declared for directory_user.mfa_enabled, which needs the
// same scope: there the 2fa_disabled listing's failure is RETURNED from
// ListOrgMembers, so an unscoped token errors the policy instead of quietly
// grading it on a fabricated value. A caveat warns about a silent gap; that one
// is not silent, and warning about it would dilute the ones that are.
func (*Plugin) Caveats() []core.SourceCaveat {
	return []core.SourceCaveat{{
		EvidenceType: EvidenceTypeOrgPolicy,
		Field:        "two_factor_required",
		Detail: "GitHub reports the org-wide 2FA requirement only to a token holding the admin:org " +
			"scope; without it the flag comes back null and is normalized to false, so grant the " +
			"token admin:org before treating this as a real enforcement gap",
	}}
}

// Init is a no-op; the constructor has already received configuration.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// repoPayload is the git_repository shape this plugin emits. Every
// boolean/integer property the git_repository schema declares is emitted
// (never omitempty on the policy-read fields): an absent field would now
// error the consuming policy rather than being read as false, so the
// plugin owns the full cross-vendor contract.
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

// memberPayload is the directory_user shape this plugin emits for
// GitHub org members. id, username and display_name all carry the
// member's login (GitHub's primary identifier; username is what roster
// aliases match on); mfa_enabled is the 2FA flag;
// is_admin reflects the org role. Email and last_login_at are
// omitted — neither is exposed by the public org-members endpoint.
type memberPayload struct {
	ID          string `json:"id"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name"`
	MFAEnabled  bool   `json:"mfa_enabled"`
	IsAdmin     bool   `json:"is_admin"`
	IsActive    bool   `json:"is_active"`
	// IsExternal distinguishes outside collaborators (true) from org
	// members (false). Emitted unconditionally so a policy can filter on
	// it with an is_set guard and find it present on every GitHub record.
	IsExternal bool `json:"is_external"`
}

// orgPolicyPayload is the source_control_org_policy shape this plugin
// emits — one record per organization. The two required schema fields
// (two_factor_required, default_member_repository_permission) plus
// provider are always emitted without omitempty so a consuming policy
// never reads an absent field; the secure-default booleans are emitted
// too so policies can read them without null guards.
type orgPolicyPayload struct {
	ID                                string `json:"id"`
	Provider                          string `json:"provider"`
	TwoFactorRequired                 bool   `json:"two_factor_required"`
	DefaultMemberRepositoryPermission string `json:"default_member_repository_permission"`
	MembersCanCreatePublicRepos       bool   `json:"members_can_create_public_repos"`
	WebCommitSignoffRequired          bool   `json:"web_commit_signoff_required"`
	AdvancedSecurityEnabledNewRepos   bool   `json:"advanced_security_enabled_new_repos"`
	SecretScanningEnabledNewRepos     bool   `json:"secret_scanning_enabled_new_repos"`
	DependabotAlertsEnabledNewRepos   bool   `json:"dependabot_alerts_enabled_new_repos"`
}

// vulnFindingPayload is the vulnerability_finding shape this plugin emits
// for Dependabot alerts. The five required schema fields are always
// present; cve_id/score/title are omitted when GitHub does not supply
// them. remediation_available is emitted unconditionally (a policy-read
// boolean) so a consuming policy never reads an absent field.
type vulnFindingPayload struct {
	ID                   string  `json:"id"`
	ResourceID           string  `json:"resource_id"`
	ResourceType         string  `json:"resource_type"`
	Title                string  `json:"title,omitempty"`
	Severity             string  `json:"severity"`
	Status               string  `json:"status"`
	CVEID                string  `json:"cve_id,omitempty"`
	Score                float64 `json:"score,omitempty"`
	RemediationAvailable bool    `json:"remediation_available"`
}

// pullRequestPayload is the pull_request shape this plugin emits — one
// record per merged change. Every property the schema declares is
// emitted unconditionally (no omitempty): the four derived fields are
// policy-read, and an absent field errors the consuming policy rather
// than reading as false/zero. merged_at is RFC3339 UTC.
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

// Collect returns records for every evidence type in req.AcceptedTypes
// that this plugin emits. A slot whose Accepts list names several github
// types gets records for all of them in a single call. Records are
// sorted by ID within each type group; the collector splits them by
// Type for envelope writing.
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
		{EvidenceTypeOrgPolicy, p.collectOrgPolicy},
		{EvidenceTypeVulnerability, p.collectVulnerabilities},
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
		return nil, fmt.Errorf("github: AcceptedTypes %v does not include emitted types %q,%q,%q,%q,%q,%q",
			req.AcceptedTypes, EvidenceTypeRepository, EvidenceTypeDirectoryUser, EvidenceTypeOrgPolicy,
			EvidenceTypeVulnerability, EvidenceTypePullRequest, EvidenceTypeDeployment)
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
// KISS-no-DRY axiom: plugins do not share vendor-neutral helpers.
// The one shared thing is internal/sources/errors.go, because the
// collector needs a single retry classification for every plugin —
// see the note at the top of that file.)
func timeParam(m map[string]any, key string) time.Time {
	if v, ok := m[key].(time.Time); ok {
		return v
	}
	return time.Time{}
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
		// An archived repository is read-only: its protection and
		// security settings cannot change without unarchiving it, and no
		// change can merge into it, so it is out of scope for the
		// repository policies (docs/reference/sources.md, GitHub caveats).
		if r.Archived {
			continue
		}
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
	collaborators, err := p.api.ListOutsideCollaborators(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: list outside collaborators: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(members)+len(collaborators))
	// Org members: is_admin reflects the org role; is_external false.
	for i := range members {
		m := members[i]
		records = append(records, p.directoryUserRecord(m, strings.EqualFold(m.Role, "admin"), false, now))
	}
	// Outside collaborators: external identities with repo access, never
	// org admins, flagged is_external so policies can isolate them.
	for i := range collaborators {
		records = append(records, p.directoryUserRecord(collaborators[i], false, true, now))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// directoryUserRecord builds one directory_user record from a GitHub
// member or outside collaborator. The marshal of a fixed-shape struct
// cannot fail, so any error is treated as programmer error and the empty
// payload is used (validation would catch it downstream); in practice
// json.Marshal of memberPayload never errors.
func (p *Plugin) directoryUserRecord(m Member, isAdmin, isExternal bool, now time.Time) core.EvidenceRecord {
	payload := memberPayload{
		ID:          m.Login,
		Username:    m.Login,
		DisplayName: m.Login,
		MFAEnabled:  m.TwoFactorOn,
		IsAdmin:     isAdmin,
		IsActive:    true, // only active identities appear in these listings
		IsExternal:  isExternal,
	}
	body, _ := json.Marshal(payload) //nolint:errcheck // fixed-shape struct never fails to marshal
	return core.EvidenceRecord{
		Type:        EvidenceTypeDirectoryUser,
		ID:          m.Login,
		IdentityKey: m.Login,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
	}
}

// collectOrgPolicy returns the single source_control_org_policy record
// for the configured org. The record ID is the org login.
func (p *Plugin) collectOrgPolicy(ctx context.Context) ([]core.EvidenceRecord, error) {
	op, err := p.api.GetOrgPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: get org policy: %w", err)
	}
	payload := orgPolicyPayload{
		ID:                                p.org,
		Provider:                          "github",
		TwoFactorRequired:                 op.TwoFactorRequired,
		DefaultMemberRepositoryPermission: op.DefaultRepoPermission,
		MembersCanCreatePublicRepos:       op.MembersCanCreatePublicRepos,
		WebCommitSignoffRequired:          op.WebCommitSignoffRequired,
		AdvancedSecurityEnabledNewRepos:   op.AdvancedSecurityNewRepos,
		SecretScanningEnabledNewRepos:     op.SecretScanningNewRepos,
		DependabotAlertsEnabledNewRepos:   op.DependabotAlertsNewRepos,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("github: marshal org policy payload: %w", err)
	}
	return []core.EvidenceRecord{{
		Type:        EvidenceTypeOrgPolicy,
		ID:          p.org,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: p.now(),
	}}, nil
}

// collectVulnerabilities returns one vulnerability_finding record per
// open org Dependabot alert. Record IDs are "{repo}/{alert-number}".
func (p *Plugin) collectVulnerabilities(ctx context.Context) ([]core.EvidenceRecord, error) {
	alerts, err := p.api.ListDependabotAlerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: list dependabot alerts: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(alerts))
	for i := range alerts {
		a := alerts[i]
		id := fmt.Sprintf("%s/%d", a.RepoFullName, a.Number)
		payload := vulnFindingPayload{
			ID:                   id,
			ResourceID:           a.RepoFullName,
			ResourceType:         "repository",
			Title:                vulnTitle(&a),
			Severity:             normalizeSeverity(a.Severity),
			Status:               normalizeAlertState(a.State),
			CVEID:                a.CVEID,
			Score:                a.CVSSScore,
			RemediationAvailable: a.PatchAvailable,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("github: marshal vulnerability payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeVulnerability,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// vulnTitle builds a human-readable finding title from the package name
// and advisory summary, preferring the summary when present.
func vulnTitle(a *DependabotAlert) string {
	switch {
	case a.Summary != "" && a.PackageName != "":
		return fmt.Sprintf("%s: %s", a.PackageName, a.Summary)
	case a.Summary != "":
		return a.Summary
	default:
		return a.PackageName
	}
}

// normalizeSeverity maps GitHub's lowercase Dependabot severity to the
// vulnerability_finding enum. Unknown values map to INFORMATIONAL so an
// unexpected vocabulary change never produces a schema-invalid record.
func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

// normalizeAlertState maps a Dependabot alert state to the
// vulnerability_finding status enum. Unknown states map to ACTIVE
// (fail-safe: an unrecognized alert is surfaced rather than hidden).
func normalizeAlertState(state string) string {
	switch strings.ToLower(state) {
	case "fixed":
		return "RESOLVED"
	case "dismissed", "auto_dismissed":
		return "SUPPRESSED"
	default:
		return "ACTIVE"
	}
}

// collectPullRequests returns one pull_request record per change merged
// inside [start, end]. Record IDs are "{org}/{repo}#{number}" — the form
// a customer writes in a YAML waiver's resource_id, so it must stay
// stable and human-writable. The window is re-applied here (the adapter
// already filters) so the plugin owns the period semantics regardless of
// which API implementation is wired in.
func (p *Plugin) collectPullRequests(ctx context.Context, start, end time.Time) ([]core.EvidenceRecord, error) {
	prs, err := p.api.ListMergedPullRequests(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("github: list merged pull requests: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(prs))
	for i := range prs {
		pr := prs[i]
		if pr.MergedAt.IsZero() || pr.MergedAt.Before(start) || pr.MergedAt.After(end) {
			continue
		}
		id := fmt.Sprintf("%s#%d", pr.Repository, pr.Number)
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
			ChecksPassed:             checksPassed(pr.CheckRuns, pr.CommitStatusState, pr.CommitStatusCount),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("github: marshal pull request payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypePullRequest,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// approvalState reduces a pull request's review history to the three
// approval fields the pull_request evidence type declares.
//
// Counting rule: a user's LATEST non-COMMENTED review decides their
// verdict — a reviewer who approves twice counts once, and an approval
// later DISMISSED or superseded by CHANGES_REQUESTED does not count.
// approvalCount includes the author; independentCount excludes them.
// approvedBeforeMerge is true when at least one counted INDEPENDENT
// approval was submitted at or before the merge, so a retroactive
// approval added after the merge does not rescue the change.
func approvalState(pr *PullRequest) (approvalCount, independentCount int, approvedBeforeMerge bool) {
	latest := map[string]Review{}
	order := make([]string, 0, len(pr.Reviews))
	for _, rv := range pr.Reviews {
		if rv.User == "" || strings.EqualFold(rv.State, "COMMENTED") {
			continue
		}
		prev, seen := latest[rv.User]
		if !seen {
			order = append(order, rv.User)
		}
		// Ties and zero timestamps resolve to the later list position;
		// GitHub returns reviews in submission order.
		if !seen || !rv.SubmittedAt.Before(prev.SubmittedAt) {
			latest[rv.User] = rv
		}
	}
	for _, user := range order {
		rv := latest[user]
		if !strings.EqualFold(rv.State, "APPROVED") {
			continue
		}
		approvalCount++
		if user == pr.Author {
			continue
		}
		independentCount++
		if !pr.MergedAt.IsZero() && rv.SubmittedAt.After(pr.MergedAt) {
			continue
		}
		approvedBeforeMerge = true
	}
	return approvalCount, independentCount, approvedBeforeMerge
}

// checksPassed reports whether every automated check on the merged
// commit succeeded, counting both check runs (Checks API) and commit
// statuses (Status API, which CI systems without the Checks integration
// use). A commit with NEITHER reports false: the schema states
// explicitly that "no CI configured" is not a pass, since a change
// merged with nothing verifying it is the condition CC8.1 asks about.
// neutral and skipped conclusions count as success (a check that
// deliberately did not apply is not a failure). Statuses pass only when
// GitHub's combined state is success.
func checksPassed(runs []CheckRun, statusState string, statusCount int) bool {
	if len(runs) == 0 && statusCount == 0 {
		return false
	}
	if statusCount > 0 && !strings.EqualFold(statusState, "success") {
		return false
	}
	for _, r := range runs {
		if !strings.EqualFold(r.Status, "completed") {
			return false
		}
		if !checkConclusionPasses[strings.ToLower(r.Conclusion)] {
			return false
		}
	}
	return true
}

// collectDeployments returns one deployment record per deployment
// created inside [start, end], failed ones included. Record IDs are
// "{org}/{repo}/deployments/{id}" — waiver-writable, like the
// pull_request form.
func (p *Plugin) collectDeployments(ctx context.Context, start, end time.Time) ([]core.EvidenceRecord, error) {
	deployments, err := p.api.ListDeployments(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("github: list deployments: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(deployments))
	for i := range deployments {
		d := deployments[i]
		if d.CreatedAt.IsZero() || d.CreatedAt.Before(start) || d.CreatedAt.After(end) {
			continue
		}
		id := fmt.Sprintf("%s/deployments/%s", d.Repository, d.ID)
		payload := deploymentPayload{
			Repository:   d.Repository,
			DeploymentID: d.ID,
			Environment:  d.Environment,
			IsProduction: isProductionEnvironment(d.ProductionEnvironment, d.Environment),
			DeployedBy:   d.Creator,
			DeployedAt:   d.CreatedAt.UTC().Format(time.RFC3339),
			CommitSHA:    d.SHA,
			Status:       normalizeDeploymentState(d.State),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("github: marshal deployment payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeDeployment,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// isProductionEnvironment normalizes GitHub's two production signals:
// the explicit production_environment flag (frequently absent from the
// response, hence false), or a conventional environment name. Keeping
// the customer's local naming out of policies is the point of
// is_production.
func isProductionEnvironment(flag bool, environment string) bool {
	if flag {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "production", "prod", "live":
		return true
	default:
		return false
	}
}

// The deployment evidence type's closed status vocabulary. Named
// because the enum is the contract policies read, distinct from the raw
// vendor states the switch below matches on.
const (
	deploymentStatusSuccess = "success"
	deploymentStatusFailure = "failure"
	deploymentStatusPending = "pending"
	deploymentStatusUnknown = "unknown"
)

// checkConclusionPasses lists the check-run conclusions that do not block a
// merge: an outright success plus the two outcomes GitHub itself treats as
// non-failing. Anything else — failure, timed_out, action_required, stale,
// canceled, or a run still in flight — means the change merged without its
// checks having passed.
var checkConclusionPasses = map[string]bool{
	deploymentStatusSuccess: true,
	"neutral":               true,
	"skipped":               true,
}

// normalizeDeploymentState maps the latest GitHub deployment-status
// state to the deployment status enum. An empty state means the
// deployment carries no status entries at all, which the schema
// distinguishes from pending: "unknown" must never be read as either
// success or failure. An unrecognized vocabulary also maps to unknown
// rather than guessing a terminal outcome.
func normalizeDeploymentState(state string) string {
	switch strings.ToLower(state) {
	case "success":
		return deploymentStatusSuccess
	case "error", "failure":
		return deploymentStatusFailure
	case "pending", "queued", "in_progress":
		return deploymentStatusPending
	default:
		return deploymentStatusUnknown
	}
}

// --- Real HTTP adapter -----------------------------------------------------

// httpAPI is the production implementation of API. It hits api.github.com
// directly via net/http to avoid pulling in github.com/google/go-github
// (which would add a sizable dependency tree). The endpoints used:
//
//	GET /orgs/{org}/repos                  — paged listing of repos
//	GET /repos/{org}/{repo}/branches/{br}/protection  — classic branch protection
//	GET /repos/{org}/{repo}/rules/branches/{br}       — active ruleset rules
//	GET /repos/{org}/{repo}/vulnerability-alerts      — Dependabot alerts on/off
//	GET /repos/{org}/{repo}/code-scanning/analyses    — code scanning in use
//	GET /orgs/{org}/members?filter=2fa_disabled       — 2FA-off members
//	GET /orgs/{org}/members                — full member roster + role
//	GET /repos/{org}/{repo}/pulls          — closed PRs on the default branch
//	GET /repos/{org}/{repo}/pulls/{n}      — merged_by (absent from the listing)
//	GET /repos/{org}/{repo}/pulls/{n}/reviews         — approval history
//	GET /repos/{org}/{repo}/commits/{sha}/check-runs  — CI outcome (Checks API)
//	GET /repos/{org}/{repo}/commits/{sha}/status      — CI outcome (Status API)
//	GET /repos/{org}/{repo}/deployments    — deployments, newest first
//	GET /repos/{org}/{repo}/deployments/{id}/statuses — latest state
//
// The adapter respects GitHub's `Link` header for pagination but is
// otherwise minimal; integration coverage is deferred.
type httpAPI struct {
	org    string
	token  string
	base   string
	client *http.Client
}

// ghFeatureStatus is the {"status":"enabled"|"disabled"} shape GitHub
// uses for security_and_analysis features.
type ghFeatureStatus struct {
	Status string `json:"status"`
}

func (f ghFeatureStatus) on() bool { return f.Status == "enabled" }

type ghRepo struct {
	Name                string `json:"name"`
	DefaultBranch       string `json:"default_branch"`
	Private             bool   `json:"private"`
	Archived            bool   `json:"archived"`
	SecurityAndAnalysis struct {
		SecretScanning               ghFeatureStatus `json:"secret_scanning"`
		SecretScanningPushProtection ghFeatureStatus `json:"secret_scanning_push_protection"`
	} `json:"security_and_analysis"`
}

// ghEnabled is the {"enabled":bool} shape used by several branch-protection
// sub-objects.
type ghEnabled struct {
	Enabled bool `json:"enabled"`
}

type ghProtection struct {
	RequiredPullRequestReviews struct {
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
	} `json:"required_pull_request_reviews"`
	RequiredSignatures    ghEnabled `json:"required_signatures"`
	AllowForcePushes      ghEnabled `json:"allow_force_pushes"`
	RequiredLinearHistory ghEnabled `json:"required_linear_history"`
}

// ghRule is one active rule from GET /repos/{o}/{r}/rules/branches/{b},
// the effective result of every repository and organization ruleset
// that targets the branch. Only the pull_request rule carries
// parameters the plugin reads.
type ghRule struct {
	Type       string `json:"type"`
	Parameters struct {
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		DismissStaleReviewsOnPush    bool `json:"dismiss_stale_reviews_on_push"`
		RequireCodeOwnerReview       bool `json:"require_code_owner_review"`
	} `json:"parameters"`
}

type ghCodeScanningAnalysis struct {
	ID int64 `json:"id"`
}

type ghMember struct {
	Login string `json:"login"`
}

type ghMembership struct {
	Role string `json:"role"`
}

// ghOrg is the subset of GET /orgs/{org} the plugin reads. The 2FA
// requirement is nullable: GitHub returns null when the caller lacks
// org-admin scope, so a *bool distinguishes "off" from "unknown".
type ghOrg struct {
	TwoFactorRequirementEnabled    *bool  `json:"two_factor_requirement_enabled"`
	DefaultRepositoryPermission    string `json:"default_repository_permission"`
	MembersCanCreatePublicRepos    bool   `json:"members_can_create_public_repositories"`
	WebCommitSignoffRequired       bool   `json:"web_commit_signoff_required"`
	AdvancedSecurityEnabledNewRepo bool   `json:"advanced_security_enabled_for_new_repositories"`
	SecretScanningEnabledNewRepo   bool   `json:"secret_scanning_enabled_for_new_repositories"`
	DependabotAlertsEnabledNewRepo bool   `json:"dependabot_alerts_enabled_for_new_repositories"`
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
			rp := Repo{
				Name:                  r.Name,
				DefaultBranch:         r.DefaultBranch,
				IsPrivate:             r.Private,
				Archived:              r.Archived,
				SecretScanningEnabled: r.SecurityAndAnalysis.SecretScanning.on(),
				PushProtectionEnabled: r.SecurityAndAnalysis.SecretScanningPushProtection.on(),
			}
			if r.Archived {
				// Dropped by the plugin; skip the per-repo calls.
				out = append(out, rp)
				continue
			}
			if err := h.fillRepoDetails(ctx, &rp); err != nil {
				return nil, fmt.Errorf("repository %s: %w", r.Name, err)
			}
			out = append(out, rp)
		}
		if !hasMore {
			return out, nil
		}
		page++
	}
}

// fillRepoDetails reads the per-repository settings the listing does
// not carry. Every read either answers or returns its error: a guessed
// value (an unreadable protection read as "unprotected, force-push not
// allowed") is a verdict the evidence does not support.
func (h *httpAPI) fillRepoDetails(ctx context.Context, rp *Repo) error {
	if rp.DefaultBranch != "" {
		if err := h.fetchProtection(ctx, rp); err != nil {
			return err
		}
	}
	// Dependabot vulnerability alerts: 204 = enabled, 404 = disabled.
	on, err := h.probeEnabled(ctx,
		fmt.Sprintf("/repos/%s/%s/vulnerability-alerts", url.PathEscape(h.org), url.PathEscape(rp.Name)))
	if err != nil {
		return fmt.Errorf("dependabot alerts: %w", adminHint(err))
	}
	rp.DependabotAlertsEnabled = on
	scanning, err := h.codeScanningInUse(ctx, rp.Name)
	if err != nil {
		return fmt.Errorf("code scanning: %w", err)
	}
	rp.CodeScanningEnabled = scanning
	return nil
}

// fetchProtection combines the two ways GitHub protects a branch: classic
// branch protection and rulesets. The classic endpoint does not see
// rulesets (it answers "Branch not protected" for a branch governed only
// by one), so both are read and merged.
func (h *httpAPI) fetchProtection(ctx context.Context, rp *Repo) error {
	classic, err := h.fetchClassicProtection(ctx, rp)
	if err != nil {
		return fmt.Errorf("branch protection: %w", err)
	}
	rules, err := h.fetchBranchRules(ctx, rp)
	if err != nil {
		return fmt.Errorf("branch rules: %w", err)
	}
	applyProtection(rp, classic, rules)
	return nil
}

// fetchClassicProtection returns the branch's classic protection, or nil
// when the branch has none. GitHub says "none" three ways: 404 "Branch
// not protected", 404 "Branch not found" (an empty repository), and 403
// "Upgrade to GitHub Pro or make this repository public" (a private repo
// on a plan without the feature). Every other error (a token without
// admin read, a rate limit, a 5xx) is returned.
func (h *httpAPI) fetchClassicProtection(ctx context.Context, rp *Repo) (*ghProtection, error) {
	path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection",
		url.PathEscape(h.org), url.PathEscape(rp.Name), url.PathEscape(rp.DefaultBranch))
	var p ghProtection
	if _, err := h.getJSON(ctx, path, &p); err != nil {
		if apiErrorIs(err, http.StatusNotFound, "Branch not protected", "Branch not found") ||
			apiErrorIs(err, http.StatusForbidden, "Upgrade to GitHub Pro") {
			return nil, nil
		}
		return nil, adminHint(err)
	}
	return &p, nil
}

// adminHint adds the fix to a 403 or 404 from an endpoint that needs
// admin on the repository (classic branch protection, the
// vulnerability-alerts probe). Without it the customer sees only "403
// Forbidden" for one repository in an org listing. A rate-limit 403 is
// returned as is.
func adminHint(err error) error {
	var apiErr *sources.APIError
	if !errors.As(err, &apiErr) || strings.Contains(strings.ToLower(apiErr.Message), "rate limit") {
		return err
	}
	if apiErr.StatusCode != http.StatusForbidden && apiErr.StatusCode != http.StatusNotFound {
		return err
	}
	return fmt.Errorf("%w (the token needs admin on this repository: a classic token whose user is a "+
		"repository admin, or a fine-grained token or GitHub App with Administration: read; "+
		"the Actions GITHUB_TOKEN cannot read this)", err)
}

// fetchBranchRules pages the active ruleset rules for the branch. The
// endpoint needs only read access. A plan that lacks rulesets for the
// repository and a branch that does not exist yet both mean no rules.
func (h *httpAPI) fetchBranchRules(ctx context.Context, rp *Repo) ([]ghRule, error) {
	var out []ghRule
	page := 1
	for {
		path := fmt.Sprintf("/repos/%s/%s/rules/branches/%s?per_page=100&page=%d",
			url.PathEscape(h.org), url.PathEscape(rp.Name), url.PathEscape(rp.DefaultBranch), page)
		var rules []ghRule
		hasMore, err := h.getJSON(ctx, path, &rules)
		if err != nil {
			if apiErrorIs(err, http.StatusNotFound, "Branch not found") ||
				apiErrorIs(err, http.StatusForbidden, "Upgrade to GitHub Pro") {
				return nil, nil
			}
			return nil, err
		}
		out = append(out, rules...)
		if !hasMore {
			return out, nil
		}
		page++
	}
}

// applyProtection merges classic protection (nil = none) and ruleset
// rules into the repo's protection fields. A requirement holds when
// either mechanism enforces it; the reviewer count is the stricter of
// the two. Force-push is allowed unless something blocks it: on a branch
// with no protection at all GitHub permits force-push, classic
// protection blocks it unless allow_force_pushes is on, and a
// non_fast_forward rule blocks it.
func applyProtection(rp *Repo, classic *ghProtection, rules []ghRule) {
	forcePushBlocked := false
	if classic != nil {
		rp.ProtectionOn = true
		rp.RequiredReviews = classic.RequiredPullRequestReviews.RequiredApprovingReviewCount
		rp.DismissStaleReviews = classic.RequiredPullRequestReviews.DismissStaleReviews
		rp.RequireCodeOwnerReviews = classic.RequiredPullRequestReviews.RequireCodeOwnerReviews
		rp.RequiresSignedCommits = classic.RequiredSignatures.Enabled
		rp.RequiresLinearHistory = classic.RequiredLinearHistory.Enabled
		forcePushBlocked = !classic.AllowForcePushes.Enabled
	}
	for i := range rules {
		r := &rules[i]
		rp.ProtectionOn = true
		switch r.Type {
		case "pull_request":
			rp.RequiredReviews = max(rp.RequiredReviews, r.Parameters.RequiredApprovingReviewCount)
			rp.DismissStaleReviews = rp.DismissStaleReviews || r.Parameters.DismissStaleReviewsOnPush
			rp.RequireCodeOwnerReviews = rp.RequireCodeOwnerReviews || r.Parameters.RequireCodeOwnerReview
		case "required_signatures":
			rp.RequiresSignedCommits = true
		case "required_linear_history":
			rp.RequiresLinearHistory = true
		case "non_fast_forward":
			forcePushBlocked = true
		}
	}
	rp.AllowsForcePush = !forcePushBlocked
}

// codeScanningInUse reports whether the repository has any code scanning
// analysis: CodeQL default or advanced setup and third-party SARIF
// uploads all produce one. 404 ("no analysis found") and a 403 saying
// code scanning or Advanced Security is not enabled mean no; any other
// error is returned.
func (h *httpAPI) codeScanningInUse(ctx context.Context, repo string) (bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/code-scanning/analyses?per_page=1",
		url.PathEscape(h.org), url.PathEscape(repo))
	var analyses []ghCodeScanningAnalysis
	if _, err := h.getJSON(ctx, path, &analyses); err != nil {
		if apiErrorIs(err, http.StatusNotFound) ||
			apiErrorIs(err, http.StatusForbidden, "must be enabled", "not enabled") {
			return false, nil
		}
		return false, err
	}
	return len(analyses) > 0, nil
}

// apiErrorIs reports whether err is a GitHub API error with the given
// status and, when phrases are given, a message containing one of them.
func apiErrorIs(err error, status int, phrases ...string) bool {
	var apiErr *sources.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
		return false
	}
	if len(phrases) == 0 {
		return true
	}
	for _, ph := range phrases {
		if strings.Contains(apiErr.Message, ph) {
			return true
		}
	}
	return false
}

// probeEnabled issues a GET for an endpoint that answers 204 (on) or 404
// (off) with no body, which getJSON cannot decode. Any other status is
// an error: a token without the permission is not a feature that is off.
func (h *httpAPI) probeEnabled(ctx context.Context, path string) (bool, error) {
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
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:errcheck // body is only context for the error
		return false, &sources.APIError{
			Source:     SourceID,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("%s: %s: %s", h.base+path, resp.Status, strings.TrimSpace(string(body))),
		}
	}
}

func (h *httpAPI) ListOrgMembers(ctx context.Context) ([]Member, error) {
	// 2FA-disabled members are reported by a filtered listing.
	disabled := map[string]bool{}
	if err := h.listLogins(ctx, "members", "2fa_disabled", disabled); err != nil {
		return nil, err
	}
	// Full roster.
	all := map[string]bool{}
	if err := h.listLogins(ctx, "members", "", all); err != nil {
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

// ListOutsideCollaborators lists external collaborators on the org's
// repos. The shape mirrors ListOrgMembers (login + 2FA via the
// 2fa_disabled filter) but outside collaborators carry no org role, so
// no membership lookup is performed.
func (h *httpAPI) ListOutsideCollaborators(ctx context.Context) ([]Member, error) {
	disabled := map[string]bool{}
	if err := h.listLogins(ctx, "outside_collaborators", "2fa_disabled", disabled); err != nil {
		return nil, err
	}
	all := map[string]bool{}
	if err := h.listLogins(ctx, "outside_collaborators", "", all); err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(all))
	for login := range all {
		out = append(out, Member{Login: login, TwoFactorOn: !disabled[login]})
	}
	return out, nil
}

// listLogins pages an org listing endpoint (members or
// outside_collaborators), collecting logins into `into`. An optional
// filter (e.g. "2fa_disabled") narrows the listing.
func (h *httpAPI) listLogins(ctx context.Context, endpoint, filter string, into map[string]bool) error {
	page := 1
	for {
		q := url.Values{}
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		if filter != "" {
			q.Set("filter", filter)
		}
		path := fmt.Sprintf("/orgs/%s/%s?%s", url.PathEscape(h.org), endpoint, q.Encode())
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

// GetOrgPolicy reads org-level governance settings from GET /orgs/{org}.
// The 2FA-requirement and default-permission fields require an
// org-admin-scoped token; a token without it sees a null 2FA flag
// (normalized to false) and the org's public default permission.
func (h *httpAPI) GetOrgPolicy(ctx context.Context) (OrgPolicy, error) {
	path := fmt.Sprintf("/orgs/%s", url.PathEscape(h.org))
	var o ghOrg
	if _, err := h.getJSON(ctx, path, &o); err != nil {
		return OrgPolicy{}, err
	}
	twoFA := o.TwoFactorRequirementEnabled != nil && *o.TwoFactorRequirementEnabled
	return OrgPolicy{
		TwoFactorRequired:           twoFA,
		DefaultRepoPermission:       o.DefaultRepositoryPermission,
		MembersCanCreatePublicRepos: o.MembersCanCreatePublicRepos,
		WebCommitSignoffRequired:    o.WebCommitSignoffRequired,
		AdvancedSecurityNewRepos:    o.AdvancedSecurityEnabledNewRepo,
		SecretScanningNewRepos:      o.SecretScanningEnabledNewRepo,
		DependabotAlertsNewRepos:    o.DependabotAlertsEnabledNewRepo,
	}, nil
}

// ghDependabotAlert is the subset of an org Dependabot alert the adapter
// reads. Severity and CVSS come from the advisory; the patched-version
// presence drives remediation_available.
type ghDependabotAlert struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	Dependency struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		CVEID    string `json:"cve_id"`
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		CVSS     struct {
			Score float64 `json:"score"`
		} `json:"cvss"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		FirstPatchedVersion *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// ListDependabotAlerts fetches the org's open Dependabot alerts. A 403
// saying alerts are disabled is "no alerts" — the per-repo enablement gap
// is reported by the dependabot_alerts_enabled policy. Any other 403 (a
// token without Dependabot alerts read, a rate limit) is returned, so the
// vulnerability policies error instead of passing on zero findings.
//
// The org-level Dependabot alerts endpoint uses CURSOR pagination only —
// it rejects the `page` parameter with 400 — so we follow the Link
// header's rel="next" URL rather than incrementing a page number.
func (h *httpAPI) ListDependabotAlerts(ctx context.Context) ([]DependabotAlert, error) {
	var out []DependabotAlert
	next := h.base + fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open&per_page=100", url.PathEscape(h.org))
	for next != "" {
		var alerts []ghDependabotAlert
		n, err := h.getJSONURL(ctx, next, &alerts)
		if apiErrorIs(err, http.StatusForbidden, "disabled") {
			return nil, nil // alerts disabled for the org: no findings
		}
		if err != nil {
			return nil, err
		}
		for _, a := range alerts {
			out = append(out, DependabotAlert{
				Number:         a.Number,
				RepoFullName:   a.Repository.FullName,
				PackageName:    a.Dependency.Package.Name,
				Summary:        a.SecurityAdvisory.Summary,
				Severity:       a.SecurityAdvisory.Severity,
				State:          a.State,
				CVEID:          a.SecurityAdvisory.CVEID,
				CVSSScore:      a.SecurityAdvisory.CVSS.Score,
				PatchAvailable: a.SecurityVulnerability.FirstPatchedVersion != nil,
			})
		}
		next = n
	}
	return out, nil
}

// --- Period-scoped endpoints (pull requests, deployments) ------------------

// repoRef is the minimum a period-scoped listing needs about a repo: its
// name and the default branch PRs must target.
type repoRef struct {
	name          string
	defaultBranch string
}

// ghPull is the subset of a pulls LIST item the adapter reads. MergedAt
// is nil for a PR closed without merging; UpdatedAt drives the
// pagination stop (the listing is sorted by updated desc and GitHub
// offers no date filter). The list item does NOT carry merged_by — that
// needs the per-PR detail call.
type ghPull struct {
	Number         int        `json:"number"`
	MergedAt       *time.Time `json:"merged_at"`
	UpdatedAt      *time.Time `json:"updated_at"`
	MergeCommitSHA string     `json:"merge_commit_sha"`
	User           *struct {
		Login string `json:"login"`
	} `json:"user"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

// ghPullDetail is the subset of GET /repos/{o}/{r}/pulls/{n} the adapter
// reads: merged_by is absent from the listing and nil when the vendor
// attributes the merge to no user.
type ghPullDetail struct {
	MergedBy *struct {
		Login string `json:"login"`
	} `json:"merged_by"`
}

type ghReview struct {
	State       string     `json:"state"`
	SubmittedAt *time.Time `json:"submitted_at"`
	User        *struct {
		Login string `json:"login"`
	} `json:"user"`
}

type ghCheckRunList struct {
	TotalCount int `json:"total_count"`
	CheckRuns  []struct {
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	} `json:"check_runs"`
}

// ghDeployment is the subset of a deployments LIST item the adapter
// reads. production_environment is frequently ABSENT from the response,
// so its zero value (false) is the correct "not flagged" reading;
// creator is nil for a deleted account or a token-driven deployment.
type ghDeployment struct {
	ID                    int64     `json:"id"`
	SHA                   string    `json:"sha"`
	Environment           string    `json:"environment"`
	ProductionEnvironment bool      `json:"production_environment"`
	CreatedAt             time.Time `json:"created_at"`
	Creator               *struct {
		Login string `json:"login"`
	} `json:"creator"`
}

type ghDeploymentStatus struct {
	State string `json:"state"`
}

// listRepoRefs pages the org's repo listing for just the names and
// default branches the period-scoped endpoints need. It deliberately
// skips the per-repo protection/Dependabot probes ListRepos performs.
func (h *httpAPI) listRepoRefs(ctx context.Context) ([]repoRef, error) {
	var out []repoRef
	page := 1
	for {
		path := fmt.Sprintf("/orgs/%s/repos?per_page=100&page=%d", url.PathEscape(h.org), page)
		var repos []ghRepo
		hasMore, err := h.getJSON(ctx, path, &repos)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			out = append(out, repoRef{name: r.Name, defaultBranch: r.DefaultBranch})
		}
		if !hasMore {
			return out, nil
		}
		page++
	}
}

// ListMergedPullRequests walks every repo in the org and collects the
// changes merged into its default branch inside the window. An error on
// any repo is returned: dropping the repo would let the change policies
// pass on the subset that could be read.
func (h *httpAPI) ListMergedPullRequests(ctx context.Context, start, end time.Time) ([]PullRequest, error) {
	repos, err := h.listRepoRefs(ctx)
	if err != nil {
		return nil, err
	}
	var out []PullRequest
	for _, r := range repos {
		if r.defaultBranch == "" {
			continue
		}
		prs, err := h.listRepoMergedPulls(ctx, r, start, end)
		if err != nil {
			return nil, fmt.Errorf("repository %s pull requests: %w", r.name, err)
		}
		out = append(out, prs...)
	}
	return out, nil
}

func (h *httpAPI) listRepoMergedPulls(ctx context.Context, r repoRef, start, end time.Time) ([]PullRequest, error) {
	full := h.org + "/" + r.name
	var out []PullRequest
	page := 1
	for {
		q := url.Values{}
		q.Set("state", "closed")
		q.Set("base", r.defaultBranch)
		q.Set("sort", "updated")
		q.Set("direction", "desc")
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		path := fmt.Sprintf("/repos/%s/%s/pulls?%s", url.PathEscape(h.org), url.PathEscape(r.name), q.Encode())
		var pulls []ghPull
		hasMore, err := h.getJSON(ctx, path, &pulls)
		if err != nil {
			return nil, err
		}
		exhausted := false
		for i := range pulls {
			p := pulls[i]
			// The listing is updated-desc and has no date filter: once an
			// item predates the window nothing further can qualify.
			if p.UpdatedAt != nil && p.UpdatedAt.Before(start) {
				exhausted = true
				break
			}
			if p.MergedAt == nil {
				continue // closed without merging: not a change
			}
			merged := p.MergedAt.UTC()
			if merged.Before(start) || merged.After(end) {
				continue
			}
			pr := PullRequest{
				Repository:     full,
				Number:         p.Number,
				TargetBranch:   p.Base.Ref,
				MergeCommitSHA: p.MergeCommitSHA,
				MergedAt:       merged,
			}
			if p.User != nil {
				pr.Author = p.User.Login
			}
			if err := h.fillPullDetails(ctx, r.name, p.Head.SHA, &pr); err != nil {
				return nil, fmt.Errorf("#%d: %w", p.Number, err)
			}
			out = append(out, pr)
		}
		if exhausted || !hasMore {
			return out, nil
		}
		page++
	}
}

// fillPullDetails reads what the pulls listing does not carry: the
// merging user, the review history, and the head commit's check runs
// and commit statuses.
func (h *httpAPI) fillPullDetails(ctx context.Context, repo, headSHA string, pr *PullRequest) error {
	var err error
	if pr.MergedBy, err = h.fetchPullMergedBy(ctx, repo, pr.Number); err != nil {
		return fmt.Errorf("merged_by: %w", err)
	}
	if pr.Reviews, err = h.fetchPullReviews(ctx, repo, pr.Number); err != nil {
		return fmt.Errorf("reviews: %w", err)
	}
	if headSHA == "" {
		return nil // nothing to read checks for: checksPassed reads false
	}
	if pr.CheckRuns, err = h.fetchCheckRuns(ctx, repo, headSHA); err != nil {
		return fmt.Errorf("check runs: %w", err)
	}
	if pr.CommitStatusState, pr.CommitStatusCount, err = h.fetchCombinedStatus(ctx, repo, headSHA); err != nil {
		return fmt.Errorf("commit status: %w", err)
	}
	return nil
}

// fetchPullMergedBy resolves the merging user via the per-PR detail
// endpoint (the listing omits it). A null merged_by yields "" — the
// schema's documented "vendor does not attribute the merge".
func (h *httpAPI) fetchPullMergedBy(ctx context.Context, repo string, number int) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", url.PathEscape(h.org), url.PathEscape(repo), number)
	var d ghPullDetail
	if _, err := h.getJSON(ctx, path, &d); err != nil {
		return "", err
	}
	if d.MergedBy == nil {
		return "", nil
	}
	return d.MergedBy.Login, nil
}

// fetchPullReviews pages a PR's review history.
func (h *httpAPI) fetchPullReviews(ctx context.Context, repo string, number int) ([]Review, error) {
	var out []Review
	page := 1
	for {
		path := fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews?per_page=100&page=%d",
			url.PathEscape(h.org), url.PathEscape(repo), number, page)
		var reviews []ghReview
		hasMore, err := h.getJSON(ctx, path, &reviews)
		if err != nil {
			return nil, err
		}
		for _, rv := range reviews {
			r := Review{State: rv.State}
			if rv.User != nil {
				r.User = rv.User.Login
			}
			if rv.SubmittedAt != nil {
				r.SubmittedAt = rv.SubmittedAt.UTC()
			}
			out = append(out, r)
		}
		if !hasMore {
			return out, nil
		}
		page++
	}
}

// fetchCheckRuns pages the check runs attached to the PR's head commit.
func (h *httpAPI) fetchCheckRuns(ctx context.Context, repo, headSHA string) ([]CheckRun, error) {
	var out []CheckRun
	page := 1
	for {
		path := fmt.Sprintf("/repos/%s/%s/commits/%s/check-runs?per_page=100&page=%d",
			url.PathEscape(h.org), url.PathEscape(repo), url.PathEscape(headSHA), page)
		var list ghCheckRunList
		hasMore, err := h.getJSON(ctx, path, &list)
		if err != nil {
			return nil, err
		}
		for _, cr := range list.CheckRuns {
			out = append(out, CheckRun{Status: cr.Status, Conclusion: cr.Conclusion})
		}
		if !hasMore {
			return out, nil
		}
		page++
	}
}

// ghCombinedStatus is the subset of GET /repos/{o}/{r}/commits/{ref}/status
// the adapter reads. state is "pending" when there are no statuses, so
// total_count is what says whether any CI reported.
type ghCombinedStatus struct {
	State      string `json:"state"`
	TotalCount int    `json:"total_count"`
}

// fetchCombinedStatus reads the head commit's combined commit status.
func (h *httpAPI) fetchCombinedStatus(ctx context.Context, repo, headSHA string) (state string, count int, err error) {
	path := fmt.Sprintf("/repos/%s/%s/commits/%s/status",
		url.PathEscape(h.org), url.PathEscape(repo), url.PathEscape(headSHA))
	var cs ghCombinedStatus
	if _, err := h.getJSON(ctx, path, &cs); err != nil {
		return "", 0, err
	}
	return cs.State, cs.TotalCount, nil
}

// ListDeployments walks every repo in the org and collects the
// deployments created inside the window, failed ones included. Same
// error handling as ListMergedPullRequests.
func (h *httpAPI) ListDeployments(ctx context.Context, start, end time.Time) ([]Deployment, error) {
	repos, err := h.listRepoRefs(ctx)
	if err != nil {
		return nil, err
	}
	var out []Deployment
	for _, r := range repos {
		ds, err := h.listRepoDeployments(ctx, r, start, end)
		if err != nil {
			return nil, fmt.Errorf("repository %s deployments: %w", r.name, err)
		}
		out = append(out, ds...)
	}
	return out, nil
}

func (h *httpAPI) listRepoDeployments(ctx context.Context, r repoRef, start, end time.Time) ([]Deployment, error) {
	full := h.org + "/" + r.name
	var out []Deployment
	page := 1
	for {
		path := fmt.Sprintf("/repos/%s/%s/deployments?per_page=100&page=%d",
			url.PathEscape(h.org), url.PathEscape(r.name), page)
		var deployments []ghDeployment
		hasMore, err := h.getJSON(ctx, path, &deployments)
		if err != nil {
			return nil, err
		}
		exhausted := false
		for _, d := range deployments {
			created := d.CreatedAt.UTC()
			// The listing is created-desc with no date filter.
			if created.Before(start) {
				exhausted = true
				break
			}
			if created.After(end) {
				continue
			}
			id := strconv.FormatInt(d.ID, 10)
			state, err := h.fetchLatestDeploymentState(ctx, r.name, id)
			if err != nil {
				return nil, fmt.Errorf("deployment %s status: %w", id, err)
			}
			dep := Deployment{
				Repository:            full,
				ID:                    id,
				SHA:                   d.SHA,
				Environment:           d.Environment,
				ProductionEnvironment: d.ProductionEnvironment,
				CreatedAt:             created,
				State:                 state,
			}
			if d.Creator != nil {
				dep.Creator = d.Creator.Login
			}
			out = append(out, dep)
		}
		if exhausted || !hasMore {
			return out, nil
		}
		page++
	}
}

// fetchLatestDeploymentState returns the newest deployment-status state,
// or "" when the deployment has none (normalized to "unknown", which the
// schema keeps distinct from pending). The statuses listing is
// newest-first. An error is returned: the plugin must not invent an
// outcome it could not read.
func (h *httpAPI) fetchLatestDeploymentState(ctx context.Context, repo, deploymentID string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/deployments/%s/statuses?per_page=100",
		url.PathEscape(h.org), url.PathEscape(repo), url.PathEscape(deploymentID))
	var statuses []ghDeploymentStatus
	if _, err := h.getJSON(ctx, path, &statuses); err != nil {
		return "", err
	}
	if len(statuses) == 0 {
		return "", nil
	}
	return statuses[0].State, nil
}

func (h *httpAPI) fetchMembershipRole(ctx context.Context, login string) (string, error) {
	path := fmt.Sprintf("/orgs/%s/memberships/%s", url.PathEscape(h.org), url.PathEscape(login))
	var m ghMembership
	if _, err := h.getJSON(ctx, path, &m); err != nil {
		return "", err
	}
	return m.Role, nil
}

// getJSON performs a single GET on a base-relative path and decodes the JSON
// body into out. It returns hasMore=true when the response carries a `Link`
// header with a rel="next" entry (page-based callers increment a page number).
func (h *httpAPI) getJSON(ctx context.Context, path string, out any) (bool, error) {
	next, err := h.getJSONURL(ctx, h.base+path, out)
	return next != "", err
}

// getJSONURL GETs an absolute URL, decodes the JSON body into out, and
// returns the rel="next" URL from the Link header (empty when there is none).
// A non-2xx response is a *sources.APIError carrying the status and the body,
// so a caller can recognize a specific answer (apiErrorIs). Cursor-paginated
// endpoints (e.g. org Dependabot alerts) follow the returned next URL directly.
func (h *httpAPI) getJSONURL(ctx context.Context, fullURL string, out any) (next string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", &sources.APIError{
				Source:     SourceID,
				StatusCode: resp.StatusCode,
				Message:    fmt.Sprintf("%s: %s: %v", fullURL, resp.Status, readErr),
				Err:        readErr,
			}
		}
		return "", &sources.APIError{
			Source:     SourceID,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("%s: %s: %s", fullURL, resp.Status, strings.TrimSpace(string(body))),
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", fmt.Errorf("github: decode %s: %w", fullURL, err)
	}
	return h.followableLink(nextLink(resp.Header.Get("Link")))
}

// followableLink checks a rel="next" URL before it is requested with the
// token: it must use the configured API base's scheme and host and lie
// under its path. A Link header pointing anywhere else (a misbehaving
// GHES proxy, a hostile mock) would otherwise receive the token.
// getJSONURL, the only place a Link header is read, returns next through
// here, so every caller that follows it is covered.
func (h *httpAPI) followableLink(next string) (string, error) {
	return sources.FollowableLink(SourceID, h.base, next)
}

// nextLink returns the rel="next" URL from a Link header, or "" when there is
// none. Format reference:
// https://docs.github.com/rest/guides/using-pagination-in-the-rest-api
func nextLink(link string) string {
	for _, part := range strings.Split(link, ",") {
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		if i := strings.IndexByte(part, '<'); i >= 0 {
			if j := strings.IndexByte(part[i+1:], '>'); j >= 0 {
				return part[i+1 : i+1+j]
			}
		}
	}
	return ""
}

var _ core.SourcePlugin = (*Plugin)(nil)
