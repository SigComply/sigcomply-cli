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
	// full list in one slice.
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
	// Requires a token with security-events read access; when Dependabot
	// alerts are disabled for the org (403) the implementation returns an
	// empty slice rather than an error, so the per-repo enablement gap is
	// reported by the dependabot_alerts_enabled policy instead of failing
	// the run.
	ListDependabotAlerts(ctx context.Context) ([]DependabotAlert, error)
	// ListMergedPullRequests returns the org's pull requests merged into
	// each repository's default branch with a merge timestamp inside
	// [start, end]. GitHub's pulls listing has no date filter, so
	// implementations paginate newest-updated-first and stop once a page
	// predates start. A repository the token cannot read is skipped, not
	// an error — one inaccessible repo must not fail the whole run.
	ListMergedPullRequests(ctx context.Context, start, end time.Time) ([]PullRequest, error)
	// ListDeployments returns the org's deployments created inside
	// [start, end], including failed ones. Same pagination and
	// per-repository error tolerance as ListMergedPullRequests.
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
	return []string{
		EvidenceTypeRepository, EvidenceTypeDirectoryUser, EvidenceTypeOrgPolicy,
		EvidenceTypeVulnerability, EvidenceTypePullRequest, EvidenceTypeDeployment,
	}
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
// KISS-no-DRY axiom — source plugins share no helper package.)
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
			ChecksPassed:             checksPassed(pr.CheckRuns),
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
// commit succeeded. A repository that runs NO checks reports false: the
// schema states explicitly that "no CI configured" is not a pass, since
// a change merged with nothing verifying it is the condition CC8.1 asks
// about. neutral and skipped conclusions count as success (a check that
// deliberately did not apply is not a failure).
func checksPassed(runs []CheckRun) bool {
	if len(runs) == 0 {
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
//	GET /repos/{org}/{repo}/branches/{br}/protection  — branch protection
//	GET /orgs/{org}/members?filter=2fa_disabled       — 2FA-off members
//	GET /orgs/{org}/members                — full member roster + role
//	GET /repos/{org}/{repo}/pulls          — closed PRs on the default branch
//	GET /repos/{org}/{repo}/pulls/{n}      — merged_by (absent from the listing)
//	GET /repos/{org}/{repo}/pulls/{n}/reviews         — approval history
//	GET /repos/{org}/{repo}/commits/{sha}/check-runs  — CI outcome
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
		CodeScanningDefaultSetup     ghFeatureStatus `json:"code_scanning_default_setup"`
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
				CodeScanningEnabled:   r.SecurityAndAnalysis.CodeScanningDefaultSetup.on(),
			}
			if r.DefaultBranch != "" {
				h.fetchProtection(ctx, &rp)
			}
			// Dependabot vulnerability alerts: 204 = enabled, 404 = disabled.
			rp.DependabotAlertsEnabled = h.probeEnabled(ctx,
				fmt.Sprintf("/repos/%s/%s/vulnerability-alerts", url.PathEscape(h.org), url.PathEscape(r.Name)))
			out = append(out, rp)
		}
		if !hasMore {
			return out, nil
		}
		page++
	}
}

func (h *httpAPI) fetchProtection(ctx context.Context, rp *Repo) {
	path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection",
		url.PathEscape(h.org), url.PathEscape(rp.Name), url.PathEscape(rp.DefaultBranch))
	var p ghProtection
	if _, err := h.getJSON(ctx, path, &p); err != nil {
		// 404 = no protection; any other error leaves all protection
		// fields at their false/zero zero-values. The aggregator decides.
		return
	}
	rp.ProtectionOn = true
	rp.RequiredReviews = p.RequiredPullRequestReviews.RequiredApprovingReviewCount
	rp.DismissStaleReviews = p.RequiredPullRequestReviews.DismissStaleReviews
	rp.RequireCodeOwnerReviews = p.RequiredPullRequestReviews.RequireCodeOwnerReviews
	rp.RequiresSignedCommits = p.RequiredSignatures.Enabled
	rp.RequiresLinearHistory = p.RequiredLinearHistory.Enabled
	rp.AllowsForcePush = p.AllowForcePushes.Enabled
}

// probeEnabled issues a GET and reports whether the response is 2xx.
// GitHub uses 204/404 to signal feature on/off for endpoints with no
// body (e.g. vulnerability-alerts), which getJSON cannot decode.
func (h *httpAPI) probeEnabled(ctx context.Context, path string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+path, http.NoBody)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := h.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	return resp.StatusCode >= 200 && resp.StatusCode < 300
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
// (alerts disabled for the org, or the token lacks security-events
// access) is treated as "no alerts" rather than an error — the per-repo
// enablement gap is reported by the dependabot_alerts_enabled policy.
//
// The org-level Dependabot alerts endpoint uses CURSOR pagination only —
// it rejects the `page` parameter with 400 — so we follow the Link
// header's rel="next" URL rather than incrementing a page number.
func (h *httpAPI) ListDependabotAlerts(ctx context.Context) ([]DependabotAlert, error) {
	var out []DependabotAlert
	next := h.base + fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open&per_page=100", url.PathEscape(h.org))
	for next != "" {
		var alerts []ghDependabotAlert
		n, status, err := h.getJSONStatus(ctx, next, &alerts)
		if status == http.StatusForbidden {
			return nil, nil // alerts disabled / no access: no findings
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
// changes merged into its default branch inside the window. A repo whose
// pulls listing errors is skipped (same tolerance idiom as
// fetchProtection) so one inaccessible repository does not fail the run.
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
			continue // inaccessible repo: skip, do not fail the org collection
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
				MergedBy:       h.fetchPullMergedBy(ctx, r.name, p.Number),
				Reviews:        h.fetchPullReviews(ctx, r.name, p.Number),
				CheckRuns:      h.fetchCheckRuns(ctx, r.name, p.Head.SHA),
			}
			if p.User != nil {
				pr.Author = p.User.Login
			}
			out = append(out, pr)
		}
		if exhausted || !hasMore {
			return out, nil
		}
		page++
	}
}

// fetchPullMergedBy resolves the merging user via the per-PR detail
// endpoint (the listing omits it). An error or a null merged_by yields
// "" — the schema's documented "vendor does not attribute the merge".
func (h *httpAPI) fetchPullMergedBy(ctx context.Context, repo string, number int) string {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", url.PathEscape(h.org), url.PathEscape(repo), number)
	var d ghPullDetail
	if _, err := h.getJSON(ctx, path, &d); err != nil || d.MergedBy == nil {
		return ""
	}
	return d.MergedBy.Login
}

// fetchPullReviews pages a PR's review history. An error yields no
// reviews, which reads as an unapproved change — failing closed is the
// correct bias for a review-evidence type.
func (h *httpAPI) fetchPullReviews(ctx context.Context, repo string, number int) []Review {
	var out []Review
	page := 1
	for {
		path := fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews?per_page=100&page=%d",
			url.PathEscape(h.org), url.PathEscape(repo), number, page)
		var reviews []ghReview
		hasMore, err := h.getJSON(ctx, path, &reviews)
		if err != nil {
			return out
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
			return out
		}
		page++
	}
}

// fetchCheckRuns pages the check runs attached to the PR's head commit.
// An error or an empty head SHA yields no runs, which checksPassed reads
// as false (deliberately: "no CI configured" is not a pass).
func (h *httpAPI) fetchCheckRuns(ctx context.Context, repo, headSHA string) []CheckRun {
	if headSHA == "" {
		return nil
	}
	var out []CheckRun
	page := 1
	for {
		path := fmt.Sprintf("/repos/%s/%s/commits/%s/check-runs?per_page=100&page=%d",
			url.PathEscape(h.org), url.PathEscape(repo), url.PathEscape(headSHA), page)
		var list ghCheckRunList
		hasMore, err := h.getJSON(ctx, path, &list)
		if err != nil {
			return out
		}
		for _, cr := range list.CheckRuns {
			out = append(out, CheckRun{Status: cr.Status, Conclusion: cr.Conclusion})
		}
		if !hasMore {
			return out
		}
		page++
	}
}

// ListDeployments walks every repo in the org and collects the
// deployments created inside the window, failed ones included. Same
// per-repo error tolerance as ListMergedPullRequests.
func (h *httpAPI) ListDeployments(ctx context.Context, start, end time.Time) ([]Deployment, error) {
	repos, err := h.listRepoRefs(ctx)
	if err != nil {
		return nil, err
	}
	var out []Deployment
	for _, r := range repos {
		ds, err := h.listRepoDeployments(ctx, r, start, end)
		if err != nil {
			continue // inaccessible repo: skip, do not fail the org collection
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
			dep := Deployment{
				Repository:            full,
				ID:                    id,
				SHA:                   d.SHA,
				Environment:           d.Environment,
				ProductionEnvironment: d.ProductionEnvironment,
				CreatedAt:             created,
				State:                 h.fetchLatestDeploymentState(ctx, r.name, id),
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
// newest-first. An error also yields "": the plugin must not invent a
// terminal outcome it could not read.
func (h *httpAPI) fetchLatestDeploymentState(ctx context.Context, repo, deploymentID string) string {
	path := fmt.Sprintf("/repos/%s/%s/deployments/%s/statuses?per_page=100",
		url.PathEscape(h.org), url.PathEscape(repo), url.PathEscape(deploymentID))
	var statuses []ghDeploymentStatus
	if _, err := h.getJSON(ctx, path, &statuses); err != nil || len(statuses) == 0 {
		return ""
	}
	return statuses[0].State
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
	next, _, err := h.getJSONStatus(ctx, h.base+path, out)
	return next != "", err
}

// getJSONStatus GETs an absolute URL, decodes the JSON body into out, and
// returns the rel="next" URL from the Link header (empty when there is none).
// It also reports the HTTP status code, so a caller can distinguish a specific
// status (e.g. 403 = feature disabled) from a generic transport error; status
// is 0 when the request never reached a response. Cursor-paginated endpoints
// (e.g. org Dependabot alerts) follow the returned next URL directly.
func (h *httpAPI) getJSONStatus(ctx context.Context, fullURL string, out any) (next string, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode == http.StatusNotFound {
		return "", resp.StatusCode, fmt.Errorf("github: %s: %s", fullURL, resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", resp.StatusCode, fmt.Errorf("github: %s: %s: %w", fullURL, resp.Status, readErr)
		}
		return "", resp.StatusCode, fmt.Errorf("github: %s: %s: %s", fullURL, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", resp.StatusCode, fmt.Errorf("github: decode %s: %w", fullURL, err)
	}
	return nextLink(resp.Header.Get("Link")), resp.StatusCode, nil
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
