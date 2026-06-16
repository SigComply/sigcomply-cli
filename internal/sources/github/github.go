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
const (
	EvidenceTypeRepository    = "git_repository"
	EvidenceTypeDirectoryUser = "directory_user"
	EvidenceTypeOrgPolicy     = "source_control_org_policy"
	EvidenceTypeVulnerability = "vulnerability_finding"
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
	return []string{EvidenceTypeRepository, EvidenceTypeDirectoryUser, EvidenceTypeOrgPolicy, EvidenceTypeVulnerability}
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
// GitHub org members. id and display_name both carry the member's
// login (GitHub's primary identifier); mfa_enabled is the 2FA flag;
// is_admin reflects the org role. Email and last_login_at are
// omitted — neither is exposed by the public org-members endpoint.
type memberPayload struct {
	ID          string `json:"id"`
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

// Collect returns records for every evidence type in req.AcceptedTypes
// that this plugin emits. A slot whose Accepts list includes both
// github types gets records for both in a single call. Records are
// sorted by ID within each type group; the collector splits them by
// Type for envelope writing.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantRepos := req.Accepts(EvidenceTypeRepository)
	wantMembers := req.Accepts(EvidenceTypeDirectoryUser)
	wantOrgPolicy := req.Accepts(EvidenceTypeOrgPolicy)
	wantVulns := req.Accepts(EvidenceTypeVulnerability)
	if !wantRepos && !wantMembers && !wantOrgPolicy && !wantVulns {
		return nil, fmt.Errorf("github: AcceptedTypes %v does not include emitted types %q,%q,%q,%q",
			req.AcceptedTypes, EvidenceTypeRepository, EvidenceTypeDirectoryUser, EvidenceTypeOrgPolicy, EvidenceTypeVulnerability)
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
	if wantOrgPolicy {
		rs, err := p.collectOrgPolicy(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if wantVulns {
		rs, err := p.collectVulnerabilities(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
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
func (h *httpAPI) ListDependabotAlerts(ctx context.Context) ([]DependabotAlert, error) {
	var out []DependabotAlert
	page := 1
	for {
		q := url.Values{}
		q.Set("state", "open")
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		path := fmt.Sprintf("/orgs/%s/dependabot/alerts?%s", url.PathEscape(h.org), q.Encode())
		var alerts []ghDependabotAlert
		hasMore, status, err := h.getJSONStatus(ctx, path, &alerts)
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
		if !hasMore {
			return out, nil
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
	hasMore, _, err := h.getJSONStatus(ctx, path, out)
	return hasMore, err
}

// getJSONStatus is getJSON that also reports the HTTP status code, so a
// caller can distinguish a specific status (e.g. 403 = feature disabled)
// from a generic transport error. The status is 0 when the request never
// reached a response (transport error, context cancel).
func (h *httpAPI) getJSONStatus(ctx context.Context, path string, out any) (hasMore bool, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+path, http.NoBody)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := h.client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode == http.StatusNotFound {
		return false, resp.StatusCode, fmt.Errorf("github: %s: %s", path, resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return false, resp.StatusCode, fmt.Errorf("github: %s: %s: %w", path, resp.Status, readErr)
		}
		return false, resp.StatusCode, fmt.Errorf("github: %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return false, resp.StatusCode, fmt.Errorf("github: decode %s: %w", path, err)
	}
	return hasNextLink(resp.Header.Get("Link")), resp.StatusCode, nil
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
