package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// cc8Policies — CC8.1 change management: source-control protections and
// secure-SDLC repository hygiene.
func cc8Policies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc8.1.default_branch_protected", control: "CC8.1", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories protect their default branch.",
			rem:     "Enable branch protection on each repository's default branch.",
			clause:  all(leaf("payload.default_branch_protected", "eq", true), "repository {{.payload.name}} does not protect its default branch"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.required_code_reviews", control: "CC8.1", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories require at least one approving review.",
			rem:     "Require at least one reviewer on default-branch merges.",
			clause:  all(leaf("payload.required_reviewers_count", "gte", 1), "repository {{.payload.name}} does not require code review"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.no_force_push_to_main", control: "CC8.1", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "No repository allows force-push to the default branch.",
			rem:     "Disable force-push on each protected default branch.",
			clause:  none(leaf("payload.allows_force_push", "eq", true), "repository {{.payload.name}} allows force-push to its default branch"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.signed_commits_required", control: "CC8.1", severity: core.SeverityLow, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories require signed commits.",
			rem:     "Enable required commit signing on each repository.",
			clause:  all(leaf("payload.requires_signed_commits", "eq", true), "repository {{.payload.name}} does not require signed commits"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.dependabot_alerts_enabled", control: "CC8.1", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories have dependency vulnerability alerts enabled.",
			rem:     "Enable Dependabot (or equivalent) alerts on each repository.",
			clause:  all(leaf("payload.dependabot_alerts_enabled", "eq", true), "repository {{.payload.name}} does not have dependency alerts enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.code_scanning_enabled", control: "CC8.1", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories have code scanning (SAST) enabled.",
			rem:     "Enable code scanning on each repository.",
			clause:  all(leaf("payload.code_scanning_enabled", "eq", true), "repository {{.payload.name}} does not have code scanning enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.dismiss_stale_reviews", control: "CC8.1", severity: core.SeverityLow, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories dismiss stale approvals when new commits are pushed.",
			rem:     "Enable dismissal of stale reviews on each repository.",
			clause:  all(leaf("payload.dismiss_stale_reviews", "eq", true), "repository {{.payload.name}} does not dismiss stale reviews"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.require_code_owner_reviews", control: "CC8.1", severity: core.SeverityLow, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories require code-owner review for owned paths.",
			rem:     "Enable required code-owner review on each repository.",
			clause:  all(leaf("payload.require_code_owner_reviews", "eq", true), "repository {{.payload.name}} does not require code-owner review"),
		}.policy(),
	}
}

// cc6SecretHygienePolicies — CC6.5 secret scanning in repositories.
func cc6SecretHygienePolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.5.secret_scanning_enabled", control: "CC6.5", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories have secret scanning enabled.",
			rem:     "Enable secret scanning on each repository.",
			clause:  all(leaf("payload.secret_scanning_enabled", "eq", true), "repository {{.payload.name}} does not have secret scanning enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.5.push_protection_enabled", control: "CC6.5", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "All repositories have push protection enabled.",
			rem:     "Enable secret push protection on each repository.",
			clause:  all(leaf("payload.push_protection_enabled", "eq", true), "repository {{.payload.name}} does not have push protection enabled"),
		}.policy(),
	}
}
