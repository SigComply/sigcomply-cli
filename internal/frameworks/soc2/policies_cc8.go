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

// cc8ChangeEvidencePolicies — CC8.1 change management, evidenced from the
// changes themselves rather than from the guardrail configured around
// them. cc8Policies above reads git_repository: it answers "is review
// required?". These read pull_request and deployment: they answer "did
// the changes that actually shipped get reviewed?". Both are needed — a
// protection setting can be bypassed by an admin, disabled and re-enabled
// between runs, or simply not apply to everyone, and none of that is
// visible in a configuration snapshot. An auditor testing CC8.1 samples a
// population of changes from the period, which is the population these
// policies evaluate.
func cc8ChangeEvidencePolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc8.1.changes_independently_approved", control: "CC8.1", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"pull_request"},
			desc:    "Every change merged during the period was approved by someone other than its author.",
			rem:     "Require an independent approval before merge. For a change that legitimately merged without one (a production hotfix, an automated dependency bump), record a scoped exception naming the change.",
			clause:  all(leaf("payload.independent_approval_count", "gte", 1), "change {{.payload.repository}}#{{.payload.number}} by {{.payload.author}} was merged without an independent approval"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.changes_passed_checks", control: "CC8.1", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"pull_request"},
			desc:    "Every change merged during the period passed its automated checks.",
			rem:     "Require status checks to pass before merge, and ensure each repository runs at least one check — a change merged with nothing verifying it is what this control asks about.",
			clause:  all(leaf("payload.checks_passed", "eq", true), "change {{.payload.repository}}#{{.payload.number}} was merged without passing automated checks"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc8.1.approval_precedes_merge", control: "CC8.1", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"pull_request"},
			desc:    "Approvals were recorded before the merge, not after it.",
			rem:     "Approve changes before merging them. An approval added after the fact does not evidence review of what shipped.",
			// Scoped to changes that carry an independent approval: a change
			// with none at all is the subject of changes_independently_approved,
			// and reporting it twice would double-count one defect.
			clause: allWhere(leaf("payload.independent_approval_count", "gte", 1), leaf("payload.approved_before_merge", "eq", true), "change {{.payload.repository}}#{{.payload.number}} was approved only after it had already been merged"),
		}.policy(),
		deploymentTraceabilityPolicy(
			"soc2.cc8.1.production_deploys_from_approved_changes",
			controlRefs("CC8.1"),
		),
	}
}

// deploymentTraceabilityPolicy builds the two-slot policy asserting that
// every production deployment shipped a change that was independently
// approved. It cannot use autoPolicy, which expands to a single slot.
//
// The join is deployment.commit_sha → pull_request.merge_commit_sha, with
// the approval requirement expressed as the index's `where` so that a
// deployment matching only unapproved changes fails. Note this is
// traceability, not a segregation-of-duties check between the merger and
// the deployer: comparing two fields across two slots is not expressible
// in the pass_when DSL, and matches_in tests membership only.
//
// Records whose join key is empty are skipped by matches_in rather than
// matched loosely, so a vendor that reports no merge commit fails closed.
func deploymentTraceabilityPolicy(id string, controls []core.ControlRef) core.Policy {
	return core.Policy{
		ID:           id,
		Controls:     controls,
		Description:  "Every production deployment during the period shipped an independently approved change.",
		Remediation:  "Deploy to production only from the reviewed branch, so each release traces back to an approved change. A deployment of a commit with no corresponding approved change is an unreviewed production release.",
		Severity:     core.SeverityHigh,
		Category:     "change-management",
		Cadence:      "daily",
		OnPush:       true,
		EvidenceMode: core.EvidenceModeAutomated,
		Slots: map[string]core.Slot{
			"deployments": {Accepts: []string{"deployment"}, Cardinality: core.SlotOneOrMore, Required: true, Description: "deployments performed during the period"},
			"changes":     {Accepts: []string{"pull_request"}, Cardinality: core.SlotOneOrMore, Required: true, Description: "changes merged during the period"},
		},
		PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
			Slot:       "deployments",
			Quantifier: core.QuantifierAll,
			Filter:     leaf("payload.is_production", "eq", true),
			Condition: &core.PassWhenCondition{
				Op:          core.OpMatchesIn,
				Field:       "payload.commit_sha",
				InSlot:      "changes",
				RemoteField: "payload.merge_commit_sha",
				Where:       leaf("payload.independent_approval_count", "gte", 1),
			},
			ViolationMsg: "production deployment {{.payload.deployment_id}} of {{.payload.repository}} shipped commit {{.payload.commit_sha}}, which does not trace to an independently approved change",
		}}},
	}
}
