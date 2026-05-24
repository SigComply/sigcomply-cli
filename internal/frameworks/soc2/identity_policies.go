package soc2

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
)

// Identity-source policy IDs. These four policies demonstrate the
// github and okta source plugins under their natural SOC 2 controls.
const (
	PolicyGitHubBranchProtection = "soc2.cc6.6.github_branch_protection_on_default"
	PolicyGitHubMembers2FA       = "soc2.cc6.1.github_org_members_have_2fa"
	PolicyOktaUsersMFA           = "soc2.cc6.1.okta_users_have_mfa"
	PolicyOktaAppsMFA            = "soc2.cc6.7.okta_apps_require_mfa"
)

// Rule IDs registered for the identity-source policies.
const (
	ruleIDGitHubBranchProtection = "rules.soc2.github_branch_protection.v1"
	ruleIDGitHubMembers2FA       = "rules.soc2.github_members_2fa.v1"
	ruleIDOktaUsersMFA           = "rules.soc2.okta_users_mfa.v1"
	ruleIDOktaAppsMFA            = "rules.soc2.okta_apps_mfa.v1"
)

// identityPolicies returns the four representative policies that
// exercise the github and okta source plugins.
//
//nolint:dupl // each policy spec is a deliberately-declarative config block; collapsing them would obscure rather than clarify
func identityPolicies() []core.Policy {
	return []core.Policy{
		{
			ID:          PolicyGitHubBranchProtection,
			Control:     "SOC2.CC6.6",
			Description: "Default branches of all repositories enforce branch protection.",
			Remediation: "Enable branch protection on the default branch via Settings → Branches in each affected GitHub repository.",
			Severity:    core.SeverityHigh,
			Category:    "change-management",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"repositories": {Accepts: []string{"github_repository"}, Cardinality: core.SlotExactlyOne, Required: true, Description: "GitHub repos in the configured org"},
			},
			RuleRef: ruleIDGitHubBranchProtection,
		},
		{
			ID:          PolicyGitHubMembers2FA,
			Control:     "SOC2.CC6.1",
			Description: "All GitHub organization members have two-factor authentication enabled.",
			Remediation: "Enable required 2FA at the GitHub org level (Settings → Authentication security) and re-invite members with 2FA disabled.",
			Severity:    core.SeverityHigh,
			Category:    "access",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"members": {Accepts: []string{"github_org_member"}, Cardinality: core.SlotExactlyOne, Required: true, Description: "GitHub org members"},
			},
			RuleRef: ruleIDGitHubMembers2FA,
		},
		{
			ID:          PolicyOktaUsersMFA,
			Control:     "SOC2.CC6.1",
			Description: "All active Okta users have at least one enrolled MFA factor.",
			Remediation: "Enroll the affected users in an Okta MFA factor (Security → Multifactor → Factor Enrollment).",
			Severity:    core.SeverityHigh,
			Category:    "access",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"directory": {Accepts: []string{"okta_user"}, Cardinality: core.SlotExactlyOne, Required: true, Description: "Okta users"},
			},
			RuleRef: ruleIDOktaUsersMFA,
		},
		{
			ID:          PolicyOktaAppsMFA,
			Control:     "SOC2.CC6.7",
			Description: "All Okta-managed applications require MFA at sign-on.",
			Remediation: "Attach an Okta sign-on policy that requires MFA to each affected application (Applications → <app> → Sign-On → Sign-On Policy).",
			Severity:    core.SeverityHigh,
			Category:    "access",
			Cadence:     "weekly",
			OnPush:      false,
			Slots: map[string]core.Slot{
				"applications": {Accepts: []string{"okta_app"}, Cardinality: core.SlotExactlyOne, Required: true, Description: "Okta applications"},
			},
			RuleRef: ruleIDOktaAppsMFA,
		},
	}
}

// identityRules returns the rules backing the four identity-source policies.
func identityRules() []core.Rule {
	return []core.Rule{
		githubBranchProtectionRule(),
		githubMembers2FARule(),
		oktaUsersMFARule(),
		oktaAppsMFARule(),
	}
}

// githubBranchProtectionRule fails when any repo's default branch lacks
// branch protection.
func githubBranchProtectionRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDGitHubBranchProtection,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["repositories"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				on, err := payloadBool(r.Payload, "branch_protection_enabled")
				if err != nil {
					return core.RuleResult{}, err
				}
				if on {
					continue
				}
				name, err := payloadString(r.Payload, "name")
				if err != nil {
					return core.RuleResult{}, err
				}
				if name == "" {
					name = r.ID
				}
				branch, err := payloadString(r.Payload, "default_branch")
				if err != nil {
					return core.RuleResult{}, err
				}
				if branch == "" {
					branch = "default"
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     "branch protection disabled on " + name + "@" + branch,
				})
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// githubMembers2FARule fails when any org member has 2FA disabled.
func githubMembers2FARule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDGitHubMembers2FA,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["members"]
			deduped := dedupeByIdentity(records)
			violations := make([]core.Violation, 0)
			for i := range deduped {
				r := &deduped[i]
				on, err := payloadBool(r.Payload, "two_fa_enabled")
				if err != nil {
					return core.RuleResult{}, err
				}
				if on {
					continue
				}
				login, err := payloadString(r.Payload, "login")
				if err != nil {
					return core.RuleResult{}, err
				}
				if login == "" {
					login = r.ID
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     "2FA disabled for GitHub member " + login,
				})
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// oktaUsersMFARule fails when any active Okta user has zero enrolled
// MFA factors. Non-active users (STAGED, DEPROVISIONED, …) are skipped
// to avoid flagging accounts that cannot sign in.
func oktaUsersMFARule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDOktaUsersMFA,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["directory"]
			deduped := dedupeByIdentity(records)
			violations := make([]core.Violation, 0)
			for i := range deduped {
				r := &deduped[i]
				status, err := payloadString(r.Payload, "status")
				if err != nil {
					return core.RuleResult{}, err
				}
				if status != "ACTIVE" {
					continue
				}
				count, err := payloadInt(r.Payload, "mfa_factor_count")
				if err != nil {
					return core.RuleResult{}, err
				}
				if count > 0 {
					continue
				}
				email, err := payloadString(r.Payload, "email")
				if err != nil {
					return core.RuleResult{}, err
				}
				if email == "" {
					email = r.ID
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     "no MFA factors enrolled for Okta user " + email,
				})
			}
			st := core.StatusPass
			if len(violations) > 0 {
				st = core.StatusFail
			}
			return core.RuleResult{Status: st, Violations: violations}, nil
		},
	}
}

// oktaAppsMFARule fails when any Okta-managed application does not
// require MFA at sign-on. The plugin's heuristic populates the
// `mfa_required` field from the app's sign-on mode; finer-grained
// sign-on policy inspection is deferred.
func oktaAppsMFARule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDOktaAppsMFA,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["applications"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				required, err := payloadBool(r.Payload, "mfa_required")
				if err != nil {
					return core.RuleResult{}, err
				}
				if required {
					continue
				}
				label, err := payloadString(r.Payload, "label")
				if err != nil {
					return core.RuleResult{}, err
				}
				if label == "" {
					label = r.ID
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     "MFA not required for Okta application " + label,
				})
			}
			st := core.StatusPass
			if len(violations) > 0 {
				st = core.StatusFail
			}
			return core.RuleResult{Status: st, Violations: violations}, nil
		},
	}
}
