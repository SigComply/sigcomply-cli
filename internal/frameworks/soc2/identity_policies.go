package soc2

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
)

// Identity-source policy IDs. The per-source MFA policies that used
// to live here (okta_users_have_mfa, github_org_members_have_2fa,
// aws_iam mfa_enforced) collapsed into the canonical source-agnostic
// PolicyMFAUnion now that all three plugins emit the cross-vendor
// directory_user shape. What remains here is policies that consume
// types with no cross-vendor analog yet — github_repository,
// okta_app — under their natural SOC 2 controls.
const (
	PolicyGitHubBranchProtection = "soc2.cc6.6.github_branch_protection_on_default"
	PolicyOktaAppsMFA            = "soc2.cc6.7.okta_apps_require_mfa"
)

// Rule IDs registered for the identity-source policies.
const (
	ruleIDGitHubBranchProtection = "rules.soc2.github_branch_protection.v1"
	ruleIDOktaAppsMFA            = "rules.soc2.okta_apps_mfa.v1"
)

// identityPolicies returns the policies that exercise the github and
// okta source plugins on types without a cross-vendor analog. The
// directory_user-consuming MFA policy lives in corePolicies().
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

// identityRules returns the rules backing the identity-source policies.
func identityRules() []core.Rule {
	return []core.Rule{
		githubBranchProtectionRule(),
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
