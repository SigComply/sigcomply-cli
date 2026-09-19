package iso27001

import "github.com/sigcomply/sigcomply-cli/internal/core"

// organizationalAutomatedPolicies returns the Theme A (5.x) controls
// that can be checked automatically against infrastructure evidence.
func organizationalAutomatedPolicies() []core.Policy {
	return []core.Policy{
		// A.5.33 — protection of records: stored records must not be
		// silently destroyed. Both fields are unread by any other policy.
		autoPolicy{
			id: "iso27001.5.33.database_deletion_protection", control: ctrlProtectionOfRecords, severity: core.SeverityMedium, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etManagedDatabaseInstance},
			desc:    "Managed databases holding records have deletion protection enabled.",
			rem:     "Enable deletion protection on each managed database instance.",
			// is_set guard: deletion_protection is optional in the schema, so a
			// source that omits it is scoped out rather than fabricating a pass.
			clause: allWhere(leaf("payload.deletion_protection", "is_set", nil), leaf("payload.deletion_protection", "eq", true), "database {{.payload.name}} does not have deletion protection enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.33.nosql_deletion_protection", control: ctrlProtectionOfRecords, severity: core.SeverityMedium, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"nosql_table"},
			desc:    "NoSQL tables holding records have deletion protection enabled.",
			rem:     "Enable deletion protection on each NoSQL table.",
			clause:  all(leaf("payload.deletion_protection", "eq", true), "table {{.payload.name}} does not have deletion protection enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.3.no_broad_admin_bindings", control: "A.5.3", severity: core.SeverityHigh, category: catAccess, cadence: cadenceDaily,
			accepts: []string{"iam_binding"},
			desc:    "No individual user holds an unconditional broad-admin role (segregation of duties).",
			rem:     "Grant admin roles to conditional group bindings, not directly to users.",
			clause:  noneWhere(leaf("payload.principal_type", "eq", "user"), allOf(leaf("payload.is_broad_admin_role", "eq", true), leaf("payload.has_condition", "eq", false)), "user {{.payload.principal_id}} holds unconditional broad-admin role {{.payload.role}}"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.16.inactive_user_accounts", control: ctrlIdentityManagement, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{"directory_user.v2"},
			desc:    "No active user account has been unused for more than 90 days (identity management).",
			rem:     "Disable accounts unused for more than 90 days; investigate never-logged-in accounts.",
			// is_active is is_set-guarded because it is optional in
			// directory_user.v2 and an unevaluable filter errors the
			// policy. unused_days, also optional, is deliberately left
			// unguarded in the condition: a directory that cannot say
			// how long an account has been idle cannot answer this
			// control, and erroring says so. Guarding it would instead
			// drop those users from the population and pass. Only
			// aws.iam emits directory_user.v2 today and it always
			// populates both.
			clause: allWhere(allOf(isSet("payload.is_active"), leaf("payload.is_active", "eq", true)), allOf(leaf("payload.unused_days", "gte", 0), leaf("payload.unused_days", "lte", 90)), "user {{.payload.display_name}} has been inactive for more than 90 days (or never logged in)"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.17.mfa_enforced", control: "A.5.17", severity: core.SeverityCritical, category: catAccess, cadence: cadenceDaily,
			accepts: directoryUserTypes,
			desc:    "All users have MFA enabled (authentication information).",
			rem:     "Enable MFA for every user.",
			clause:  all(leaf("payload.mfa_enabled", "eq", true), "user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.15.repo_default_permission_least_privilege", control: "A.5.15", severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etSourceControlOrgPolicy},
			desc:    "The source-control organization grants members a least-privilege default repository permission (access control).",
			rem:     "Set the default member repository permission to `none` or `read`; grant write/admin per team.",
			clause:  all(leaf("payload.default_member_repository_permission", "not_in", []any{"write", "admin"}), "organization {{.payload.id}} grants an overly broad default repository permission"),
		}.policy(),
		// A.5.16 / A.5.18 — identity lifecycle, checked by joining accounts
		// in every bound identity source to the roster the project
		// designates (experimental.roster.source). The roster directory's
		// own accounts are never checked against itself, so removal from
		// that directory still needs manual A.5.18 evidence.
		rosterPolicy{
			id: "iso27001.5.16.accounts_linked_to_roster", control: ctrlIdentityManagement, severity: core.SeverityHigh,
			desc: "Every active human account in the bound identity sources (GitHub, GitLab, AWS IAM, …) belongs to a person in the designated roster directory, matched by email or a declared alias (identity management). " +
				"Accounts in the roster directory itself are not checked. A person deleted from the roster directory drops out of the roster, so their remaining accounts are reported here.",
			rem: "Remove accounts that belong to no one in the roster. Link an account whose email is absent or differs from the roster's with experimental.roster.aliases, and declare bots and deploy users in experimental.roster.non_human.",
			clause: allWhere(allOf(leaf("account.active", "eq", true), leaf("account.non_human", "eq", false)), inRoster(nil),
				"account {{.account.ref}} is not linked to anyone in the roster"),
		}.policy(),
		rosterPolicy{
			id: "iso27001.5.18.no_active_accounts_for_inactive_personnel", control: ctrlAccessRights, severity: core.SeverityCritical,
			desc: "No active account in the bound identity sources belongs to a person the designated roster directory marks inactive: suspended, disabled or deprovisioned (access rights). " +
				"This does not attest removal from the roster directory itself (keep providing manual evidence for that), and people deleted outright from the roster are reported by iso27001.5.16.accounts_linked_to_roster instead.",
			rem: "Disable or remove the accounts of people who are inactive in the roster, in every system where they still have access.",
			clause: noneWhere(leaf("account.active", "eq", true), inRoster(leaf("payload.status", "eq", "inactive")),
				"account {{.account.ref}} belongs to {{.account.key}}, who is inactive in the roster"),
		}.policy(),
	}
}
