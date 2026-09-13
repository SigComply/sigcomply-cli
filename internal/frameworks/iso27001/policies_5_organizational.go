package iso27001

import "github.com/sigcomply/sigcomply-cli/internal/core"

// organizationalAutomatedPolicies returns the Theme A (5.x) controls
// that can be checked automatically against infrastructure evidence.
func organizationalAutomatedPolicies() []core.Policy {
	return []core.Policy{
		// A.5.33 — protection of records: stored records must not be
		// silently destroyed. Both fields are unread by any other policy.
		autoPolicy{
			id: "iso27001.5.33.database_deletion_protection", control: "A.5.33", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "Managed databases holding records have deletion protection enabled.",
			rem:     "Enable deletion protection on each managed database instance.",
			// is_set guard: deletion_protection is optional in the schema, so a
			// source that omits it is scoped out rather than fabricating a pass.
			clause: allWhere(leaf("payload.deletion_protection", "is_set", nil), leaf("payload.deletion_protection", "eq", true), "database {{.payload.name}} does not have deletion protection enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.33.nosql_deletion_protection", control: "A.5.33", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"nosql_table"},
			desc:    "NoSQL tables holding records have deletion protection enabled.",
			rem:     "Enable deletion protection on each NoSQL table.",
			clause:  all(leaf("payload.deletion_protection", "eq", true), "table {{.payload.name}} does not have deletion protection enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.3.no_broad_admin_bindings", control: "A.5.3", severity: core.SeverityHigh, category: "access", cadence: "daily",
			accepts: []string{"iam_binding"},
			desc:    "No individual user holds an unconditional broad-admin role (segregation of duties).",
			rem:     "Grant admin roles to conditional group bindings, not directly to users.",
			clause:  noneWhere(leaf("payload.principal_type", "eq", "user"), allOf(leaf("payload.is_broad_admin_role", "eq", true), leaf("payload.has_condition", "eq", false)), "user {{.payload.principal_id}} holds unconditional broad-admin role {{.payload.role}}"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.16.inactive_user_accounts", control: "A.5.16", severity: core.SeverityMedium, category: "access", cadence: "daily",
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
			id: "iso27001.5.17.mfa_enforced", control: "A.5.17", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: directoryUserTypes,
			desc:    "All users have MFA enabled (authentication information).",
			rem:     "Enable MFA for every user.",
			clause:  all(leaf("payload.mfa_enabled", "eq", true), "user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.15.repo_default_permission_least_privilege", control: "A.5.15", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"source_control_org_policy"},
			desc:    "The source-control organization grants members a least-privilege default repository permission (access control).",
			rem:     "Set the default member repository permission to `none` or `read`; grant write/admin per team.",
			clause:  all(leaf("payload.default_member_repository_permission", "not_in", []any{"write", "admin"}), "organization {{.payload.id}} grants an overly broad default repository permission"),
		}.policy(),
	}
}
