package iso27001

import "github.com/sigcomply/sigcomply-cli/internal/core"

// organizationalAutomatedPolicies returns the Theme A (5.x) controls
// that can be checked automatically against infrastructure evidence.
func organizationalAutomatedPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "iso27001.5.3.no_broad_admin_bindings", control: "A.5.3", severity: core.SeverityHigh, category: "access", cadence: "daily",
			accepts: []string{"iam_binding"},
			desc:    "No individual user holds an unconditional broad-admin role (segregation of duties).",
			rem:     "Grant admin roles to conditional group bindings, not directly to users.",
			clause:  noneWhere(leaf("payload.principal_type", "eq", "user"), allOf(leaf("payload.is_broad_admin_role", "eq", true), leaf("payload.has_condition", "eq", false)), "user {{.payload.principal_id}} holds unconditional broad-admin role {{.payload.role}}"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.3.gcp_no_user_managed_sa_keys", control: "A.5.3", severity: core.SeverityHigh, category: "access", cadence: "daily",
			accepts: []string{"gcp_service_account_key"},
			desc:    "No GCP service account uses user-managed keys (segregation of duties).",
			rem:     "Delete user-managed service account keys; use workload identity.",
			clause:  none(leaf("payload.is_user_managed", "eq", true), "service account key {{.payload.id}} is user-managed"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.16.inactive_user_accounts", control: "A.5.16", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"directory_user.v2"},
			desc:    "No active user account has been unused for more than 90 days (identity management).",
			rem:     "Disable accounts unused for more than 90 days; investigate never-logged-in accounts.",
			clause:  allWhere(leaf("payload.is_active", "eq", true), allOf(leaf("payload.unused_days", "gte", 0), leaf("payload.unused_days", "lte", 90)), "user {{.payload.display_name}} has been inactive for more than 90 days (or never logged in)"),
		}.policy(),
		autoPolicy{
			id: "iso27001.5.17.mfa_enforced", control: "A.5.17", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: directoryUserTypes,
			desc:    "All users have MFA enabled (authentication information).",
			rem:     "Enable MFA for every user.",
			clause:  all(leaf("payload.mfa_enabled", "eq", true), "user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
	}
}
