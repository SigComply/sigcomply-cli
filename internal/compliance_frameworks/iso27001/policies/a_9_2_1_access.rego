# METADATA
# title: A.9.2.1 - User Access Provisioning
# description: Formal user access provisioning process shall be implemented to assign or revoke access rights
# scope: package
# schemas:
#   - input: schema.input
package tracevault.iso27001.a_9_2_1

metadata := {
	"id": "iso27001-a.9.2.1-access",
	"name": "User Access Provisioning",
	"framework": "iso27001",
	"control": "A.9.2.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user", "github:member"],
	"remediation": "Review and document user access provisioning. Ensure all users have appropriate access rights and MFA enabled.",
}

# AWS IAM User - Check for MFA as part of access provisioning security
violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' does not have MFA enabled - access provisioning should include MFA requirement", [input.data.user_name]),
		"details": {
			"user_name": input.data.user_name,
			"user_id": input.data.user_id,
			"control": "A.9.2.1",
		},
	}
}

# GitHub Organization Member - Check for 2FA as part of access provisioning
violations contains violation if {
	input.resource_type == "github:member"
	input.data.two_factor_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GitHub organization member '%s' does not have 2FA enabled - access provisioning should require 2FA", [input.data.login]),
		"details": {
			"login": input.data.login,
			"organization": input.data.organization,
			"control": "A.9.2.1",
		},
	}
}

# GitHub Organization Member - Unknown 2FA status
violations contains violation if {
	input.resource_type == "github:member"
	not has_github_2fa_status
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GitHub organization member '%s' has unknown 2FA status - cannot verify access provisioning compliance", [input.data.login]),
		"details": {
			"login": input.data.login,
			"organization": input.data.organization,
			"control": "A.9.2.1",
			"severity_override": "medium",
		},
	}
}

# Helper to check if GitHub 2FA status is present
has_github_2fa_status if {
	input.data.two_factor_enabled == true
}

has_github_2fa_status if {
	input.data.two_factor_enabled == false
}
