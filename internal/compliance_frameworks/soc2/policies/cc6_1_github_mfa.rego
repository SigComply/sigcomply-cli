# METADATA
# title: CC6.1 - GitHub 2FA Required for All Organization Members
# description: All GitHub organization members must have two-factor authentication enabled
# scope: package
# schemas:
#   - input: schema.input
package tracevault.soc2.cc6_1_github

metadata := {
	"id": "soc2-cc6.1-github-mfa",
	"name": "GitHub 2FA Required for All Organization Members",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["github:member"],
	"remediation": "Enable two-factor authentication for the GitHub organization member. Go to Settings > Password and authentication > Enable two-factor authentication.",
}

# violations contains a violation if the member does not have 2FA enabled
violations contains violation if {
	input.resource_type == "github:member"
	input.data.two_factor_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GitHub organization member '%s' does not have two-factor authentication enabled", [input.data.login]),
		"details": {
			"login": input.data.login,
			"organization": input.data.organization,
		},
	}
}

# violations contains a violation if 2FA status is unknown (null/not present)
# This catches cases where we couldn't determine the 2FA status
violations contains violation if {
	input.resource_type == "github:member"
	not has_2fa_status
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GitHub organization member '%s' has unknown two-factor authentication status (requires admin access to verify)", [input.data.login]),
		"details": {
			"login": input.data.login,
			"organization": input.data.organization,
			"severity_override": "medium",
		},
	}
}

# Helper to check if 2FA status is present
has_2fa_status if {
	input.data.two_factor_enabled == true
}

has_2fa_status if {
	input.data.two_factor_enabled == false
}
