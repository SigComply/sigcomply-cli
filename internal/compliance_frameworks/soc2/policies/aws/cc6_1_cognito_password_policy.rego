# METADATA
# title: CC6.1 - Cognito Password Policy
# description: Cognito User Pools should enforce strong password requirements
# scope: package
package sigcomply.soc2.cc6_1_cognito_password_policy

metadata := {
	"id": "soc2-cc6.1-cognito-password-policy",
	"name": "Cognito Password Policy",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cognito:user-pool"],
	"remediation": "Set minimum password length to 12+ and enable all complexity requirements.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cognito:user-pool"
	input.data.min_password_length < 12
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cognito User Pool '%s' has minimum password length %d (should be >= 12)", [input.data.name, input.data.min_password_length]),
		"details": {"pool_name": input.data.name, "min_password_length": input.data.min_password_length},
	}
}

violations contains violation if {
	input.resource_type == "aws:cognito:user-pool"
	not input.data.require_uppercase
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cognito User Pool '%s' does not require uppercase characters", [input.data.name]),
		"details": {"pool_name": input.data.name},
	}
}

violations contains violation if {
	input.resource_type == "aws:cognito:user-pool"
	not input.data.require_lowercase
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cognito User Pool '%s' does not require lowercase characters", [input.data.name]),
		"details": {"pool_name": input.data.name},
	}
}

violations contains violation if {
	input.resource_type == "aws:cognito:user-pool"
	not input.data.require_numbers
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cognito User Pool '%s' does not require numbers", [input.data.name]),
		"details": {"pool_name": input.data.name},
	}
}

violations contains violation if {
	input.resource_type == "aws:cognito:user-pool"
	not input.data.require_symbols
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cognito User Pool '%s' does not require symbols", [input.data.name]),
		"details": {"pool_name": input.data.name},
	}
}
