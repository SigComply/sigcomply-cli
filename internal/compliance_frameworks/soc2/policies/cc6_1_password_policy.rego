# METADATA
# title: CC6.1 - Password Policy Strength
# description: IAM password policy must meet minimum security requirements
# scope: package
package sigcomply.soc2.cc6_1_password

metadata := {
	"id": "soc2-cc6.1-password-policy",
	"name": "Password Policy Strength",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:password-policy"],
	"remediation": "Configure a strong password policy: minimum 14 characters, require complexity, 90-day expiration, prevent reuse.",
}

violations contains violation if {
	input.resource_type == "aws:iam:password-policy"
	input.data.has_policy == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No IAM password policy is configured",
		"details": {},
	}
}

violations contains violation if {
	input.resource_type == "aws:iam:password-policy"
	input.data.has_policy == true
	input.data.minimum_password_length < 14
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Password minimum length is %d characters (should be at least 14)", [input.data.minimum_password_length]),
		"details": {
			"minimum_password_length": input.data.minimum_password_length,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:iam:password-policy"
	input.data.has_policy == true
	input.data.require_uppercase_characters == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Password policy does not require uppercase characters",
		"details": {},
	}
}

violations contains violation if {
	input.resource_type == "aws:iam:password-policy"
	input.data.has_policy == true
	input.data.require_lowercase_characters == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Password policy does not require lowercase characters",
		"details": {},
	}
}

violations contains violation if {
	input.resource_type == "aws:iam:password-policy"
	input.data.has_policy == true
	input.data.require_numbers == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Password policy does not require numbers",
		"details": {},
	}
}

violations contains violation if {
	input.resource_type == "aws:iam:password-policy"
	input.data.has_policy == true
	input.data.require_symbols == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Password policy does not require symbols",
		"details": {},
	}
}

violations contains violation if {
	input.resource_type == "aws:iam:password-policy"
	input.data.has_policy == true
	input.data.max_password_age == 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Password policy has no expiration configured (recommended: 90 days)",
		"details": {
			"severity_override": "low",
		},
	}
}
