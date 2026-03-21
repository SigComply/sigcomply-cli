# METADATA
# title: CC6.8 - Cognito Advanced Security
# description: Cognito User Pools should have advanced security enabled (ENFORCED or AUDIT)
# scope: package
package sigcomply.soc2.cc6_8_cognito_advanced_security

metadata := {
	"id": "soc2-cc6.8-cognito-advanced-security",
	"name": "Cognito Advanced Security",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cognito:user-pool"],
	"remediation": "Enable advanced security (ENFORCED or AUDIT mode) on the Cognito User Pool.",
}

allowed_security_modes := {"ENFORCED", "AUDIT"}

violations contains violation if {
	input.resource_type == "aws:cognito:user-pool"
	not allowed_security_modes[input.data.advanced_security_mode]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cognito User Pool '%s' does not have advanced security enabled", [input.data.name]),
		"details": {"pool_name": input.data.name, "advanced_security_mode": input.data.advanced_security_mode},
	}
}
