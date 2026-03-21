# METADATA
# title: CC6.1 - Cognito User Pool MFA
# description: Cognito User Pools should have MFA enabled
# scope: package
package sigcomply.soc2.cc6_1_cognito_mfa

metadata := {
	"id": "soc2-cc6.1-cognito-mfa",
	"name": "Cognito User Pool MFA",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cognito:user-pool"],
	"remediation": "Enable MFA (ON or OPTIONAL) for the Cognito User Pool.",
}

violations contains violation if {
	input.resource_type == "aws:cognito:user-pool"
	input.data.mfa_configuration == "OFF"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cognito User Pool '%s' does not have MFA enabled", [input.data.name]),
		"details": {"pool_name": input.data.name, "mfa_configuration": input.data.mfa_configuration},
	}
}
