# METADATA
# title: CC6.1 - MFA Required for All Users
# description: All IAM users must have MFA enabled for logical access security
# scope: package
# schemas:
#   - input: schema.input
package sigcomply.soc2.cc6_1

metadata := {
	"id": "soc2-cc6.1-mfa",
	"name": "MFA Required for All Users",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Enable MFA for the user via the AWS Console or CLI: aws iam enable-mfa-device",
}

# violations contains a violation if the user does not have MFA enabled
violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.mfa_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' does not have MFA enabled", [input.data.user_name]),
		"details": {
			"user_name": input.data.user_name,
			"user_id": input.data.user_id,
		},
	}
}
