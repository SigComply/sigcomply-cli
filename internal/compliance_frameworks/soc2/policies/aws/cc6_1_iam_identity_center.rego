# METADATA
# title: CC6.1 - IAM Identity Center
# description: IAM Identity Center (SSO) should be enabled for centralized access management
# scope: package
package sigcomply.soc2.cc6_1_iam_identity_center

metadata := {
	"id": "soc2-cc6.1-iam-identity-center",
	"name": "IAM Identity Center",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:identitycenter:status"],
	"remediation": "Enable IAM Identity Center (AWS SSO) to provide centralized access management with single sign-on capabilities.",
}

violations contains violation if {
	input.resource_type == "aws:identitycenter:status"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "IAM Identity Center (SSO) is not enabled",
		"details": {"region": input.data.region},
	}
}
