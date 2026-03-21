# METADATA
# title: CC4.2 - Account Security Contact
# description: AWS account should have a security contact configured
# scope: package
package sigcomply.soc2.cc4_2_account_security_contact

metadata := {
	"id": "soc2-cc4.2-account-security-contact",
	"name": "Account Security Contact",
	"framework": "soc2",
	"control": "CC4.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:account:security-contact"],
	"remediation": "Configure a security contact in the AWS Account settings: aws account put-alternate-contact --alternate-contact-type SECURITY --name ... --email-address ... --phone-number ...",
}

violations contains violation if {
	input.resource_type == "aws:account:security-contact"
	input.data.has_security_contact == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "AWS account does not have a security contact configured",
		"details": {},
	}
}
