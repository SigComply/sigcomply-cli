# METADATA
# title: CC6.1 - KMS Key Policy Not Publicly Accessible
# description: KMS key policies must not grant public access
# scope: package
package sigcomply.soc2.cc6_1_kms_key_policy_public

metadata := {
	"id": "soc2-cc6.1-kms-key-policy-public",
	"name": "KMS Key Policy Not Public",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kms:key"],
	"remediation": "Update the KMS key policy to remove wildcard principal (*) access. Restrict to specific AWS accounts, IAM users, or roles.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:kms:key"
	input.data.enabled == true
	input.data.key_policy_public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("KMS key '%s' has a key policy that grants public access", [input.data.key_id]),
		"details": {
			"key_id": input.data.key_id,
			"key_arn": input.data.key_arn,
		},
	}
}
