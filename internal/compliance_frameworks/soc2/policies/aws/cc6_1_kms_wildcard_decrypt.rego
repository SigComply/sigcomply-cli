# METADATA
# title: CC6.1 - No Wildcard KMS Decrypt in IAM Policies
# description: IAM policies should not allow kms:Decrypt on all KMS keys (Resource *)
# scope: package
package sigcomply.soc2.cc6_1_kms_wildcard_decrypt

metadata := {
	"id": "soc2-cc6.1-kms-wildcard-decrypt",
	"name": "No Wildcard KMS Decrypt",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:policy"],
	"remediation": "Update IAM policies to scope kms:Decrypt and kms:* actions to specific KMS key ARNs rather than using Resource: *.",
}

violations contains violation if {
	input.resource_type == "aws:iam:policy"
	input.data.has_wildcard_kms_decrypt == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM policy '%s' allows kms:Decrypt on all KMS keys (Resource: *)", [input.data.policy_name]),
		"details": {
			"policy_name": input.data.policy_name,
			"policy_arn": input.data.policy_arn,
		},
	}
}
