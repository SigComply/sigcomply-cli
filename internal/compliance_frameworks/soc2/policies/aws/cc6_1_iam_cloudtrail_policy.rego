# METADATA
# title: CC6.1 - No Full Access to CloudTrail
# description: IAM policies should not grant full access to CloudTrail
# scope: package
package sigcomply.soc2.cc6_1_iam_cloudtrail_policy

metadata := {
	"id": "soc2-cc6.1-iam-cloudtrail-policy",
	"name": "No Full Access to CloudTrail",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:policy"],
	"remediation": "Restrict CloudTrail permissions to read-only access where possible.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:policy"
	input.data.has_full_cloudtrail_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM policy '%s' grants full access to CloudTrail", [input.data.policy_name]),
		"details": {"policy_name": input.data.policy_name},
	}
}
