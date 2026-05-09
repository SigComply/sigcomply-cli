# METADATA
# title: CC6.1 - IAM Support Role
# description: An IAM role with AWSSupportAccess policy must exist for AWS Support access
# scope: package
package sigcomply.soc2.cc6_1_iam_support_role

metadata := {
	"id": "soc2-cc6.1-iam-support-role",
	"name": "IAM Support Role",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:support-role-status"],
	"remediation": "Create an IAM role with the AWSSupportAccess managed policy attached to enable AWS Support access.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:support-role-status"
	input.data.has_support_role == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No IAM role with AWSSupportAccess policy found. Create a support role for AWS Support access.",
		"details": {},
	}
}
