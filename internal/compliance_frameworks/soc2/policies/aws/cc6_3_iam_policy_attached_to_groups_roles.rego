# METADATA
# title: CC6.3 - No Policies Directly Attached to Users
# description: IAM policies should be attached to groups or roles, not directly to users
# scope: package
package sigcomply.soc2.cc6_3_iam_policy_attached_to_groups_roles

metadata := {
	"id": "soc2-cc6.3-iam-policy-attached-to-groups-roles",
	"name": "No Policies Directly Attached to Users",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Remove policies directly attached to users and use groups or roles instead.",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.attached_policy_count > 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has %d policies directly attached", [input.data.username, input.data.attached_policy_count]),
		"details": {"username": input.data.username, "attached_policy_count": input.data.attached_policy_count},
	}
}
