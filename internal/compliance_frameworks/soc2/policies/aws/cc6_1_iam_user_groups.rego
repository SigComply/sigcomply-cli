# METADATA
# title: CC6.1 - IAM User Group Membership
# description: IAM users with direct policy attachments should belong to at least one group
# scope: package
package sigcomply.soc2.cc6_1_iam_user_groups

metadata := {
	"id": "soc2-cc6.1-iam-user-groups",
	"name": "IAM User Group Membership",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Add the IAM user to appropriate groups and manage permissions through group policies instead of direct policy attachments.",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.group_count == 0
	has_direct_policies
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has direct policy attachments but belongs to no groups", [input.data.user_name]),
		"details": {
			"user_name": input.data.user_name,
			"group_count": input.data.group_count,
			"inline_policy_count": input.data.inline_policy_count,
			"attached_policy_count": count(input.data.attached_policies),
		},
	}
}

has_direct_policies if {
	input.data.inline_policy_count > 0
}

has_direct_policies if {
	count(input.data.attached_policies) > 0
}
