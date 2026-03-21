# METADATA
# title: CC6.3 - No Inline IAM Policies
# description: IAM users should not have inline policies attached directly
# scope: package
package sigcomply.soc2.cc6_3_inline_policies

metadata := {
	"id": "soc2-cc6.3-inline-policies",
	"name": "No Inline IAM Policies",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Remove inline policies and use managed policies instead: aws iam delete-user-policy --user-name <user> --policy-name <policy>",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.inline_policy_count > 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has %d inline policy(ies). Use managed policies for better governance.", [input.data.user_name, input.data.inline_policy_count]),
		"details": {
			"user_name": input.data.user_name,
			"inline_policy_count": input.data.inline_policy_count,
		},
	}
}
