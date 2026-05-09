# METADATA
# title: CC6.1 - Multiple Active Access Keys
# description: IAM users should not have more than one active access key
# scope: package
package sigcomply.soc2.cc6_1_multiple_active_keys

metadata := {
	"id": "soc2-cc6.1-multiple-active-keys",
	"name": "Multiple Active Access Keys",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Deactivate or delete unused access keys. Each IAM user should have at most one active access key to reduce credential exposure.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.active_key_count > 1
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has %d active access keys (maximum 1 recommended)", [input.data.user_name, input.data.active_key_count]),
		"details": {
			"user_name": input.data.user_name,
			"active_key_count": input.data.active_key_count,
		},
	}
}
