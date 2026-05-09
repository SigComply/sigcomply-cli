# METADATA
# title: CC6.1 - IAM Access Key Rotation
# description: IAM users should rotate access keys at least every 90 days
# scope: package
package sigcomply.soc2.cc6_1_access_key_rotation

metadata := {
	"id": "soc2-cc6.1-access-key-rotation",
	"name": "IAM Access Key Rotation",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:iam:user"],
	"remediation": "Rotate IAM access keys that are older than 90 days. Disable or delete unused keys.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:iam:user"
	input.data.active_key_count > 0
	input.data.oldest_key_age_days > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("IAM user '%s' has active access keys older than 90 days (%d days)", [input.data.user_name, input.data.oldest_key_age_days]),
		"details": {
			"user_name": input.data.user_name,
			"oldest_key_age_days": input.data.oldest_key_age_days,
			"active_key_count": input.data.active_key_count,
		},
	}
}
