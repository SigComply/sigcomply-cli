# METADATA
# title: CC6.1 - Access Key Rotation
# description: IAM access keys and GCP service account keys must be rotated within 90 days
# scope: package
package sigcomply.soc2.cc6_1_key_rotation

metadata := {
	"id": "soc2-cc6.1-key-rotation",
	"name": "Access Key Rotation",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["gcp:iam:service-account"],
	"remediation": "Rotate service account keys older than 90 days. Create a new key and delete the old one.",
}

violations contains violation if {
	input.resource_type == "gcp:iam:service-account"
	input.data.key_count > 0
	input.data.oldest_key_age_days > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Service account '%s' has keys older than 90 days (%d days)", [input.data.email, input.data.oldest_key_age_days]),
		"details": {
			"email": input.data.email,
			"oldest_key_age_days": input.data.oldest_key_age_days,
			"key_count": input.data.key_count,
		},
	}
}
