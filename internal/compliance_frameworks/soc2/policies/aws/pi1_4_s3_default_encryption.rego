# METADATA
# title: PI1.4 - S3 Default Encryption
# description: S3 buckets should have default encryption enabled for processing integrity
# scope: package
package sigcomply.soc2.pi1_4_s3_default_encryption

metadata := {
	"id": "soc2-pi1.4-s3-default-encryption",
	"name": "S3 Default Encryption",
	"framework": "soc2",
	"control": "PI1.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable default encryption on the S3 bucket.",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have default encryption enabled", [input.data.name]),
		"details": {"bucket_name": input.data.name},
	}
}
