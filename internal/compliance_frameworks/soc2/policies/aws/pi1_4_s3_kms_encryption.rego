# METADATA
# title: PI1.4 - S3 KMS Encryption
# description: S3 buckets should use KMS encryption (not just AES-256) for stronger integrity guarantees
# scope: package
package sigcomply.soc2.pi1_4_s3_kms_encryption

metadata := {
	"id": "soc2-pi1.4-s3-kms-encryption",
	"name": "S3 KMS Encryption",
	"framework": "soc2",
	"control": "PI1.4",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Configure S3 bucket to use aws:kms encryption instead of AES256.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.encryption_enabled == true
	input.data.encryption_algorithm != "aws:kms"
	input.data.encryption_algorithm != "aws:kms:dsse"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' uses %s encryption instead of KMS", [input.data.name, input.data.encryption_algorithm]),
		"details": {"bucket_name": input.data.name, "algorithm": input.data.encryption_algorithm},
	}
}
