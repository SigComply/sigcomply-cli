# METADATA
# title: CC6.2 - S3 Bucket Encryption Required
# description: All S3 buckets must have server-side encryption enabled
# scope: package
# schemas:
#   - input: schema.input
package sigcomply.soc2.cc6_2

metadata := {
	"id": "soc2-cc6.2-encryption",
	"name": "S3 Encryption Required",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable default encryption on the S3 bucket using AWS Console or CLI: aws s3api put-bucket-encryption",
}

# violations contains a violation if the S3 bucket does not have encryption enabled
violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have encryption enabled", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}

# Additional check: Warn if bucket is not using KMS encryption (AES256 is less secure)
violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.encryption_enabled == true
	input.data.encryption_algorithm == "AES256"
	not input.data.encryption_key_id
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' uses AES256 encryption instead of KMS (recommended)", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
			"encryption_algorithm": input.data.encryption_algorithm,
			"severity_override": "low",
		},
	}
}
