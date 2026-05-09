# METADATA
# title: CC6.2 - S3 MFA Delete
# description: S3 buckets should have MFA Delete enabled for versioned buckets
# scope: package
package sigcomply.soc2.cc6_2_s3_mfa_delete

metadata := {
	"id": "soc2-cc6.2-s3-mfa-delete",
	"name": "S3 MFA Delete Enabled",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable MFA Delete on versioned S3 buckets: aws s3api put-bucket-versioning --bucket <bucket> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa '<serial> <code>'",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.versioning_enabled == true
	input.data.mfa_delete_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' has versioning enabled but MFA Delete is not enabled", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
			"versioning_enabled": true,
		},
	}
}
