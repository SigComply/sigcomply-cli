# METADATA
# title: CC7.2 - CloudTrail S3 Bucket Access Logging
# description: S3 buckets used by CloudTrail should have access logging enabled
# scope: package
package sigcomply.soc2.cc7_2_cloudtrail_s3_access_logging

metadata := {
	"id": "soc2-cc7.2-cloudtrail-s3-access-logging",
	"name": "CloudTrail S3 Bucket Access Logging",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable access logging on the S3 bucket used by CloudTrail.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have access logging enabled", [input.data.name]),
		"details": {"bucket_name": input.data.name},
	}
}
