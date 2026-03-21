# METADATA
# title: CC7.1 - CloudTrail Log Bucket Security
# description: CloudTrail trails must have an S3 bucket configured with KMS encryption
# scope: package
package sigcomply.soc2.cc7_1_cloudtrail_log_bucket

metadata := {
	"id": "soc2-cc7.1-cloudtrail-log-bucket",
	"name": "CloudTrail Log Bucket Security",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Configure an S3 bucket with KMS encryption for CloudTrail logs: aws cloudtrail update-trail --name <trail> --s3-bucket-name <bucket> --kms-key-id <key-arn>",
}

# Violation: no S3 bucket configured
violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.s3_bucket_name == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not have an S3 bucket configured for log storage", [input.data.name]),
		"details": {
			"trail_name": input.data.name,
		},
	}
}

# Violation: S3 bucket configured but no KMS encryption
violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.s3_bucket_name != ""
	input.data.kms_key_id == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' S3 bucket is not encrypted with KMS", [input.data.name]),
		"details": {
			"trail_name": input.data.name,
			"s3_bucket_name": input.data.s3_bucket_name,
		},
	}
}
