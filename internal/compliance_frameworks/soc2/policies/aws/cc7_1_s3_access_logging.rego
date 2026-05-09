# METADATA
# title: CC7.1 - S3 Access Logging
# description: S3 buckets must have access logging enabled for security monitoring
# scope: package
package sigcomply.soc2.cc7_1_s3_access_logging

metadata := {
	"id": "soc2-cc7.1-s3-access-logging",
	"name": "S3 Access Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable S3 access logging: aws s3api put-bucket-logging --bucket BUCKET --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"LOG_BUCKET\",\"TargetPrefix\":\"logs/\"}}'",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have access logging enabled", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}
