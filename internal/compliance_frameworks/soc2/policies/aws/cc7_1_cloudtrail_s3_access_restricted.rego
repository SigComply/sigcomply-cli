# METADATA
# title: CC7.1 - CloudTrail S3 Bucket Configured
# description: CloudTrail trails should have a dedicated S3 bucket configured for log storage
# scope: package
package sigcomply.soc2.cc7_1_cloudtrail_s3_access_restricted

metadata := {
	"id": "soc2-cc7.1-cloudtrail-s3-access-restricted",
	"name": "CloudTrail S3 Bucket Configured",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Configure a dedicated S3 bucket for the CloudTrail trail to ensure audit logs are stored securely.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.s3_bucket_name == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not have an S3 bucket configured for log storage", [input.data.name]),
		"details": {"trail_name": input.data.name},
	}
}
