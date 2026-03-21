# METADATA
# title: CC7.2 - CIS Metric Filter for S3 Bucket Policy Changes
# description: A metric filter and alarm should exist for S3 bucket policy changes
# scope: package
package sigcomply.soc2.cc7_2_cis_s3_bucket_policy_changes

metadata := {
	"id": "soc2-cc7.2-cis-s3-bucket-policy-changes",
	"name": "CIS Alarm - S3 Bucket Policy Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for S3 bucket policy changes (PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, etc.) and associate an SNS alarm.",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "s3_bucket_policy_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for S3 bucket policy changes (CIS 4.8)",
		"details": {
			"cis_control": "4.8",
			"filter_name": "s3_bucket_policy_changes",
		},
	}
}
