# METADATA
# title: C1.2 - S3 Lifecycle Configuration
# description: S3 buckets should have lifecycle rules configured for data retention management
# scope: package
package sigcomply.soc2.c1_2_s3_lifecycle

metadata := {
	"id": "soc2-c1.2-s3-lifecycle",
	"name": "S3 Lifecycle Configuration",
	"framework": "soc2",
	"control": "C1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Configure lifecycle rules for the S3 bucket to manage data retention, transitions, and expiration.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.has_lifecycle_rules == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have lifecycle rules configured", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}
