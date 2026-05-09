# METADATA
# title: CC7.4 - S3 Versioning for Recovery
# description: S3 buckets should have versioning enabled for incident response data recovery
# scope: package
package sigcomply.soc2.cc7_4_s3_versioning

metadata := {
	"id": "soc2-cc7.4-s3-versioning",
	"name": "S3 Versioning for Recovery",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable versioning on the S3 bucket for data recovery capabilities.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.versioning_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have versioning enabled for incident response recovery", [input.data.name]),
		"details": {"bucket_name": input.data.name},
	}
}
