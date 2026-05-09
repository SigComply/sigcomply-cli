# METADATA
# title: PI1.5 - S3 Object Versioning
# description: S3 buckets should have versioning enabled to protect data integrity
# scope: package
package sigcomply.soc2.pi1_5_s3_versioning

metadata := {
	"id": "soc2-pi1.5-s3-versioning",
	"name": "S3 Object Versioning",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable versioning on the S3 bucket.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.versioning_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have versioning enabled", [input.data.name]),
		"details": {"bucket_name": input.data.name},
	}
}
