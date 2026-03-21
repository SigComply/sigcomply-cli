# METADATA
# title: PI1.5 - S3 Object Lock
# description: S3 buckets should have Object Lock enabled for immutability
# scope: package
package sigcomply.soc2.pi1_5_s3_object_lock

metadata := {
	"id": "soc2-pi1.5-s3-object-lock",
	"name": "S3 Object Lock Enabled",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable Object Lock on the S3 bucket (must be set at bucket creation).",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.object_lock_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have Object Lock enabled", [input.data.name]),
		"details": {"bucket_name": input.data.name},
	}
}
