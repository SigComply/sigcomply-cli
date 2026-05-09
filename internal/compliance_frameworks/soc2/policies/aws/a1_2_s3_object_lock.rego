# METADATA
# title: A1.2 - S3 Object Lock
# description: S3 buckets should have object lock enabled for data immutability
# scope: package
package sigcomply.soc2.a1_2_s3_object_lock

metadata := {
	"id": "soc2-a1.2-s3-object-lock",
	"name": "S3 Object Lock",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Enable Object Lock when creating the S3 bucket. Object Lock cannot be enabled on existing buckets without recreation.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.object_lock_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have Object Lock enabled", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
