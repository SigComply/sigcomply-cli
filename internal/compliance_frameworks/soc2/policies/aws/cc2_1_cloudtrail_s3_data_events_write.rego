# METADATA
# title: CC2.1 - CloudTrail S3 Data Events (Write)
# description: CloudTrail should record S3 data events for write operations
# scope: package
package sigcomply.soc2.cc2_1_cloudtrail_s3_data_events_write

metadata := {
	"id": "soc2-cc2.1-cloudtrail-s3-data-events-write",
	"name": "CloudTrail S3 Data Events (Write)",
	"framework": "soc2",
	"control": "CC2.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Configure CloudTrail to record S3 data events including write operations.",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.has_s3_data_events == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not record S3 write data events", [input.data.name]),
		"details": {"trail_name": input.data.name},
	}
}
