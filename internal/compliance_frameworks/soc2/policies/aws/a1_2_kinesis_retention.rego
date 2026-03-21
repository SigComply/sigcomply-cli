# METADATA
# title: A1.2 - Kinesis Stream Retention
# description: Kinesis data streams must retain data for at least 7 days (168 hours)
# scope: package
package sigcomply.soc2.a1_2_kinesis_retention

metadata := {
	"id": "soc2-a1.2-kinesis-retention",
	"name": "Kinesis Stream Retention Period",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kinesis:stream"],
	"remediation": "Increase retention: aws kinesis increase-stream-retention-period --stream-name STREAM --retention-period-hours 168",
}

violations contains violation if {
	input.resource_type == "aws:kinesis:stream"
	input.data.retention_hours < 168
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Kinesis stream '%s' has a retention period of less than 7 days (%d hours)", [input.data.stream_name, input.data.retention_hours]),
		"details": {"stream_name": input.data.stream_name},
	}
}
