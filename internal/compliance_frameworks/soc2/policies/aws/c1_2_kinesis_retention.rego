# METADATA
# title: C1.2 - Kinesis Data Retention Period
# description: Kinesis streams should have appropriate data retention period
# scope: package
package sigcomply.soc2.c1_2_kinesis_retention

metadata := {
	"id": "soc2-c1.2-kinesis-retention",
	"name": "Kinesis Data Retention Period",
	"framework": "soc2",
	"control": "C1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kinesis:stream"],
	"remediation": "Configure Kinesis stream retention period to at least 168 hours (7 days).",
}

violations contains violation if {
	input.resource_type == "aws:kinesis:stream"
	input.data.retention_hours < 168
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Kinesis stream '%s' has retention period of %d hours (less than 7 days)", [input.data.stream_name, input.data.retention_hours]),
		"details": {"stream_name": input.data.stream_name, "retention_hours": input.data.retention_hours},
	}
}
