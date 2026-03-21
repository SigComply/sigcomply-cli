# METADATA
# title: CC7.1 - DataSync Task Logging
# description: DataSync tasks should have CloudWatch logging enabled
# scope: package
package sigcomply.soc2.cc7_1_datasync_logging

metadata := {
	"id": "soc2-cc7.1-datasync-logging",
	"name": "DataSync Task Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:datasync:task"],
	"remediation": "Configure CloudWatch log group for the DataSync task.",
}

violations contains violation if {
	input.resource_type == "aws:datasync:task"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DataSync task '%s' does not have logging enabled", [input.data.name]),
		"details": {"task_name": input.data.name},
	}
}
