# METADATA
# title: CC7.1 - DMS Target Logging
# description: DMS replication tasks should have target logging enabled
# scope: package
package sigcomply.soc2.cc7_1_dms_target_logging

metadata := {
	"id": "soc2-cc7.1-dms-target-logging",
	"name": "DMS Target Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dms:replication-task"],
	"remediation": "Enable target component logging for the DMS replication task.",
}

violations contains violation if {
	input.resource_type == "aws:dms:replication-task"
	input.data.target_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DMS replication task '%s' does not have target logging enabled", [input.data.task_id]),
		"details": {"task_id": input.data.task_id},
	}
}
