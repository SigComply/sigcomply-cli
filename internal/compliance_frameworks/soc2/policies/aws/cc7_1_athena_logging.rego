# METADATA
# title: CC7.1 - Athena Workgroup Logging
# description: Athena workgroups should have query result logging configured
# scope: package
package sigcomply.soc2.cc7_1_athena_logging

metadata := {
	"id": "soc2-cc7.1-athena-logging",
	"name": "Athena Workgroup Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:athena:workgroup"],
	"remediation": "Configure query result output location and encryption for the Athena workgroup.",
}

violations contains violation if {
	input.resource_type == "aws:athena:workgroup"
	input.data.publish_cloudwatch_metrics == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Athena workgroup '%s' does not publish CloudWatch metrics", [input.data.name]),
		"details": {"workgroup_name": input.data.name},
	}
}
