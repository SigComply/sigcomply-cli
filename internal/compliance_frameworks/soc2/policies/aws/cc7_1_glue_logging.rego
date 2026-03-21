# METADATA
# title: CC7.1 - Glue ETL Job Logging
# description: Glue ETL jobs should have CloudWatch logging enabled
# scope: package
package sigcomply.soc2.cc7_1_glue_logging

metadata := {
	"id": "soc2-cc7.1-glue-logging",
	"name": "Glue ETL Job Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:glue:job"],
	"remediation": "Enable continuous CloudWatch logging for the Glue job.",
}

violations contains violation if {
	input.resource_type == "aws:glue:job"
	input.data.continuous_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Glue job '%s' does not have continuous logging enabled", [input.data.name]),
		"details": {"job_name": input.data.name},
	}
}
