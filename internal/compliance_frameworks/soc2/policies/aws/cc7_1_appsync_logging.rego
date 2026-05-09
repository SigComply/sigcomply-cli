# METADATA
# title: CC7.1 - AppSync API Logging
# description: AppSync APIs should have field-level logging enabled
# scope: package
package sigcomply.soc2.cc7_1_appsync_logging

metadata := {
	"id": "soc2-cc7.1-appsync-logging",
	"name": "AppSync API Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:appsync:api"],
	"remediation": "Enable field-level logging on the AppSync API.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:appsync:api"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("AppSync API '%s' does not have logging enabled", [input.data.name]),
		"details": {"api_name": input.data.name},
	}
}
