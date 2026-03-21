# METADATA
# title: CC7.1 - EMR Logging
# description: EMR clusters must have logging enabled for security monitoring
# scope: package
package sigcomply.soc2.cc7_1_emr_logging

metadata := {
	"id": "soc2-cc7.1-emr-logging",
	"name": "EMR Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:emr:cluster"],
	"remediation": "Enable logging when creating EMR clusters by specifying a log URI (S3 bucket) in the cluster configuration.",
}

violations contains violation if {
	input.resource_type == "aws:emr:cluster"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EMR cluster '%s' does not have logging enabled", [input.data.name]),
		"details": {
			"name": input.data.name,
			"id": input.data.id,
		},
	}
}
