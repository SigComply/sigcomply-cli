# METADATA
# title: CC7.1 - Bedrock Model Invocation Logging
# description: Bedrock model invocations should have logging enabled
# scope: package
package sigcomply.soc2.cc7_1_bedrock_logging

metadata := {
	"id": "soc2-cc7.1-bedrock-logging",
	"name": "Bedrock Model Invocation Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:bedrock:model"],
	"remediation": "Enable model invocation logging in Amazon Bedrock settings.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:bedrock:model"
	input.data.invocation_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Bedrock model invocation logging is not enabled",
		"details": {},
	}
}
