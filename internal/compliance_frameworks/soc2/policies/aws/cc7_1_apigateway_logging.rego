# METADATA
# title: CC7.1 - API Gateway Logging
# description: API Gateway REST API stages should have execution logging enabled
# scope: package
package sigcomply.soc2.cc7_1_apigateway_logging

metadata := {
	"id": "soc2-cc7.1-apigateway-logging",
	"name": "API Gateway Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:apigateway:rest_api"],
	"remediation": "Enable execution logging for all API Gateway stages. Configure CloudWatch Logs with an appropriate logging level (INFO or ERROR).",
}

violations contains violation if {
	input.resource_type == "aws:apigateway:rest_api"
	stage := input.data.stages[_]
	stage.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("API Gateway '%s' stage '%s' does not have execution logging enabled", [input.data.name, stage.stage_name]),
		"details": {
			"api_name": input.data.name,
			"stage_name": stage.stage_name,
		},
	}
}
