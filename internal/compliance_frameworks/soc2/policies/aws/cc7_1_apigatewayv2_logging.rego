# METADATA
# title: CC7.1 - API Gateway V2 Access Logging
# description: API Gateway V2 (HTTP/WebSocket) APIs should have access logging enabled
# scope: package
package sigcomply.soc2.cc7_1_apigatewayv2_logging

metadata := {
	"id": "soc2-cc7.1-apigatewayv2-logging",
	"name": "API Gateway V2 Access Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:apigateway:v2-api"],
	"remediation": "Enable access logging on the API Gateway V2 stage.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:apigateway:v2-api"
	input.data.access_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("API Gateway V2 '%s' does not have access logging enabled", [input.data.name]),
		"details": {"api_name": input.data.name},
	}
}
