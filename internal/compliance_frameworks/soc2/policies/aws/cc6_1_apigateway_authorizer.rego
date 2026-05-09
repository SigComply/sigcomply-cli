# METADATA
# title: CC6.1 - API Gateway Authorizer
# description: API Gateway REST APIs must have an authorizer configured
# scope: package
package sigcomply.soc2.cc6_1_apigateway_authorizer

metadata := {
	"id": "soc2-cc6.1-apigateway-authorizer",
	"name": "API Gateway Authorizer",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:apigateway:rest_api"],
	"remediation": "Configure an authorizer (Lambda, Cognito, or IAM) for the API Gateway REST API",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:apigateway:rest_api"
	input.data.has_authorizer == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("API Gateway '%s' does not have an authorizer configured", [input.data.name]),
		"details": {
			"api_name": input.data.name,
		},
	}
}
