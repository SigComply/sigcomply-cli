# METADATA
# title: CC6.6 - API Gateway Throttling
# description: API Gateway stages must have throttling enabled
# scope: package
package sigcomply.soc2.cc6_6_apigateway_throttling

metadata := {
	"id": "soc2-cc6.6-apigateway-throttling",
	"name": "API Gateway Throttling",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:apigateway:rest_api"],
	"remediation": "Enable throttling on API Gateway stages via method settings",
}

# Violation if stages exist but none have throttling enabled
violations contains violation if {
	input.resource_type == "aws:apigateway:rest_api"
	count(input.data.stages) > 0
	not any_throttling_enabled
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("API Gateway '%s' has no stages with throttling enabled", [input.data.name]),
		"details": {
			"api_name": input.data.name,
		},
	}
}

any_throttling_enabled if {
	some i
	input.data.stages[i].throttling_enabled == true
}
