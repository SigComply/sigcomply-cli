# METADATA
# title: CC6.2 - API Gateway Cache Encryption
# description: API Gateway stages must have cache encryption enabled
# scope: package
package sigcomply.soc2.cc6_2_apigateway_cache_encryption

metadata := {
	"id": "soc2-cc6.2-apigateway-cache-encryption",
	"name": "API Gateway Cache Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:apigateway:rest_api"],
	"remediation": "Enable cache data encryption for API Gateway stages via method settings",
}

violations contains violation if {
	input.resource_type == "aws:apigateway:rest_api"
	some i
	input.data.stages[i].cache_encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("API Gateway '%s' stage '%s' does not have cache encryption enabled", [input.data.name, input.data.stages[i].stage_name]),
		"details": {
			"api_name": input.data.name,
			"stage_name": input.data.stages[i].stage_name,
		},
	}
}
