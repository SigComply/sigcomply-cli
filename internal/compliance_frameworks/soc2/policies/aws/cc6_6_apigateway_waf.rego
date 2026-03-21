# METADATA
# title: CC6.6 - API Gateway WAF Associated
# description: API Gateway should have a WAF web ACL associated for protection
# scope: package
package sigcomply.soc2.cc6_6_apigateway_waf

metadata := {
	"id": "soc2-cc6.6-apigateway-waf",
	"name": "API Gateway WAF Associated",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:apigateway:rest_api"],
	"remediation": "Associate an AWS WAF web ACL with the API Gateway stage for additional protection.",
}

violations contains violation if {
	input.resource_type == "aws:apigateway:rest_api"
	input.data.waf_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("API Gateway '%s' does not have a WAF web ACL associated", [input.data.name]),
		"details": {"api_name": input.data.name},
	}
}
