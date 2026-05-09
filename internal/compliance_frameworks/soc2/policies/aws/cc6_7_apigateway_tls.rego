# METADATA
# title: CC6.7 - API Gateway Minimum TLS 1.2
# description: API Gateway should enforce TLS 1.2 minimum
# scope: package
package sigcomply.soc2.cc6_7_apigateway_tls

metadata := {
	"id": "soc2-cc6.7-apigateway-tls",
	"name": "API Gateway Minimum TLS 1.2",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:apigateway:rest_api"],
	"remediation": "Configure API Gateway to use a security policy that enforces TLS 1.2 minimum.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:apigateway:rest_api"
	input.data.tls_1_0_enabled == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("API Gateway '%s' allows TLS versions below 1.2", [input.data.name]),
		"details": {"api_name": input.data.name},
	}
}
