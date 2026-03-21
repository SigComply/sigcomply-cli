# METADATA
# title: CC6.7 - CloudFront Origin HTTPS Only
# description: CloudFront origins must not use HTTP-only protocol policy
# scope: package
package sigcomply.soc2.cc6_7_cloudfront_origin_ssl

metadata := {
	"id": "soc2-cc6.7-cloudfront-origin-ssl",
	"name": "CloudFront Origin HTTPS Only",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Configure CloudFront origins to use HTTPS-only protocol policy.",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.origin_protocol_policy == "http-only"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' uses HTTP-only origin protocol policy", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name, "origin_protocol_policy": input.data.origin_protocol_policy},
	}
}
