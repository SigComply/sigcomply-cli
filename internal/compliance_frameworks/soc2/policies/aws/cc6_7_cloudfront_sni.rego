# METADATA
# title: CC6.7 - CloudFront SNI
# description: CloudFront distributions must use SNI for SSL/TLS certificate serving
# scope: package
package sigcomply.soc2.cc6_7_cloudfront_sni

metadata := {
	"id": "soc2-cc6.7-cloudfront-sni",
	"name": "CloudFront SNI",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Configure the CloudFront distribution to use SNI (sni-only) for SSL certificate serving instead of dedicated IP.",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.uses_sni == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not use SNI for SSL/TLS", [input.data.domain_name]),
		"details": {
			"domain_name": input.data.domain_name,
		},
	}
}
