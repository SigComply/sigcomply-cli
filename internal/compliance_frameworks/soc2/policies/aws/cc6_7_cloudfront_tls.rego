# METADATA
# title: CC6.7 - CloudFront Minimum TLS Version
# description: CloudFront distributions must use TLSv1.2_2018 or higher
# scope: package
package sigcomply.soc2.cc6_7_cloudfront_tls

metadata := {
	"id": "soc2-cc6.7-cloudfront-tls",
	"name": "CloudFront Minimum TLS Version",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Update CloudFront distribution to use TLSv1.2_2018 or higher as minimum protocol version.",
}

outdated_tls := {"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	outdated_tls[input.data.minimum_protocol_version]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' uses outdated TLS version '%s'", [input.data.domain_name, input.data.minimum_protocol_version]),
		"details": {"domain_name": input.data.domain_name, "minimum_protocol_version": input.data.minimum_protocol_version},
	}
}
