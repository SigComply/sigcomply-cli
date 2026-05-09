# METADATA
# title: CC6.6 - CloudFront Geo Restriction
# description: CloudFront distributions should have geo restriction enabled to limit access by geography
# scope: package
package sigcomply.soc2.cc6_6_cloudfront_geo_restriction

metadata := {
	"id": "soc2-cc6.6-cloudfront-geo-restriction",
	"name": "CloudFront Geo Restriction",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Enable geo restriction on the CloudFront distribution to limit access by geography.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.geo_restriction_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not have geo restriction enabled", [input.data.domain_name]),
		"details": {
			"domain_name": input.data.domain_name,
		},
	}
}
