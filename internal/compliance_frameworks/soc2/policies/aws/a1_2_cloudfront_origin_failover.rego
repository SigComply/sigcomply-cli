# METADATA
# title: A1.2 - CloudFront Origin Failover
# description: CloudFront distributions must have origin failover configured for high availability
# scope: package
package sigcomply.soc2.a1_2_cloudfront_origin_failover

metadata := {
	"id": "soc2-a1.2-cloudfront-origin-failover",
	"name": "CloudFront Origin Failover",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Configure an origin group with primary and secondary origins for automatic failover in the CloudFront distribution.",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.has_origin_failover == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not have origin failover configured", [input.data.domain_name]),
		"details": {
			"domain_name": input.data.domain_name,
		},
	}
}
