# METADATA
# title: CC6.7 - CloudFront HTTPS
# description: CloudFront distributions must enforce HTTPS
# scope: package
package sigcomply.soc2.cc6_7_cloudfront_https

metadata := {
	"id": "soc2-cc6.7-cloudfront-https",
	"name": "CloudFront HTTPS Enforced",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Set ViewerProtocolPolicy to https-only or redirect-to-https",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.https_only == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not enforce HTTPS", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name, "viewer_protocol_policy": input.data.viewer_protocol_policy},
	}
}
