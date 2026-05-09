# METADATA
# title: CC6.6 - CloudFront Distribution WAF Associated
# description: CloudFront distributions must have AWS WAF web ACL associated
# scope: package
package sigcomply.soc2.cc6_6_cloudfront_waf

metadata := {
	"id": "soc2-cc6.6-cloudfront-waf",
	"name": "CloudFront Distribution WAF Associated",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Associate an AWS WAF web ACL with the CloudFront distribution.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.waf_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not have WAF associated", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
