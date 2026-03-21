# METADATA
# title: CC7.1 - CloudFront Distribution Logging Enabled
# description: CloudFront distributions must have access logging enabled
# scope: package
package sigcomply.soc2.cc7_1_cloudfront_logging

metadata := {
	"id": "soc2-cc7.1-cloudfront-logging",
	"name": "CloudFront Distribution Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Enable access logging for CloudFront distribution to an S3 bucket.",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not have access logging enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
