# METADATA
# title: CC6.7 - CloudFront Field-Level Encryption
# description: CloudFront distributions should use field-level encryption for sensitive data
# scope: package
package sigcomply.soc2.cc6_7_cloudfront_field_encryption

metadata := {
	"id": "soc2-cc6.7-cloudfront-field-encryption",
	"name": "CloudFront Field-Level Encryption",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Configure field-level encryption on the CloudFront distribution.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.field_level_encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not use field-level encryption", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
