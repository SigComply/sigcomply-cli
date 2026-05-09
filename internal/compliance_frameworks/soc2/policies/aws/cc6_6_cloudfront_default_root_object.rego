# METADATA
# title: CC6.6 - CloudFront Default Root Object
# description: CloudFront distributions should have a default root object configured
# scope: package
package sigcomply.soc2.cc6_6_cloudfront_default_root_object

metadata := {
	"id": "soc2-cc6.6-cloudfront-default-root-object",
	"name": "CloudFront Default Root Object",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudfront:distribution"],
	"remediation": "Configure a default root object for the CloudFront distribution to prevent directory listing exposure.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	has_key(input.data, "default_root_object")
	input.data.default_root_object == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not have a default root object configured", [input.data.domain_name]),
		"details": {
			"domain_name": input.data.domain_name,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	not has_key(input.data, "default_root_object")
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' does not have a default root object configured", [input.data.domain_name]),
		"details": {
			"domain_name": input.data.domain_name,
		},
	}
}

has_key(obj, key) if {
	_ = obj[key]
}
