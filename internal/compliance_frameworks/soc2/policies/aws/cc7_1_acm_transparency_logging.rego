# METADATA
# title: CC7.1 - ACM Certificate Transparency Logging
# description: ACM certificates should have certificate transparency logging enabled
# scope: package
package sigcomply.soc2.cc7_1_acm_transparency_logging

metadata := {
	"id": "soc2-cc7.1-acm-transparency-logging",
	"name": "ACM Transparency Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:acm:certificate"],
	"remediation": "Enable certificate transparency logging when requesting or importing a certificate",
}

violations contains violation if {
	input.resource_type == "aws:acm:certificate"
	input.data.transparency_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ACM certificate '%s' does not have certificate transparency logging enabled", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name},
	}
}
