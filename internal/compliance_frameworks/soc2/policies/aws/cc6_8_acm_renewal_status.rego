# METADATA
# title: CC6.8 - ACM Certificate Renewal
# description: ACM certificates should be eligible for renewal
# scope: package
package sigcomply.soc2.cc6_8_acm_renewal_status

metadata := {
	"id": "soc2-cc6.8-acm-renewal-status",
	"name": "ACM Certificate Renewal",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:acm:certificate"],
	"remediation": "Ensure the certificate is eligible for automatic renewal or replace it.",
}

violations contains violation if {
	input.resource_type == "aws:acm:certificate"
	input.data.renewal_status == "INELIGIBLE"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ACM certificate '%s' is not eligible for renewal", [input.data.domain_name]),
		"details": {"domain_name": input.data.domain_name, "renewal_status": input.data.renewal_status},
	}
}
