# METADATA
# title: CC6.7 - ACM Certificate Expiry
# description: ACM certificates must not be expiring within 30 days
# scope: package
package sigcomply.soc2.cc6_7_acm_expiry

metadata := {
	"id": "soc2-cc6.7-acm-expiry",
	"name": "ACM Certificate Expiry Check",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:acm:certificate"],
	"remediation": "Renew or request a new ACM certificate before expiry",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:acm:certificate"
	input.data.days_until_expiry < 30
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ACM certificate for '%s' expires in %d days", [input.data.domain_name, input.data.days_until_expiry]),
		"details": {"domain_name": input.data.domain_name, "days_until_expiry": input.data.days_until_expiry},
	}
}
