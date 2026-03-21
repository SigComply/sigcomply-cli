# METADATA
# title: CC6.2 - Route 53 DNSSEC Signing
# description: Route 53 public hosted zones should have DNSSEC signing enabled
# scope: package
package sigcomply.soc2.cc6_2_route53_dnssec

metadata := {
	"id": "soc2-cc6.2-route53-dnssec",
	"name": "Route 53 DNSSEC Signing",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:route53:hosted-zone"],
	"remediation": "Enable DNSSEC signing for the Route 53 hosted zone.",
}

violations contains violation if {
	input.resource_type == "aws:route53:hosted-zone"
	input.data.is_private == false
	input.data.dnssec_signing == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Route 53 hosted zone '%s' does not have DNSSEC signing enabled", [input.data.zone_name]),
		"details": {"zone_name": input.data.zone_name},
	}
}
