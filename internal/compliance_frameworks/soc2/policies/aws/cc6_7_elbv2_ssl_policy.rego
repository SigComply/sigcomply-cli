# METADATA
# title: CC6.7 - ELBv2 Secure SSL/TLS Policy
# description: ELBv2 HTTPS listeners must use a secure SSL/TLS policy
# scope: package
package sigcomply.soc2.cc6_7_elbv2_ssl_policy

metadata := {
	"id": "soc2-cc6.7-elbv2-ssl-policy",
	"name": "ELBv2 Secure SSL/TLS Policy",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer"],
	"remediation": "Update HTTPS listeners to use a secure SSL policy (ELBSecurityPolicy-TLS13-1-2-2021-06 or newer).",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	input.data.has_insecure_ssl_policy == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ELBv2 load balancer '%s' has HTTPS listeners with insecure SSL/TLS policy", [input.data.name]),
		"details": {"name": input.data.name, "type": input.data.type},
	}
}
