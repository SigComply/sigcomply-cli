# METADATA
# title: CC6.7 - ELBv2 HTTPS Enforcement
# description: Load balancers must enforce HTTPS on all listeners
# scope: package
package sigcomply.soc2.cc6_7_elbv2_https

metadata := {
	"id": "soc2-cc6.7-elbv2-https",
	"name": "ELBv2 HTTPS Enforced",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer"],
	"remediation": "Configure all listeners to use HTTPS/TLS or redirect HTTP to HTTPS",
}

violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	input.data.https_enforced == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Load balancer '%s' does not enforce HTTPS on all listeners", [input.data.name]),
		"details": {"name": input.data.name, "type": input.data.type, "scheme": input.data.scheme},
	}
}
