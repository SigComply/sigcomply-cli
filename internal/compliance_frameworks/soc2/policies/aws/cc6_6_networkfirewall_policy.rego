# METADATA
# title: CC6.6 - Network Firewall Policy Attached
# description: Network Firewall must have a firewall policy attached to enforce traffic inspection rules
# scope: package
package sigcomply.soc2.cc6_6_networkfirewall_policy

metadata := {
	"id": "soc2-cc6.6-networkfirewall-policy",
	"name": "Network Firewall Policy Attached",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:networkfirewall:firewall"],
	"remediation": "Attach a firewall policy to the Network Firewall to define stateless and stateful traffic inspection rules",
}

violations contains violation if {
	input.resource_type == "aws:networkfirewall:firewall"
	input.data.has_firewall_policy == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Network Firewall '%s' does not have a firewall policy attached", [input.data.firewall_name]),
		"details": {"firewall_name": input.data.firewall_name},
	}
}
