# METADATA
# title: CC7.1 - Network Firewall Logging Enabled
# description: Network Firewall must have logging configured to capture traffic events
# scope: package
package sigcomply.soc2.cc7_1_networkfirewall_logging

metadata := {
	"id": "soc2-cc7.1-networkfirewall-logging",
	"name": "Network Firewall Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:networkfirewall:firewall"],
	"remediation": "Enable logging on the Network Firewall by configuring log destinations for alert and flow logs",
}

violations contains violation if {
	input.resource_type == "aws:networkfirewall:firewall"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Network Firewall '%s' does not have logging enabled", [input.data.firewall_name]),
		"details": {"firewall_name": input.data.firewall_name},
	}
}
