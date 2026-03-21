# METADATA
# title: A1.2 - Network Firewall Deletion Protection Enabled
# description: Network Firewall must have deletion protection enabled to prevent accidental removal
# scope: package
package sigcomply.soc2.a1_2_networkfirewall_deletion_protection

metadata := {
	"id": "soc2-a1.2-networkfirewall-deletion-protection",
	"name": "Network Firewall Deletion Protection Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:networkfirewall:firewall"],
	"remediation": "Enable deletion protection on the Network Firewall to prevent accidental or unauthorized deletion",
}

violations contains violation if {
	input.resource_type == "aws:networkfirewall:firewall"
	input.data.deletion_protection == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Network Firewall '%s' does not have deletion protection enabled", [input.data.firewall_name]),
		"details": {"firewall_name": input.data.firewall_name},
	}
}
