# METADATA
# title: CC6.6 - Client VPN Split Tunnel
# description: Client VPN endpoints should have split tunnel disabled for full traffic inspection
# scope: package
package sigcomply.soc2.cc6_6_clientvpn_split_tunnel

metadata := {
	"id": "soc2-cc6.6-clientvpn-split-tunnel",
	"name": "Client VPN Split Tunnel",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:client-vpn-endpoint"],
	"remediation": "Disable split tunnel on the Client VPN endpoint to route all traffic through the VPN.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:client-vpn-endpoint"
	input.data.split_tunnel == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Client VPN endpoint '%s' has split tunnel enabled", [input.resource_id]),
		"details": {},
	}
}
