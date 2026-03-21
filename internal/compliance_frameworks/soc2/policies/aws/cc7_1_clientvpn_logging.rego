# METADATA
# title: CC7.1 - Client VPN Connection Logging
# description: EC2 Client VPN endpoints should have connection logging enabled
# scope: package
package sigcomply.soc2.cc7_1_clientvpn_logging

metadata := {
	"id": "soc2-cc7.1-clientvpn-logging",
	"name": "Client VPN Connection Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:client-vpn-endpoint"],
	"remediation": "Enable connection logging on the Client VPN endpoint.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:client-vpn-endpoint"
	input.data.connection_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Client VPN endpoint '%s' does not have connection logging enabled", [input.resource_id]),
		"details": {},
	}
}
