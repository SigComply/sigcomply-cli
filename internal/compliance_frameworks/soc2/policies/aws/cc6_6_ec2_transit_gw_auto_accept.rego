# METADATA
# title: CC6.6 - Transit Gateway No Auto-Accept
# description: Transit gateways should not auto-accept VPC attachment requests
# scope: package
package sigcomply.soc2.cc6_6_ec2_transit_gw_auto_accept

metadata := {
	"id": "soc2-cc6.6-ec2-transit-gw-auto-accept",
	"name": "Transit Gateway No Auto-Accept",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:transit-gateway"],
	"remediation": "Disable auto-accept shared attachments on the transit gateway.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:transit-gateway"
	input.data.auto_accept_shared_attachments == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Transit gateway '%s' auto-accepts shared attachment requests", [input.resource_id]),
		"details": {},
	}
}
