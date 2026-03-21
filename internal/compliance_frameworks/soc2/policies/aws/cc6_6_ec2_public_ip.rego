# METADATA
# title: CC6.6 - EC2 Public IP
# description: EC2 instances should not have public IP addresses unless required
# scope: package
package sigcomply.soc2.cc6_6_ec2_public_ip

metadata := {
	"id": "soc2-cc6.6-ec2-public-ip",
	"name": "EC2 Public IP",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:instance"],
	"remediation": "Launch EC2 instances in private subnets without public IP addresses. Use NAT gateways or VPC endpoints for outbound connectivity.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:instance"
	input.data.public_ip != ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EC2 instance '%s' has a public IP address assigned (%s)", [input.data.instance_id, input.data.public_ip]),
		"details": {
			"instance_id": input.data.instance_id,
			"public_ip": input.data.public_ip,
		},
	}
}
