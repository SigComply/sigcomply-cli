# METADATA
# title: CC6.6 - Subnet No Auto-Assign Public IP
# description: VPC subnets should not automatically assign public IP addresses
# scope: package
package sigcomply.soc2.cc6_6_subnet_no_public_ip

metadata := {
	"id": "soc2-cc6.6-subnet-no-public-ip",
	"name": "Subnet No Auto-Assign Public IP",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:subnet"],
	"remediation": "Disable auto-assign public IP for the subnet: aws ec2 modify-subnet-attribute --subnet-id <id> --no-map-public-ip-on-launch",
}

violations contains violation if {
	input.resource_type == "aws:ec2:subnet"
	input.data.map_public_ip_on_launch == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Subnet '%s' automatically assigns public IP addresses on launch", [input.data.subnet_id]),
		"details": {
			"subnet_id": input.data.subnet_id,
			"vpc_id": input.data.vpc_id,
			"availability_zone": input.data.availability_zone,
		},
	}
}
