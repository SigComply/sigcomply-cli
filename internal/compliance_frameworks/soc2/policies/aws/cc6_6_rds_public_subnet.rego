# METADATA
# title: CC6.6 - RDS Not in Public Subnet
# description: RDS instances should not be in a subnet with an internet gateway route
# scope: package
package sigcomply.soc2.cc6_6_rds_public_subnet

metadata := {
	"id": "soc2-cc6.6-rds-public-subnet",
	"name": "RDS Not in Public Subnet",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Move the RDS instance to a private subnet without an internet gateway route. Use VPC endpoints or NAT gateway for outbound access if needed.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.in_public_subnet == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' is in a subnet with an internet gateway route", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"subnet_group": input.data.db_subnet_group_name,
		},
	}
}
