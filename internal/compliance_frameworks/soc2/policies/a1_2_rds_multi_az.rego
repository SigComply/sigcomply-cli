# METADATA
# title: A1.2 - RDS Multi-AZ Deployment
# description: RDS instances should use Multi-AZ deployment for high availability
# scope: package
package sigcomply.soc2.a1_2_rds_multi_az

metadata := {
	"id": "soc2-a1.2-rds-multi-az",
	"name": "RDS Multi-AZ Deployment",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable Multi-AZ deployment for RDS instances to ensure high availability and automatic failover.",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.multi_az == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have Multi-AZ deployment enabled", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": input.data.engine,
		},
	}
}
