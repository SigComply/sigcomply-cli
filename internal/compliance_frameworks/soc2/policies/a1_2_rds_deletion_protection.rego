# METADATA
# title: A1.2 - RDS Deletion Protection
# description: RDS instances must have deletion protection enabled
# scope: package
package sigcomply.soc2.a1_2_rds_deletion_protection

metadata := {
	"id": "soc2-a1.2-rds-deletion-protection",
	"name": "RDS Deletion Protection Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable deletion protection: aws rds modify-db-instance --db-instance-identifier INSTANCE_ID --deletion-protection --apply-immediately",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.deletion_protection == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have deletion protection enabled", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": input.data.engine,
		},
	}
}
