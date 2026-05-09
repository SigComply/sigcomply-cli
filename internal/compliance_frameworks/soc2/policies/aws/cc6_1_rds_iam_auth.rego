# METADATA
# title: CC6.1 - RDS IAM Database Authentication
# description: RDS instances should have IAM database authentication enabled
# scope: package
package sigcomply.soc2.cc6_1_rds_iam_auth

metadata := {
	"id": "soc2-cc6.1-rds-iam-auth",
	"name": "RDS IAM Authentication",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable IAM database authentication: aws rds modify-db-instance --db-instance-identifier <id> --enable-iam-database-authentication",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.iam_database_authentication_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have IAM database authentication enabled", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": input.data.engine,
		},
	}
}
