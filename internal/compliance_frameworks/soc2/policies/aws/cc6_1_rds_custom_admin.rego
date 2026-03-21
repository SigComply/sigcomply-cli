# METADATA
# title: CC6.1 - RDS Custom Admin Username
# description: RDS instances should not use default admin usernames like 'admin' or 'postgres'
# scope: package
package sigcomply.soc2.cc6_1_rds_custom_admin

metadata := {
	"id": "soc2-cc6.1-rds-custom-admin",
	"name": "RDS Custom Admin Username",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "When creating RDS instances, use a custom master username instead of default values like 'admin', 'postgres', 'root', or 'sa'.",
}

default_usernames := {"admin", "postgres", "root", "sa", "master", "administrator"}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	default_usernames[lower(input.data.master_username)]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' uses default admin username '%s'", [input.data.db_instance_id, input.data.master_username]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"master_username": input.data.master_username,
		},
	}
}
