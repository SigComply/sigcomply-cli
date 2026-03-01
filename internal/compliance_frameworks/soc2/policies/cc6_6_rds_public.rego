# METADATA
# title: CC6.6 - Public Database Access
# description: RDS instances and Cloud SQL instances must not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_6_db_public

metadata := {
	"id": "soc2-cc6.6-db-public",
	"name": "Public Database Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance", "gcp:sql:instance"],
	"remediation": "Disable public accessibility on database instances. Use VPC/private networking for database access.",
}

# AWS RDS
violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.publicly_accessible == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' is publicly accessible", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": input.data.engine,
		},
	}
}

# GCP Cloud SQL
violations contains violation if {
	input.resource_type == "gcp:sql:instance"
	input.data.public_ip_enabled == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud SQL instance '%s' has public IP enabled", [input.data.name]),
		"details": {
			"instance_name": input.data.name,
			"database_version": input.data.database_version,
		},
	}
}
