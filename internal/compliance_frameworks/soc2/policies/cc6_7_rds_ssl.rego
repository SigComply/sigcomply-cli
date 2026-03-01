# METADATA
# title: CC6.7 - Database TLS Enforcement
# description: Database instances must enforce SSL/TLS connections
# scope: package
package sigcomply.soc2.cc6_7_db_ssl

metadata := {
	"id": "soc2-cc6.7-db-ssl",
	"name": "Database TLS Enforcement",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance", "gcp:sql:instance"],
	"remediation": "Enable force_ssl parameter for RDS or require_ssl for Cloud SQL instances.",
}

# AWS RDS
violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.force_ssl == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not enforce SSL connections", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": input.data.engine,
		},
	}
}

# GCP Cloud SQL
violations contains violation if {
	input.resource_type == "gcp:sql:instance"
	input.data.require_ssl == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud SQL instance '%s' does not require SSL connections", [input.data.name]),
		"details": {
			"instance_name": input.data.name,
		},
	}
}
