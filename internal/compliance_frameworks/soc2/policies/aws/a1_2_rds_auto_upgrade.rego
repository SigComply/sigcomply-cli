# METADATA
# title: A1.2 - RDS Auto Minor Version Upgrade
# description: RDS instances should have automatic minor version upgrades enabled
# scope: package
package sigcomply.soc2.a1_2_rds_auto_upgrade

metadata := {
	"id": "soc2-a1.2-rds-auto-upgrade",
	"name": "RDS Auto Minor Version Upgrade",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable automatic minor version upgrades for the RDS instance to receive security patches automatically.",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.auto_minor_version_upgrade == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have automatic minor version upgrades enabled", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
		},
	}
}
