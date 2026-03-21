# METADATA
# title: A1.2 - Backup Cross-Region Copy
# description: AWS Backup plans should include cross-region copy rules for disaster recovery
# scope: package
package sigcomply.soc2.a1_2_backup_cross_region

metadata := {
	"id": "soc2-a1.2-backup-cross-region",
	"name": "Backup Cross-Region Copy",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:backup:plan"],
	"remediation": "Add a cross-region copy rule to the backup plan to ensure backups are replicated to a secondary region for disaster recovery.",
}

violations contains violation if {
	input.resource_type == "aws:backup:plan"
	input.data.has_cross_region_copy == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Backup plan '%s' does not have cross-region copy configured", [input.data.plan_name]),
		"details": {
			"plan_id": input.data.plan_id,
			"plan_name": input.data.plan_name,
		},
	}
}
