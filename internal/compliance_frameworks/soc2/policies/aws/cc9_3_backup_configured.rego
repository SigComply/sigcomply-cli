# METADATA
# title: CC9.3 - Backup Plans Configured
# description: AWS Backup must have at least one backup plan configured
# scope: package
package sigcomply.soc2.cc9_3_backup_configured

metadata := {
	"id": "soc2-cc9.3-backup-configured",
	"name": "Backup Plans Configured",
	"framework": "soc2",
	"control": "CC9.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:backup:status"],
	"remediation": "Create an AWS Backup plan: aws backup create-backup-plan --backup-plan '...'",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:backup:status"
	input.data.has_backup_plans == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("No AWS Backup plans configured in region '%s'. Create backup plans to protect critical resources.", [input.data.region]),
		"details": {
			"region": input.data.region,
			"plan_count": input.data.plan_count,
		},
	}
}
