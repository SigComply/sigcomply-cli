# METADATA
# title: A1.2 - Backup Restoration Log
# description: Quarterly backup restoration test log must be uploaded
# scope: package
package sigcomply.soc2.a1_2_backup_restoration_log

metadata := {
	"id": "soc2-a1.2-backup-restoration-log",
	"name": "Backup Restoration Log",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:backup_restoration_log"],
	"category": "system_ops_bcdr",
	"remediation": "Upload the quarterly backup restoration test log.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:backup_restoration_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Backup restoration log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:backup_restoration_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Backup restoration log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:backup_restoration_log"
	input.data.status == "uploaded"
	input.data.files[i].error
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Attachment '%s' not found in storage", [input.data.files[i].name]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"file": input.data.files[i].name,
		},
	}
}
