# METADATA
# title: CC7.1 - File Integrity Monitoring Configuration
# description: Annual file integrity monitoring configuration must be uploaded
# scope: package
package sigcomply.soc2.cc7_1_fim_configuration

metadata := {
	"id": "soc2-cc7.1-fim-configuration",
	"name": "File Integrity Monitoring Configuration",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:fim_configuration"],
	"category": "vulnerability_management",
	"remediation": "Upload the current file integrity monitoring (FIM) configuration showing monitored paths and alerting rules.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:fim_configuration"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("FIM configuration for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:fim_configuration"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "FIM configuration evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:fim_configuration"
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
