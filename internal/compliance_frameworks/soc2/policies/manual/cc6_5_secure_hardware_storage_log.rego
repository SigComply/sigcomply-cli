# METADATA
# title: CC6.5 - Secure Hardware Storage Log
# description: Quarterly secure hardware storage log must be uploaded
# scope: package
package sigcomply.soc2.cc6_5_secure_hardware_storage_log

metadata := {
	"id": "soc2-cc6.5-secure-hardware-storage-log",
	"name": "Secure Hardware Storage Log",
	"framework": "soc2",
	"control": "CC6.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:secure_hardware_storage_log"],
	"category": "access_physical",
	"remediation": "Upload the quarterly log of hardware assets stored in secure locations, including check-in/check-out records.",
}

violations contains violation if {
	input.resource_type == "manual:secure_hardware_storage_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Secure hardware storage log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:secure_hardware_storage_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Secure hardware storage log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:secure_hardware_storage_log"
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
