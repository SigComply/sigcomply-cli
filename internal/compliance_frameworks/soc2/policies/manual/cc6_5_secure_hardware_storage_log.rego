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
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:secure_hardware_storage_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Secure Hardware Storage Log for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
