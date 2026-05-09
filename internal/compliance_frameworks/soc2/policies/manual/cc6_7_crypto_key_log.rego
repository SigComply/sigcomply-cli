# METADATA
# title: CC6.7 - Cryptographic Key Management Log
# description: Quarterly cryptographic key management log must be uploaded
# scope: package
package sigcomply.soc2.cc6_7_crypto_key_log

metadata := {
	"id": "soc2-cc6.7-crypto-key-log",
	"name": "Cryptographic Key Management Log",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:crypto_key_log"],
	"category": "data_protection",
	"remediation": "Upload the quarterly cryptographic key management log covering key generation, rotation, and retirement.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:crypto_key_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cryptographic Key Management Log for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
