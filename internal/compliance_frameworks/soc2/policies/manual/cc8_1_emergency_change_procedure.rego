# METADATA
# title: CC8.1 - Emergency Change Procedure Declaration
# description: Quarterly declaration that emergency change procedures are documented and followed
# scope: package
package sigcomply.soc2.cc8_1_emergency_change_procedure

metadata := {
	"id": "soc2-cc8.1-emergency-change-procedure",
	"name": "Emergency Change Procedure Declaration",
	"framework": "soc2",
	"control": "CC8.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:emergency_change_procedure"],
	"category": "change_management",
	"remediation": "Declare that emergency change procedures are documented and were followed for any emergency changes this period.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:emergency_change_procedure"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Emergency Change Procedure Declaration for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
