# METADATA
# title: CC7.4 - Incident Response Plan Test
# description: Annual incident response plan testing must be completed with all required checklist items
# scope: package
package sigcomply.soc2.cc7_4_incident_response_test

metadata := {
	"id": "soc2-cc7.4-incident-response-test",
	"name": "Incident Response Plan Test",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:incident_response_test"],
	"category": "logging",
	"remediation": "Complete the incident response test checklist ensuring all required items are checked.",
}

# Violation: not uploaded and overdue
violations contains violation if {
	input.resource_type == "manual:incident_response_test"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Incident response test for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

# Violation: required checklist item not checked
violations contains violation if {
	input.resource_type == "manual:incident_response_test"
	input.data.status == "uploaded"
	item := input.data.items[_]
	item.required == true
	item.checked == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Required checklist item '%s' is not checked", [item.text]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"item_id": item.id,
			"item_text": item.text,
		},
	}
}

# Violation: hash verification failed
violations contains violation if {
	input.resource_type == "manual:incident_response_test"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Incident response test evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
