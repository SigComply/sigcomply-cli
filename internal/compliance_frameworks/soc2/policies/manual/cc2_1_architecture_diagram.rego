# METADATA
# title: CC2.1 - System Architecture Diagram
# description: Annual system architecture diagram must be uploaded
# scope: package
package sigcomply.soc2.cc2_1_architecture_diagram

metadata := {
	"id": "soc2-cc2.1-architecture-diagram",
	"name": "System Architecture Diagram",
	"framework": "soc2",
	"control": "CC2.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:architecture_diagram"],
	"category": "configuration_management",
	"remediation": "Upload the current system architecture diagram showing major components, data flows, and trust boundaries.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:architecture_diagram"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("System architecture diagram for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:architecture_diagram"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "System architecture diagram evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:architecture_diagram"
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
