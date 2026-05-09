# METADATA
# title: P3.1 - Data Minimization Proof
# description: Annual data minimization declaration must be completed
# scope: package
package sigcomply.soc2.p3_1_data_minimization_proof

metadata := {
	"id": "soc2-p3.1-data-minimization-proof",
	"name": "Data Minimization Proof",
	"framework": "soc2",
	"control": "P3.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:data_minimization_proof"],
	"category": "privacy",
	"remediation": "Declare that personal data collection is limited to what is necessary as described in the privacy notice.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:data_minimization_proof"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Data minimization proof for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:data_minimization_proof"
	input.data.status == "uploaded"
	input.data.accepted != true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Data minimization declaration was not accepted",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:data_minimization_proof"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Data minimization proof evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
