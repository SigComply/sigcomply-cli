# METADATA
# title: C1.1 - Data Classification Registry
# description: Annual data classification registry must be uploaded
# scope: package
package sigcomply.soc2.c1_1_data_classification_registry

metadata := {
	"id": "soc2-c1.1-data-classification-registry",
	"name": "Data Classification Registry",
	"framework": "soc2",
	"control": "C1.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:data_classification_registry"],
	"category": "data_protection",
	"remediation": "Upload the annual data classification registry listing data assets and their confidentiality levels.",
}

violations contains violation if {
	input.resource_type == "manual:data_classification_registry"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Data classification registry for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:data_classification_registry"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Data classification registry evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:data_classification_registry"
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
