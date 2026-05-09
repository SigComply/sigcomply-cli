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
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:data_classification_registry"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Data Classification Registry for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
