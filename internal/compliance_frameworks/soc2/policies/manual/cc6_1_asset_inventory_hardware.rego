# METADATA
# title: CC6.1 - Hardware Asset Inventory
# description: Quarterly hardware asset inventory must be uploaded
# scope: package
package sigcomply.soc2.cc6_1_asset_inventory_hardware

metadata := {
	"id": "soc2-cc6.1-asset-inventory-hardware",
	"name": "Hardware Asset Inventory",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:asset_inventory_hardware"],
	"category": "access_physical",
	"remediation": "Upload the quarterly hardware asset inventory listing all company-owned devices with assigned owners and locations.",
}

violations contains violation if {
	input.resource_type == "manual:asset_inventory_hardware"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Hardware asset inventory for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:asset_inventory_hardware"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Hardware asset inventory evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:asset_inventory_hardware"
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
