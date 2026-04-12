package sigcomply.soc2.cc6_1_asset_inventory_hardware_test

import data.sigcomply.soc2.cc6_1_asset_inventory_hardware

test_overdue if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "manual:asset_inventory_hardware",
		"resource_id": "asset_inventory_hardware/2026-Q1",
		"data": {
			"evidence_id": "asset_inventory_hardware",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "manual:asset_inventory_hardware",
		"resource_id": "asset_inventory_hardware/2026-Q1",
		"data": {
			"evidence_id": "asset_inventory_hardware",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "inventory.xlsx", "sha256": "abc", "size_bytes": 2048}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "manual:asset_inventory_hardware",
		"resource_id": "asset_inventory_hardware/2026-Q1",
		"data": {
			"evidence_id": "asset_inventory_hardware",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "inventory.xlsx", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
