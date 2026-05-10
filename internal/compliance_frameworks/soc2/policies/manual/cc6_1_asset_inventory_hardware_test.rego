package sigcomply.soc2.cc6_1_asset_inventory_hardware_test

import data.sigcomply.soc2.cc6_1_asset_inventory_hardware

# Overdue + not_uploaded → one violation
test_overdue_not_uploaded if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "manual:asset_inventory_hardware",
		"resource_id": "asset_inventory_hardware/2026-Q1",
		"data": {
			"evidence_id": "asset_inventory_hardware",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
			"expected_uri": "s3://test-bucket/manual/evidence.pdf",
		},
	}
	count(result) == 1
}

# Uploaded within window → no violation
test_uploaded_within_window if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "manual:asset_inventory_hardware",
		"resource_id": "asset_inventory_hardware/2026-Q1",
		"data": {
			"evidence_id": "asset_inventory_hardware",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"file_hash": "abc123",
			"file_path": "soc2/asset_inventory_hardware/2026-Q1/evidence.pdf",
		},
	}
	count(result) == 0
}

# Not-uploaded but within window → no violation (still in grace)
test_within_window_not_uploaded if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "manual:asset_inventory_hardware",
		"resource_id": "asset_inventory_hardware/2026-Q1",
		"data": {
			"evidence_id": "asset_inventory_hardware",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Wrong resource_type → no violation
test_wrong_resource_type if {
	result := cc6_1_asset_inventory_hardware.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/x",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
