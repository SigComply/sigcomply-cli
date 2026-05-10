package sigcomply.soc2.cc7_1_fim_configuration_test

import data.sigcomply.soc2.cc7_1_fim_configuration

# Overdue + not_uploaded → one violation
test_overdue_not_uploaded if {
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "manual:fim_configuration",
		"resource_id": "fim_configuration/2026-Q1",
		"data": {
			"evidence_id": "fim_configuration",
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
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "manual:fim_configuration",
		"resource_id": "fim_configuration/2026-Q1",
		"data": {
			"evidence_id": "fim_configuration",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"file_hash": "abc123",
			"file_path": "soc2/fim_configuration/2026-Q1/evidence.pdf",
		},
	}
	count(result) == 0
}

# Not-uploaded but within window → no violation (still in grace)
test_within_window_not_uploaded if {
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "manual:fim_configuration",
		"resource_id": "fim_configuration/2026-Q1",
		"data": {
			"evidence_id": "fim_configuration",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Wrong resource_type → no violation
test_wrong_resource_type if {
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/x",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
