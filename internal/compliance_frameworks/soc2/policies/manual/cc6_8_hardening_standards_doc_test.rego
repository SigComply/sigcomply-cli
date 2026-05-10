package sigcomply.soc2.cc6_8_hardening_standards_doc_test

import data.sigcomply.soc2.cc6_8_hardening_standards_doc

# Overdue + not_uploaded → one violation
test_overdue_not_uploaded if {
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "manual:hardening_standards_doc",
		"resource_id": "hardening_standards_doc/2026-Q1",
		"data": {
			"evidence_id": "hardening_standards_doc",
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
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "manual:hardening_standards_doc",
		"resource_id": "hardening_standards_doc/2026-Q1",
		"data": {
			"evidence_id": "hardening_standards_doc",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"file_hash": "abc123",
			"file_path": "soc2/hardening_standards_doc/2026-Q1/evidence.pdf",
		},
	}
	count(result) == 0
}

# Not-uploaded but within window → no violation (still in grace)
test_within_window_not_uploaded if {
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "manual:hardening_standards_doc",
		"resource_id": "hardening_standards_doc/2026-Q1",
		"data": {
			"evidence_id": "hardening_standards_doc",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Wrong resource_type → no violation
test_wrong_resource_type if {
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/x",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
