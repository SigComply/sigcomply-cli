package sigcomply.soc2.cc7_3_guardduty_no_high_findings_test

import data.sigcomply.soc2.cc7_3_guardduty_no_high_findings

test_has_high_findings if {
	result := cc7_3_guardduty_no_high_findings.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "guardduty-us-east-1",
		"data": {"region": "us-east-1", "high_severity_findings_count": 3},
	}
	count(result) == 1
}

test_no_findings if {
	result := cc7_3_guardduty_no_high_findings.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "guardduty-us-east-1",
		"data": {"region": "us-east-1", "high_severity_findings_count": 0},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_3_guardduty_no_high_findings.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_3_guardduty_no_high_findings.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
