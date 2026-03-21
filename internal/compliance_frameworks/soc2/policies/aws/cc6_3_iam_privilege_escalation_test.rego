package sigcomply.soc2.cc6_3_iam_privilege_escalation_test

import data.sigcomply.soc2.cc6_3_iam_privilege_escalation

test_privilege_escalation if {
	result := cc6_3_iam_privilege_escalation.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "arn:aws:iam::123:policy/risky",
		"data": {"policy_name": "risky", "allows_privilege_escalation": true},
	}
	count(result) == 1
}

test_no_escalation if {
	result := cc6_3_iam_privilege_escalation.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "arn:aws:iam::123:policy/safe",
		"data": {"policy_name": "safe", "allows_privilege_escalation": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_3_iam_privilege_escalation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_3_iam_privilege_escalation.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
