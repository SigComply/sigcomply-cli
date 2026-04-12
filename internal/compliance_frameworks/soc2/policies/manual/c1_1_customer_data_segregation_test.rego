package sigcomply.soc2.c1_1_customer_data_segregation_test

import data.sigcomply.soc2.c1_1_customer_data_segregation

test_overdue if {
	result := c1_1_customer_data_segregation.violations with input as {
		"resource_type": "manual:customer_data_segregation",
		"resource_id": "customer_data_segregation/2026",
		"data": {
			"evidence_id": "customer_data_segregation",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_accepted if {
	result := c1_1_customer_data_segregation.violations with input as {
		"resource_type": "manual:customer_data_segregation",
		"resource_id": "customer_data_segregation/2026",
		"data": {
			"evidence_id": "customer_data_segregation",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": true,
		},
	}
	count(result) == 0
}

test_unaccepted if {
	result := c1_1_customer_data_segregation.violations with input as {
		"resource_type": "manual:customer_data_segregation",
		"resource_id": "customer_data_segregation/2026",
		"data": {
			"evidence_id": "customer_data_segregation",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": false,
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := c1_1_customer_data_segregation.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
