package sigcomply.soc2.cc6_3_iam_access_analyzer_test

import data.sigcomply.soc2.cc6_3_iam_access_analyzer

test_not_enabled if {
	result := cc6_3_iam_access_analyzer.violations with input as {
		"resource_type": "aws:accessanalyzer:status",
		"resource_id": "arn:aws:access-analyzer:us-east-1:123:status",
		"data": {
			"enabled": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

test_enabled if {
	result := cc6_3_iam_access_analyzer.violations with input as {
		"resource_type": "aws:accessanalyzer:status",
		"resource_id": "arn:aws:access-analyzer:us-east-1:123:status",
		"data": {
			"enabled": true,
			"analyzer_count": 1,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_3_iam_access_analyzer.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_3_iam_access_analyzer.violations with input as {
		"resource_type": "aws:accessanalyzer:status",
		"resource_id": "arn:aws:access-analyzer:us-east-1:123:status",
		"data": {},
	}
	count(result) == 0
}
