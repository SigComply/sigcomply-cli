package sigcomply.soc2.cc6_8_scanning_test

import data.sigcomply.soc2.cc6_8_scanning

# Test: repo without scan-on-push should violate
test_no_scanning if {
	result := cc6_8_scanning.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/legacy-app",
		"data": {
			"name": "legacy-app",
			"scan_on_push": false,
		},
	}
	count(result) == 1
}

# Test: repo with scan-on-push should pass
test_scanning_enabled if {
	result := cc6_8_scanning.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/my-app",
		"data": {
			"name": "my-app",
			"scan_on_push": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_8_scanning.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"scan_on_push": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_8_scanning.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/empty",
		"data": {},
	}
	count(result) == 0
}
