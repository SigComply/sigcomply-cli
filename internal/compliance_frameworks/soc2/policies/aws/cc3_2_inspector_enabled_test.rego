package sigcomply.soc2.cc3_2_inspector_enabled_test

import data.sigcomply.soc2.cc3_2_inspector_enabled

# Test: Inspector enabled should pass
test_inspector_enabled if {
	result := cc3_2_inspector_enabled.violations with input as {
		"resource_type": "aws:inspector:status",
		"resource_id": "arn:aws:inspector2:us-east-1:123:status",
		"data": {
			"enabled": true,
			"ec2_scanning": true,
			"ecr_scanning": true,
			"lambda_scanning": false,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Test: Inspector disabled should violate
test_inspector_disabled if {
	result := cc3_2_inspector_enabled.violations with input as {
		"resource_type": "aws:inspector:status",
		"resource_id": "arn:aws:inspector2:us-east-1:123:status",
		"data": {
			"enabled": false,
			"ec2_scanning": false,
			"ecr_scanning": false,
			"lambda_scanning": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc3_2_inspector_enabled.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc3_2_inspector_enabled.violations with input as {
		"resource_type": "aws:inspector:status",
		"resource_id": "arn:aws:inspector2:us-east-1:123:status",
		"data": {},
	}
	count(result) == 0
}
