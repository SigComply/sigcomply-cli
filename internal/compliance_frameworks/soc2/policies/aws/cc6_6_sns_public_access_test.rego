package sigcomply.soc2.cc6_6_sns_public_access_test

import data.sigcomply.soc2.cc6_6_sns_public_access

# Test: public access should violate
test_public_access if {
	result := cc6_6_sns_public_access.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:my-topic",
		"data": {
			"topic_name": "my-topic",
			"topic_arn": "arn:aws:sns:us-east-1:123:my-topic",
			"policy_public_access": true,
		},
	}
	count(result) == 1
}

# Test: no public access should pass
test_no_public_access if {
	result := cc6_6_sns_public_access.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:my-topic",
		"data": {
			"topic_name": "my-topic",
			"topic_arn": "arn:aws:sns:us-east-1:123:my-topic",
			"policy_public_access": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_sns_public_access.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"policy_public_access": true},
	}
	count(result) == 0
}
