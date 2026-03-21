package sigcomply.soc2.cc7_2_cloudtrail_sns_test

import data.sigcomply.soc2.cc7_2_cloudtrail_sns

test_no_sns if {
	result := cc7_2_cloudtrail_sns.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/main",
		"data": {
			"name": "main",
			"sns_topic_configured": false,
		},
	}
	count(result) == 1
}

test_with_sns if {
	result := cc7_2_cloudtrail_sns.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/main",
		"data": {
			"name": "main",
			"sns_topic_configured": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_2_cloudtrail_sns.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"sns_topic_configured": false},
	}
	count(result) == 0
}
