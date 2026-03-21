package sigcomply.soc2.a1_2_sqs_dlq_test

import data.sigcomply.soc2.a1_2_sqs_dlq

test_no_dlq if {
	result := a1_2_sqs_dlq.violations with input as {
		"resource_type": "aws:sqs:queue",
		"resource_id": "arn:aws:sqs:us-east-1:123:myqueue",
		"data": {"name": "myqueue", "has_dlq": false},
	}
	count(result) == 1
}

test_has_dlq if {
	result := a1_2_sqs_dlq.violations with input as {
		"resource_type": "aws:sqs:queue",
		"resource_id": "arn:aws:sqs:us-east-1:123:myqueue",
		"data": {"name": "myqueue", "has_dlq": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_sqs_dlq.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
