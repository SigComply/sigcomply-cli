package sigcomply.soc2.a1_2_mq_multi_az_test

import data.sigcomply.soc2.a1_2_mq_multi_az

test_single_az if {
	result := a1_2_mq_multi_az.violations with input as {
		"resource_type": "aws:mq:broker",
		"resource_id": "arn:aws:mq:us-east-1:123:broker:mybroker",
		"data": {"broker_name": "mybroker", "deployment_mode": "SINGLE_INSTANCE"},
	}
	count(result) == 1
}

test_multi_az if {
	result := a1_2_mq_multi_az.violations with input as {
		"resource_type": "aws:mq:broker",
		"resource_id": "arn:aws:mq:us-east-1:123:broker:mybroker",
		"data": {"broker_name": "mybroker", "deployment_mode": "ACTIVE_STANDBY_MULTI_AZ"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_mq_multi_az.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
