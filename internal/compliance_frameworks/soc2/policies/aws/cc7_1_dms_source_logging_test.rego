package sigcomply.soc2.cc7_1_dms_source_logging_test

import data.sigcomply.soc2.cc7_1_dms_source_logging

test_no_logging if {
	result := cc7_1_dms_source_logging.violations with input as {
		"resource_type": "aws:dms:replication-task",
		"resource_id": "arn:aws:dms:us-east-1:123:task:abc",
		"data": {"task_id": "abc", "source_logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_dms_source_logging.violations with input as {
		"resource_type": "aws:dms:replication-task",
		"resource_id": "arn:aws:dms:us-east-1:123:task:abc",
		"data": {"task_id": "abc", "source_logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_dms_source_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_dms_source_logging.violations with input as {
		"resource_type": "aws:dms:replication-task",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
