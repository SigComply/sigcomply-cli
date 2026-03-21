package sigcomply.soc2.cc6_1_ssm_session_manager_test

import data.sigcomply.soc2.cc6_1_ssm_session_manager

test_session_manager_disabled if {
	result := cc6_1_ssm_session_manager.violations with input as {
		"resource_type": "aws:ssm:status",
		"resource_id": "arn:aws:ssm:us-east-1:123:ssm-status",
		"data": {"session_manager_enabled": false, "managed_instance_count": 0, "region": "us-east-1"},
	}
	count(result) == 1
}

test_session_manager_enabled if {
	result := cc6_1_ssm_session_manager.violations with input as {
		"resource_type": "aws:ssm:status",
		"resource_id": "arn:aws:ssm:us-east-1:123:ssm-status",
		"data": {"session_manager_enabled": true, "managed_instance_count": 5, "region": "us-east-1"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_ssm_session_manager.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"session_manager_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_1_ssm_session_manager.violations with input as {
		"resource_type": "aws:ssm:status",
		"resource_id": "arn:aws:ssm:us-east-1:123:ssm-status",
		"data": {},
	}
	count(result) == 0
}
