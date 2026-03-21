package sigcomply.soc2.pi1_3_config_recorder_test

import data.sigcomply.soc2.pi1_3_config_recorder

test_not_all_supported if {
	result := pi1_3_config_recorder.violations with input as {
		"resource_type": "aws:config:recorder",
		"resource_id": "config-us-east-1",
		"data": {"recorders": [{"name": "default", "all_supported": false, "region": "us-east-1"}]},
	}
	count(result) == 1
}

test_all_supported if {
	result := pi1_3_config_recorder.violations with input as {
		"resource_type": "aws:config:recorder",
		"resource_id": "config-us-east-1",
		"data": {"recorders": [{"name": "default", "all_supported": true, "region": "us-east-1"}]},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_3_config_recorder.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_3_config_recorder.violations with input as {
		"resource_type": "aws:config:recorder",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
