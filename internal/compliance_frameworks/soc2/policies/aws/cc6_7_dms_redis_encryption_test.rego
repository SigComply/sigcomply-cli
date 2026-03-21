package sigcomply.soc2.cc6_7_dms_redis_encryption_test

import data.sigcomply.soc2.cc6_7_dms_redis_encryption

test_no_encryption if {
	result := cc6_7_dms_redis_encryption.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "arn:aws:dms:us-east-1:123:endpoint:abc",
		"data": {"engine_name": "redis", "ssl_mode": "none"},
	}
	count(result) == 1
}

test_encryption_enabled if {
	result := cc6_7_dms_redis_encryption.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "arn:aws:dms:us-east-1:123:endpoint:abc",
		"data": {"engine_name": "redis", "ssl_mode": "require"},
	}
	count(result) == 0
}

test_non_redis_engine if {
	result := cc6_7_dms_redis_encryption.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "arn:aws:dms:us-east-1:123:endpoint:abc",
		"data": {"engine_name": "mysql", "ssl_mode": "none"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_dms_redis_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_dms_redis_encryption.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
