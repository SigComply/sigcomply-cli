package sigcomply.soc2.cc6_7_dms_ssl_mode_test

import data.sigcomply.soc2.cc6_7_dms_ssl_mode

# Test: DMS endpoint with ssl_mode "none" should violate
test_dms_no_ssl if {
	result := cc6_7_dms_ssl_mode.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "arn:aws:dms:us-east-1:123:endpoint:dev-ep",
		"data": {
			"id": "dev-ep",
			"ssl_mode": "none",
		},
	}
	count(result) == 1
}

# Test: DMS endpoint with ssl_mode "require" should pass
test_dms_ssl_require if {
	result := cc6_7_dms_ssl_mode.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "arn:aws:dms:us-east-1:123:endpoint:prod-ep",
		"data": {
			"id": "prod-ep",
			"ssl_mode": "require",
		},
	}
	count(result) == 0
}

# Test: DMS endpoint with ssl_mode "verify-full" should pass
test_dms_ssl_verify_full if {
	result := cc6_7_dms_ssl_mode.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "arn:aws:dms:us-east-1:123:endpoint:secure-ep",
		"data": {
			"id": "secure-ep",
			"ssl_mode": "verify-full",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_7_dms_ssl_mode.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {"ssl_mode": "none"},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_7_dms_ssl_mode.violations with input as {
		"resource_type": "aws:dms:endpoint",
		"resource_id": "arn:aws:dms:us-east-1:123:endpoint:empty",
		"data": {},
	}
	count(result) == 0
}
