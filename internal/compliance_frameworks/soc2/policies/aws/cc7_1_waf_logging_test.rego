package sigcomply.soc2.cc7_1_waf_logging_test

import data.sigcomply.soc2.cc7_1_waf_logging

test_logging_disabled_with_acls if {
	result := cc7_1_waf_logging.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {
			"web_acl_count": 2,
			"logging_enabled": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_waf_logging.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {
			"web_acl_count": 2,
			"logging_enabled": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

test_no_acls_no_violation if {
	result := cc7_1_waf_logging.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {
			"web_acl_count": 0,
			"logging_enabled": false,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_waf_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"web_acl_count": 2, "logging_enabled": false},
	}
	count(result) == 0
}
