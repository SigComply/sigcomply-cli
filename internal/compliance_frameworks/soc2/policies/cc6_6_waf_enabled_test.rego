package sigcomply.soc2.cc6_6_waf_enabled_test

import data.sigcomply.soc2.cc6_6_waf_enabled

test_no_waf if {
	result := cc6_6_waf_enabled.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {"web_acl_count": 0, "region": "us-east-1"},
	}
	count(result) == 1
}

test_waf_configured if {
	result := cc6_6_waf_enabled.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {"web_acl_count": 2, "region": "us-east-1"},
	}
	count(result) == 0
}

# Boundary: exactly 1 WAF ACL should pass
test_waf_single_acl if {
	result := cc6_6_waf_enabled.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {"web_acl_count": 1, "region": "us-east-1"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_waf_enabled.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"web_acl_count": 0},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_waf_enabled.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {},
	}
	count(result) == 0
}
