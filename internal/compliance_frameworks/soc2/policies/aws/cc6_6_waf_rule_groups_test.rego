package sigcomply.soc2.cc6_6_waf_rule_groups_test

import data.sigcomply.soc2.cc6_6_waf_rule_groups

test_no_rules_with_acls if {
	result := cc6_6_waf_rule_groups.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {
			"web_acl_count": 2,
			"has_rules": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

test_rules_configured if {
	result := cc6_6_waf_rule_groups.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {
			"web_acl_count": 2,
			"has_rules": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

test_no_acls_no_violation if {
	result := cc6_6_waf_rule_groups.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123:waf-status",
		"data": {
			"web_acl_count": 0,
			"has_rules": false,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_waf_rule_groups.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"web_acl_count": 2, "has_rules": false},
	}
	count(result) == 0
}
