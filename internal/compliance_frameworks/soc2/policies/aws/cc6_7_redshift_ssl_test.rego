package sigcomply.soc2.cc6_7_redshift_ssl_test

import data.sigcomply.soc2.cc6_7_redshift_ssl

test_no_ssl if {
	result := cc6_7_redshift_ssl.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:namespace:prod",
		"data": {"cluster_id": "prod", "require_ssl": false},
	}
	count(result) == 1
}

test_ssl_required if {
	result := cc6_7_redshift_ssl.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:namespace:prod",
		"data": {"cluster_id": "prod", "require_ssl": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_redshift_ssl.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod",
		"data": {"require_ssl": false},
	}
	count(result) == 0
}
