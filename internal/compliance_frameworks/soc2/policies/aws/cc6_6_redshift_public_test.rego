package sigcomply.soc2.cc6_6_redshift_public_test

import data.sigcomply.soc2.cc6_6_redshift_public

test_publicly_accessible if {
	result := cc6_6_redshift_public.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:dev-cluster",
		"data": {"cluster_id": "dev-cluster", "publicly_accessible": true},
	}
	count(result) == 1
}

test_not_publicly_accessible if {
	result := cc6_6_redshift_public.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:prod-cluster",
		"data": {"cluster_id": "prod-cluster", "publicly_accessible": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_redshift_public.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:test",
		"data": {"publicly_accessible": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_redshift_public.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:test",
		"data": {},
	}
	count(result) == 0
}
