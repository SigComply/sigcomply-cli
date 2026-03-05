package sigcomply.soc2.cc6_7_acm_expiry_test

import data.sigcomply.soc2.cc6_7_acm_expiry

test_expiring_soon if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "days_until_expiry": 15},
	}
	count(result) == 1
}

test_not_expiring if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "days_until_expiry": 90},
	}
	count(result) == 0
}

# Boundary: exactly 30 days should pass (< 30 required to violate)
test_boundary_30_days if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "days_until_expiry": 30},
	}
	count(result) == 0
}

# Boundary: 29 days should violate
test_boundary_29_days if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "days_until_expiry": 29},
	}
	count(result) == 1
}

# Edge case: already expired (0 days)
test_already_expired if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "days_until_expiry": 0},
	}
	count(result) == 1
}

# Edge case: negative days (past expiration)
test_past_expiration if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "days_until_expiry": -5},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"days_until_expiry": 5},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_acm_expiry.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {},
	}
	count(result) == 0
}
