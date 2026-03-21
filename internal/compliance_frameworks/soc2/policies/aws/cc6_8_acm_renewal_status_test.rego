package sigcomply.soc2.cc6_8_acm_renewal_status_test

import data.sigcomply.soc2.cc6_8_acm_renewal_status

test_ineligible if {
	result := cc6_8_acm_renewal_status.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "renewal_status": "INELIGIBLE"},
	}
	count(result) == 1
}

test_eligible if {
	result := cc6_8_acm_renewal_status.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc",
		"data": {"domain_name": "example.com", "renewal_status": "ELIGIBLE"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_acm_renewal_status.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
