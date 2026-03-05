package sigcomply.soc2.cc6_2_s3_account_public_access_test

import data.sigcomply.soc2.cc6_2_s3_account_public_access

test_not_all_blocked if {
	result := cc6_2_s3_account_public_access.violations with input as {
		"resource_type": "aws:s3control:account-public-access",
		"resource_id": "arn:aws:s3control::123:account-public-access",
		"data": {"all_blocked": false, "block_public_acls": true, "block_public_policy": false, "ignore_public_acls": true, "restrict_public_buckets": false},
	}
	count(result) == 1
}

test_all_blocked if {
	result := cc6_2_s3_account_public_access.violations with input as {
		"resource_type": "aws:s3control:account-public-access",
		"resource_id": "arn:aws:s3control::123:account-public-access",
		"data": {"all_blocked": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_s3_account_public_access.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"all_blocked": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_s3_account_public_access.violations with input as {
		"resource_type": "aws:s3control:account-public-access",
		"resource_id": "arn:aws:s3control::123:account-public-access",
		"data": {},
	}
	count(result) == 0
}
