package sigcomply.soc2.cc6_2_s3_mfa_delete_test

import data.sigcomply.soc2.cc6_2_s3_mfa_delete

test_versioned_no_mfa_delete if {
	result := cc6_2_s3_mfa_delete.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"name": "my-bucket", "versioning_enabled": true, "mfa_delete_enabled": false},
	}
	count(result) == 1
}

test_versioned_with_mfa_delete if {
	result := cc6_2_s3_mfa_delete.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"name": "my-bucket", "versioning_enabled": true, "mfa_delete_enabled": true},
	}
	count(result) == 0
}

test_no_versioning_no_mfa if {
	result := cc6_2_s3_mfa_delete.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"name": "my-bucket", "versioning_enabled": false, "mfa_delete_enabled": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_s3_mfa_delete.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:::i-123",
		"data": {"versioning_enabled": true, "mfa_delete_enabled": false},
	}
	count(result) == 0
}
