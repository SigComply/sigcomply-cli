package sigcomply.soc2.cc6_2_redshiftserverless_encryption_test

import data.sigcomply.soc2.cc6_2_redshiftserverless_encryption

test_not_encrypted if {
	result := cc6_2_redshiftserverless_encryption.violations with input as {
		"resource_type": "aws:redshift-serverless:workgroup",
		"resource_id": "arn:aws:redshift-serverless:us-east-1:123:workgroup/wg",
		"data": {"name": "wg", "encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := cc6_2_redshiftserverless_encryption.violations with input as {
		"resource_type": "aws:redshift-serverless:workgroup",
		"resource_id": "arn:aws:redshift-serverless:us-east-1:123:workgroup/wg",
		"data": {"name": "wg", "encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_redshiftserverless_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
