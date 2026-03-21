package sigcomply.soc2.cc6_6_redshiftserverless_not_public_test

import data.sigcomply.soc2.cc6_6_redshiftserverless_not_public

test_publicly_accessible if {
	result := cc6_6_redshiftserverless_not_public.violations with input as {
		"resource_type": "aws:redshift-serverless:workgroup",
		"resource_id": "arn:aws:redshift-serverless:us-east-1:123:workgroup/wg",
		"data": {"name": "wg", "publicly_accessible": true},
	}
	count(result) == 1
}

test_not_public if {
	result := cc6_6_redshiftserverless_not_public.violations with input as {
		"resource_type": "aws:redshift-serverless:workgroup",
		"resource_id": "arn:aws:redshift-serverless:us-east-1:123:workgroup/wg",
		"data": {"name": "wg", "publicly_accessible": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_redshiftserverless_not_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
