package sigcomply.soc2.cc6_2_secrets_manager_cmk_test

import data.sigcomply.soc2.cc6_2_secrets_manager_cmk

test_not_cmk_encrypted if {
	result := cc6_2_secrets_manager_cmk.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:db-creds",
		"data": {"name": "db-creds", "cmk_encrypted": false},
	}
	count(result) == 1
}

test_cmk_encrypted if {
	result := cc6_2_secrets_manager_cmk.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:db-creds",
		"data": {"name": "db-creds", "cmk_encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_secrets_manager_cmk.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"cmk_encrypted": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_secrets_manager_cmk.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:empty",
		"data": {},
	}
	count(result) == 0
}
