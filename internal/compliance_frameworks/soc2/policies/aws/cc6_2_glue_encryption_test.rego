package sigcomply.soc2.cc6_2_glue_encryption_test

import data.sigcomply.soc2.cc6_2_glue_encryption

test_unencrypted_job if {
	result := cc6_2_glue_encryption.violations with input as {
		"resource_type": "aws:glue:job",
		"resource_id": "arn:aws:glue::123456789012:job/unencrypted-job",
		"data": {"job_name": "unencrypted-job", "encrypted": false, "glue_version": "4.0"},
	}
	count(result) == 1
}

test_encrypted_job if {
	result := cc6_2_glue_encryption.violations with input as {
		"resource_type": "aws:glue:job",
		"resource_id": "arn:aws:glue::123456789012:job/encrypted-job",
		"data": {"job_name": "encrypted-job", "encrypted": true, "glue_version": "4.0"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_glue_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"encrypted": false},
	}
	count(result) == 0
}
