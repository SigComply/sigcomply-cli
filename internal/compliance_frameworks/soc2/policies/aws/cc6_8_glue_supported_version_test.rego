package sigcomply.soc2.cc6_8_glue_supported_version_test

import data.sigcomply.soc2.cc6_8_glue_supported_version

test_unsupported_version if {
	result := cc6_8_glue_supported_version.violations with input as {
		"resource_type": "aws:glue:job",
		"resource_id": "arn:aws:glue::123456789012:job/old-job",
		"data": {"job_name": "old-job", "encrypted": false, "glue_version": "2.0"},
	}
	count(result) == 1
}

test_supported_version if {
	result := cc6_8_glue_supported_version.violations with input as {
		"resource_type": "aws:glue:job",
		"resource_id": "arn:aws:glue::123456789012:job/new-job",
		"data": {"job_name": "new-job", "encrypted": true, "glue_version": "4.0"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_glue_supported_version.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-fn",
		"data": {"glue_version": "2.0"},
	}
	count(result) == 0
}
