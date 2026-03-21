package sigcomply.soc2.cc6_6_ssm_documents_not_public_test

import data.sigcomply.soc2.cc6_6_ssm_documents_not_public

# Test: public documents should violate
test_public_documents if {
	result := cc6_6_ssm_documents_not_public.violations with input as {
		"resource_type": "aws:ssm:document-status",
		"resource_id": "arn:aws:ssm:us-east-1:123:document-status",
		"data": {
			"has_public_documents": true,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Test: no public documents should pass
test_no_public_documents if {
	result := cc6_6_ssm_documents_not_public.violations with input as {
		"resource_type": "aws:ssm:document-status",
		"resource_id": "arn:aws:ssm:us-east-1:123:document-status",
		"data": {
			"has_public_documents": false,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_ssm_documents_not_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_public_documents": true},
	}
	count(result) == 0
}
