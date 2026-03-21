package sigcomply.soc2.cc6_2_default_ebs_encryption_test

import data.sigcomply.soc2.cc6_2_default_ebs_encryption

test_not_enabled if {
	result := cc6_2_default_ebs_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-encryption",
		"data": {
			"encryption_by_default": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

test_enabled if {
	result := cc6_2_default_ebs_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-encryption",
		"data": {
			"encryption_by_default": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_default_ebs_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encryption_by_default": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_default_ebs_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-encryption",
		"data": {},
	}
	count(result) == 0
}
