package sigcomply.soc2.cc6_2_ebs_test

import data.sigcomply.soc2.cc6_2_ebs

# Test: EBS encryption disabled should violate
test_ebs_not_encrypted if {
	result := cc6_2_ebs.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-encryption-by-default",
		"data": {
			"encryption_by_default": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Test: EBS encryption enabled should pass
test_ebs_encrypted if {
	result := cc6_2_ebs.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-encryption-by-default",
		"data": {
			"encryption_by_default": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_ebs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encryption_by_default": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_ebs.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-encryption-by-default",
		"data": {},
	}
	count(result) == 0
}
