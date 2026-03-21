package sigcomply.soc2.c1_1_encryption_test

import data.sigcomply.soc2.c1_1_encryption

# Test: unencrypted S3 bucket should violate
test_s3_not_encrypted if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::unencrypted",
		"data": {
			"name": "unencrypted",
			"encryption_enabled": false,
		},
	}
	count(result) == 1
}

# Test: encrypted S3 bucket should pass
test_s3_encrypted if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::encrypted",
		"data": {
			"name": "encrypted",
			"encryption_enabled": true,
		},
	}
	count(result) == 0
}

# Test: unencrypted RDS should violate
test_rds_not_encrypted if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev",
		"data": {
			"db_instance_id": "dev",
			"storage_encrypted": false,
		},
	}
	count(result) == 1
}

# Test: encrypted RDS should pass
test_rds_encrypted if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod",
		"data": {
			"db_instance_id": "prod",
			"storage_encrypted": true,
		},
	}
	count(result) == 0
}

# Test: EBS encryption disabled should violate
test_ebs_not_encrypted if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-default",
		"data": {
			"encryption_by_default": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Test: EBS encryption enabled should pass
test_ebs_encrypted if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-default",
		"data": {
			"encryption_by_default": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {"encryption_enabled": false, "storage_encrypted": false, "encryption_by_default": false},
	}
	count(result) == 0
}

# Negative: empty data for S3
test_s3_empty_data if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for RDS
test_rds_empty_data if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for EBS
test_ebs_empty_data if {
	result := c1_1_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-default",
		"data": {},
	}
	count(result) == 0
}
