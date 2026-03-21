package sigcomply.soc2.cc6_6_rds_public_subnet_test

import data.sigcomply.soc2.cc6_6_rds_public_subnet

# Test: RDS in public subnet should violate
test_public_subnet if {
	result := cc6_6_rds_public_subnet.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"db_subnet_group_name": "public-subnet-group",
			"in_public_subnet": true,
		},
	}
	count(result) == 1
}

# Test: RDS in private subnet should pass
test_private_subnet if {
	result := cc6_6_rds_public_subnet.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"db_subnet_group_name": "private-subnet-group",
			"in_public_subnet": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_rds_public_subnet.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"in_public_subnet": true},
	}
	count(result) == 0
}
