package sigcomply.soc2.cc6_6_open_db_ports_test

import data.sigcomply.soc2.cc6_6_open_db_ports

# Test: open MySQL should violate
test_open_mysql if {
	result := cc6_6_open_db_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-123",
		"data": {
			"group_id": "sg-123",
			"group_name": "open-mysql",
			"open_mysql": true,
			"open_postgres": false,
			"open_mssql": false,
			"open_redis": false,
			"open_mongodb": false,
		},
	}
	count(result) == 1
}

# Test: open PostgreSQL should violate
test_open_postgres if {
	result := cc6_6_open_db_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-456",
		"data": {
			"group_id": "sg-456",
			"group_name": "open-pg",
			"open_mysql": false,
			"open_postgres": true,
			"open_mssql": false,
			"open_redis": false,
			"open_mongodb": false,
		},
	}
	count(result) == 1
}

# Test: multiple open DB ports should have multiple violations
test_multiple_open if {
	result := cc6_6_open_db_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-789",
		"data": {
			"group_id": "sg-789",
			"group_name": "all-open",
			"open_mysql": true,
			"open_postgres": true,
			"open_mssql": true,
			"open_redis": true,
			"open_mongodb": true,
		},
	}
	count(result) == 5
}

# Test: no open DB ports should pass
test_restricted if {
	result := cc6_6_open_db_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-safe",
		"data": {
			"group_id": "sg-safe",
			"group_name": "restricted",
			"open_mysql": false,
			"open_postgres": false,
			"open_mssql": false,
			"open_redis": false,
			"open_mongodb": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_open_db_ports.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"open_mysql": true},
	}
	count(result) == 0
}
