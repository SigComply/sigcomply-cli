package sigcomply.soc2.a1_2_rds_auto_upgrade_test

import data.sigcomply.soc2.a1_2_rds_auto_upgrade

test_auto_upgrade_disabled if {
	result := a1_2_rds_auto_upgrade.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"auto_minor_version_upgrade": false,
		},
	}
	count(result) == 1
}

test_auto_upgrade_enabled if {
	result := a1_2_rds_auto_upgrade.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"auto_minor_version_upgrade": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_rds_auto_upgrade.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"auto_minor_version_upgrade": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_rds_auto_upgrade.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {},
	}
	count(result) == 0
}
