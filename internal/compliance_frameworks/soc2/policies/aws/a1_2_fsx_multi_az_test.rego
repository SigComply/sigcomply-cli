package sigcomply.soc2.a1_2_fsx_multi_az_test

import data.sigcomply.soc2.a1_2_fsx_multi_az

# Test: single-AZ FSx should violate
test_single_az if {
	result := a1_2_fsx_multi_az.violations with input as {
		"resource_type": "aws:fsx:filesystem",
		"resource_id": "arn:aws:fsx:us-east-1:123456789012:file-system/fs-0123456789abcdef0",
		"data": {
			"file_system_id": "fs-0123456789abcdef0",
			"file_system_type": "WINDOWS",
			"multi_az": false,
		},
	}
	count(result) == 1
}

# Test: multi-AZ FSx should pass
test_multi_az if {
	result := a1_2_fsx_multi_az.violations with input as {
		"resource_type": "aws:fsx:filesystem",
		"resource_id": "arn:aws:fsx:us-east-1:123456789012:file-system/fs-abcdef0123456789a",
		"data": {
			"file_system_id": "fs-abcdef0123456789a",
			"file_system_type": "ONTAP",
			"multi_az": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_fsx_multi_az.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:db:my-db",
		"data": {"multi_az": false},
	}
	count(result) == 0
}
