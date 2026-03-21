package sigcomply.soc2.cc7_4_efs_backup_test

import data.sigcomply.soc2.cc7_4_efs_backup

test_no_backup if {
	result := cc7_4_efs_backup.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "fs-123",
		"data": {"file_system_id": "fs-123", "backup_policy_enabled": false},
	}
	count(result) == 1
}

test_backup_enabled if {
	result := cc7_4_efs_backup.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "fs-123",
		"data": {"file_system_id": "fs-123", "backup_policy_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_4_efs_backup.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_4_efs_backup.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
