package sigcomply.soc2.a1_2_efs_backup_test

import data.sigcomply.soc2.a1_2_efs_backup

test_backup_disabled if {
	result := a1_2_efs_backup.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-123",
		"data": {"file_system_id": "fs-123", "backup_policy_enabled": false},
	}
	count(result) == 1
}

test_backup_enabled if {
	result := a1_2_efs_backup.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-123",
		"data": {"file_system_id": "fs-123", "backup_policy_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_efs_backup.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"backup_policy_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_efs_backup.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-123",
		"data": {},
	}
	count(result) == 0
}
