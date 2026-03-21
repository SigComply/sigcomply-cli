package sigcomply.soc2.cc7_1_transfer_encryption_test

import data.sigcomply.soc2.cc7_1_transfer_encryption

test_ftp if {
	result := cc7_1_transfer_encryption.violations with input as {
		"resource_type": "aws:transfer:server",
		"resource_id": "s-abc123",
		"data": {"server_id": "s-abc123", "protocol": "FTP"},
	}
	count(result) == 1
}

test_sftp if {
	result := cc7_1_transfer_encryption.violations with input as {
		"resource_type": "aws:transfer:server",
		"resource_id": "s-abc123",
		"data": {"server_id": "s-abc123", "protocol": "SFTP"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_transfer_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_transfer_encryption.violations with input as {
		"resource_type": "aws:transfer:server",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
