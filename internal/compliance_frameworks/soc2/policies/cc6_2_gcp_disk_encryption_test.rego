package sigcomply.soc2.cc6_2_gcp_disk_test

import data.sigcomply.soc2.cc6_2_gcp_disk

# Test: disk with Google-managed encryption should violate (low severity)
test_google_managed if {
	result := cc6_2_gcp_disk.violations with input as {
		"resource_type": "gcp:compute:disk",
		"resource_id": "projects/proj/zones/us-central1-a/disks/disk-1",
		"data": {
			"name": "disk-1",
			"encryption_type": "google-managed",
		},
	}
	count(result) == 1
}

# Test: disk with CMEK should pass
test_cmek if {
	result := cc6_2_gcp_disk.violations with input as {
		"resource_type": "gcp:compute:disk",
		"resource_id": "projects/proj/zones/us-central1-a/disks/disk-2",
		"data": {
			"name": "disk-2",
			"encryption_type": "cmek",
		},
	}
	count(result) == 0
}

# Test: disk with CSEK should pass
test_csek if {
	result := cc6_2_gcp_disk.violations with input as {
		"resource_type": "gcp:compute:disk",
		"resource_id": "projects/proj/zones/us-central1-a/disks/disk-3",
		"data": {
			"name": "disk-3",
			"encryption_type": "csek",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_gcp_disk.violations with input as {
		"resource_type": "aws:ec2:ebs-encryption",
		"resource_id": "arn:aws:ec2:us-east-1:123:ebs-default",
		"data": {"encryption_type": "google-managed"},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_gcp_disk.violations with input as {
		"resource_type": "gcp:compute:disk",
		"resource_id": "projects/proj/zones/us-central1-a/disks/empty",
		"data": {},
	}
	count(result) == 0
}
