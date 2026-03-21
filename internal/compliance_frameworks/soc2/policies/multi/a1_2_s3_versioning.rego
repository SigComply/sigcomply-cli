# METADATA
# title: A1.2 - Storage Versioning
# description: S3 buckets and Cloud Storage buckets should have versioning enabled
# scope: package
package sigcomply.soc2.a1_2_versioning

metadata := {
	"id": "soc2-a1.2-storage-versioning",
	"name": "Storage Versioning",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket", "gcp:storage:bucket"],
	"remediation": "Enable versioning on storage buckets for data protection and recovery.",
}

# AWS S3
violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.versioning_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have versioning enabled", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}

# GCP Cloud Storage
violations contains violation if {
	input.resource_type == "gcp:storage:bucket"
	input.data.versioning_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud Storage bucket '%s' does not have versioning enabled", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}
