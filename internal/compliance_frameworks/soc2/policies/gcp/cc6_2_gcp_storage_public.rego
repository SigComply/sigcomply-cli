# METADATA
# title: CC6.2 - GCP Storage Public Access
# description: Cloud Storage buckets must not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_2_gcp_storage_public

metadata := {
	"id": "soc2-cc6.2-gcp-storage-public",
	"name": "GCP Storage Public Access Blocked",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["gcp:storage:bucket"],
	"remediation": "Enable uniform bucket-level access and remove allUsers/allAuthenticatedUsers bindings.",
}

violations contains violation if {
	input.resource_type == "gcp:storage:bucket"
	input.data.all_users_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud Storage bucket '%s' is publicly accessible (allUsers binding)", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}

violations contains violation if {
	input.resource_type == "gcp:storage:bucket"
	input.data.all_authenticated_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud Storage bucket '%s' is accessible by all authenticated users", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}

violations contains violation if {
	input.resource_type == "gcp:storage:bucket"
	input.data.uniform_bucket_access == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud Storage bucket '%s' does not have uniform bucket-level access enabled", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
			"severity_override": "medium",
		},
	}
}
