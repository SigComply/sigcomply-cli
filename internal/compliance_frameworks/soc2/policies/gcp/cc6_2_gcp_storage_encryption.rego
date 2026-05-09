# METADATA
# title: CC6.2 - GCP Storage Encryption
# description: Cloud Storage buckets should use CMEK encryption
# scope: package
package sigcomply.soc2.cc6_2_gcp_storage

metadata := {
	"id": "soc2-cc6.2-gcp-storage-encryption",
	"name": "GCP Storage Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["gcp:storage:bucket"],
	"remediation": "Configure CMEK encryption for Cloud Storage buckets using Cloud KMS keys.",
	"evidence_type": "automated",
}

# GCS buckets are always encrypted (Google-managed). This check recommends CMEK.
violations contains violation if {
	input.resource_type == "gcp:storage:bucket"
	input.data.encryption_enabled == true
	not input.data.default_kms_key_name
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud Storage bucket '%s' uses Google-managed encryption instead of CMEK (recommended)", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
			"severity_override": "low",
		},
	}
}
