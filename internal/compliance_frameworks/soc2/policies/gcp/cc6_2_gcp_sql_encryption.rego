# METADATA
# title: CC6.2 - GCP Cloud SQL Encryption
# description: Cloud SQL instances should use CMEK encryption
# scope: package
package sigcomply.soc2.cc6_2_gcp_sql

metadata := {
	"id": "soc2-cc6.2-gcp-sql-encryption",
	"name": "GCP Cloud SQL Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["gcp:sql:instance"],
	"remediation": "Configure CMEK encryption for Cloud SQL instances using Cloud KMS keys.",
	"evidence_type": "automated",
}

# Cloud SQL instances are always encrypted. This recommends CMEK.
violations contains violation if {
	input.resource_type == "gcp:sql:instance"
	input.data.encryption_enabled == true
	not input.data.kms_key_name
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud SQL instance '%s' uses Google-managed encryption instead of CMEK (recommended)", [input.data.name]),
		"details": {
			"instance_name": input.data.name,
			"severity_override": "low",
		},
	}
}
