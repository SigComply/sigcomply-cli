# METADATA
# title: CC6.2 - GCP Disk Encryption
# description: Compute Engine disks should use CMEK encryption
# scope: package
package sigcomply.soc2.cc6_2_gcp_disk

metadata := {
	"id": "soc2-cc6.2-gcp-disk-encryption",
	"name": "GCP Disk Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["gcp:compute:disk"],
	"remediation": "Use CMEK encryption for Compute Engine disks. Create disks with --kms-key flag.",
	"evidence_type": "automated",
}

# GCP disks are always encrypted. This recommends CMEK over Google-managed.
violations contains violation if {
	input.resource_type == "gcp:compute:disk"
	input.data.encryption_type == "google-managed"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Disk '%s' uses Google-managed encryption instead of CMEK (recommended)", [input.data.name]),
		"details": {
			"disk_name": input.data.name,
			"encryption_type": input.data.encryption_type,
			"severity_override": "low",
		},
	}
}
