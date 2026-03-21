# METADATA
# title: CC6.8 - DMS Auto Minor Version Upgrade
# description: DMS replication instances should have auto minor version upgrade enabled
# scope: package
package sigcomply.soc2.cc6_8_dms_auto_upgrade

metadata := {
	"id": "soc2-cc6.8-dms-auto-upgrade",
	"name": "DMS Auto Minor Version Upgrade",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dms:replication-instance"],
	"remediation": "Enable auto minor version upgrade on the DMS replication instance to receive security patches automatically.",
}

violations contains violation if {
	input.resource_type == "aws:dms:replication-instance"
	input.data.auto_minor_version_upgrade == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DMS replication instance '%s' does not have auto minor version upgrade enabled", [input.data.id]),
		"details": {
			"id": input.data.id,
		},
	}
}
