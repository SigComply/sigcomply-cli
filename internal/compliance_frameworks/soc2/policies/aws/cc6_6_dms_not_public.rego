# METADATA
# title: CC6.6 - DMS Replication Instance Public Access
# description: DMS replication instances must not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_6_dms_not_public

metadata := {
	"id": "soc2-cc6.6-dms-not-public",
	"name": "DMS Replication Instance Public Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dms:replication-instance"],
	"remediation": "Modify the DMS replication instance to disable public accessibility. Use VPC networking for replication traffic.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:dms:replication-instance"
	input.data.publicly_accessible == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DMS replication instance '%s' is publicly accessible", [input.data.id]),
		"details": {
			"id": input.data.id,
		},
	}
}
