# METADATA
# title: A1.2 - DMS Multi-AZ Deployment
# description: DMS replication instances should use Multi-AZ deployment for high availability
# scope: package
package sigcomply.soc2.a1_2_dms_multi_az

metadata := {
	"id": "soc2-a1.2-dms-multi-az",
	"name": "DMS Multi-AZ Deployment",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dms:replication-instance"],
	"remediation": "Enable Multi-AZ deployment for DMS replication instances to ensure high availability and automatic failover.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:dms:replication-instance"
	input.data.multi_az == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DMS replication instance '%s' does not have Multi-AZ deployment enabled", [input.data.id]),
		"details": {
			"id": input.data.id,
		},
	}
}
