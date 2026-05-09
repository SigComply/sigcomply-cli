# METADATA
# title: CC7.4 - RDS Deletion Protection
# description: RDS instances should have deletion protection enabled
# scope: package
package sigcomply.soc2.cc7_4_rds_deletion_protection

metadata := {
	"id": "soc2-cc7.4-rds-deletion-protection",
	"name": "RDS Deletion Protection",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable deletion protection on the RDS instance.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.deletion_protection == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have deletion protection enabled", [input.data.db_instance_id]),
		"details": {"db_instance_id": input.data.db_instance_id},
	}
}
