# METADATA
# title: A1.2 - ElastiCache Multi-AZ Enabled
# description: ElastiCache replication groups should have Multi-AZ enabled
# scope: package
package sigcomply.soc2.a1_2_elasticache_multi_az

metadata := {
	"id": "soc2-a1.2-elasticache-multi-az",
	"name": "ElastiCache Multi-AZ Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticache:replication_group"],
	"remediation": "Enable Multi-AZ for the ElastiCache replication group.",
}

violations contains violation if {
	input.resource_type == "aws:elasticache:replication_group"
	input.data.multi_az_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ElastiCache replication group '%s' does not have Multi-AZ enabled", [input.data.replication_group_id]),
		"details": {"replication_group_id": input.data.replication_group_id},
	}
}
